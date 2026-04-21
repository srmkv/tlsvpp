// Package freeradius_files implements a source adapter that reads users from
// FreeRADIUS flat-file authorization files (mods-config/files/authorize).
//
// DSN formats:
//
//	/absolute/path/to/authorize
//	./relative/path/to/authorize
//	ssh://user@host/path/to/authorize
//	ssh://user@host:port/path/to/authorize
//	ssh://user@host/path/to/authorize?key=/home/user/.ssh/id_rsa
//	ssh://user@host/path?key=/path/to/key&timeout=20
package freeradius_files

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"radius-agent/internal/model"
)

// Adapter implements source.Adapter for FreeRADIUS files.
type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Ping(ctx context.Context, src model.Source) error {
	_, err := fetchFile(ctx, src.DSN)
	return err
}

func (a *Adapter) LoadSnapshot(ctx context.Context, src model.Source) (*model.Snapshot, error) {
	data, err := fetchFile(ctx, src.DSN)
	if err != nil {
		return nil, fmt.Errorf("fetch authorize file: %w", err)
	}
	return parseAuthorize(src.ID, data)
}

// ─── File fetching ────────────────────────────────────────────────────────────

func fetchFile(ctx context.Context, dsn string) ([]byte, error) {
	dsn = strings.TrimSpace(dsn)
	if strings.HasPrefix(dsn, "ssh://") {
		return fetchSSH(ctx, dsn)
	}
	return fetchLocal(dsn)
}

func fetchLocal(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("файл не найден: %q. Проверьте путь DSN", path)
		}
		return nil, fmt.Errorf("чтение файла %q: %w", path, err)
	}
	return data, nil
}

// sshDSN holds the parsed components of an SSH DSN.
type sshDSN struct {
	user       string
	host       string
	port       string
	remotePath string
	keyFile    string        // explicit private key path from ?key=
	timeout    time.Duration // from ?timeout= (seconds)
}

func parseSSHDSN(rawDSN string) (*sshDSN, error) {
	u, err := url.Parse(rawDSN)
	if err != nil {
		return nil, fmt.Errorf("неверный SSH DSN %q: %w", rawDSN, err)
	}
	if u.Scheme != "ssh" {
		return nil, fmt.Errorf("ожидается схема ssh://, получен %q", u.Scheme)
	}
	out := &sshDSN{
		host:       u.Hostname(),
		port:       u.Port(),
		remotePath: u.Path,
		timeout:    20 * time.Second,
	}
	if u.User != nil {
		out.user = u.User.Username()
	}
	if out.host == "" {
		return nil, fmt.Errorf("SSH DSN не содержит имени хоста: %q", rawDSN)
	}
	if out.remotePath == "" || out.remotePath == "/" {
		return nil, fmt.Errorf("SSH DSN не содержит пути к файлу: %q", rawDSN)
	}

	// Parse query parameters
	q := u.Query()
	if k := strings.TrimSpace(q.Get("key")); k != "" {
		out.keyFile = k
	}
	if t := strings.TrimSpace(q.Get("timeout")); t != "" {
		if secs, err := strconv.Atoi(t); err == nil && secs > 0 {
			out.timeout = time.Duration(secs) * time.Second
		}
	}
	return out, nil
}

// resolveSSHKey returns the private key file to use for SSH authentication.
// Priority: explicit DSN ?key= > common well-known key files.
func resolveSSHKey(explicit string) (string, bool) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit, true
		}
		// Explicit key specified but file doesn't exist — still use it (SSH
		// will give a clear error), so the admin sees exactly what path is wrong.
		return explicit, false
	}

	// Try common default key locations in priority order
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_rsa"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
		"/etc/radius-agent/ssh_key",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, true
		}
	}
	return "", false
}

// fetchSSH reads a remote file using the system's `ssh` binary.
// Uses key-based authentication only (BatchMode=yes — never prompts).
func fetchSSH(ctx context.Context, rawDSN string) ([]byte, error) {
	parsed, err := parseSSHDSN(rawDSN)
	if err != nil {
		return nil, err
	}

	keyPath, keyExists := resolveSSHKey(parsed.keyFile)

	// Build [user@]host
	dest := parsed.host
	if parsed.user != "" {
		dest = parsed.user + "@" + parsed.host
	}

	args := []string{
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", fmt.Sprintf("ConnectTimeout=%d", int(parsed.timeout.Seconds())),
		"-o", "BatchMode=yes",  // key-only, never prompt for password
		"-o", "LogLevel=ERROR", // suppress banner/motd noise
	}
	if parsed.port != "" {
		args = append(args, "-p", parsed.port)
	}
	if keyPath != "" {
		args = append(args, "-i", keyPath)
		// Disable agent and other auth methods so we know exactly which key
		// is being used and get a clear error if it fails
		args = append(args, "-o", "IdentitiesOnly=yes")
	}
	args = append(args, dest, "cat", parsed.remotePath)

	ctx2, cancel := context.WithTimeout(ctx, parsed.timeout+5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx2, "ssh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if runErr := cmd.Run(); runErr != nil {
		se := strings.TrimSpace(stderr.String())
		// Produce an actionable error message
		return nil, buildSSHError(parsed, keyPath, keyExists, runErr, se)
	}
	return stdout.Bytes(), nil
}

func buildSSHError(p *sshDSN, keyPath string, keyExists bool, runErr error, stderrMsg string) error {
	dest := p.host
	if p.user != "" {
		dest = p.user + "@" + p.host
	}

	// Authentication failure
	authFail := strings.Contains(stderrMsg, "Permission denied") ||
		strings.Contains(stderrMsg, "publickey") ||
		strings.Contains(stderrMsg, "authentication failed")
	if authFail {
		if keyPath == "" {
			return fmt.Errorf(
				"SSH %s: ошибка аутентификации — SSH-ключ не найден\n"+
					"Создайте ключ и скопируйте на удалённый хост:\n"+
					"  ssh-keygen -t ed25519\n"+
					"  ssh-copy-id %s\n"+
					"Или укажите путь к ключу в DSN: ...?key=/home/ngfw/.ssh/id_ed25519",
				dest, dest,
			)
		}
		if !keyExists {
			return fmt.Errorf(
				"SSH %s: ошибка аутентификации — файл ключа не найден: %q\n"+
					"Проверьте путь, указанный в параметре ?key= DSN",
				dest, keyPath,
			)
		}
		return fmt.Errorf(
			"SSH %s: ошибка аутентификации с ключом %q\n"+
				"Убедитесь, что публичный ключ добавлен на удалённый хост:\n"+
				"  ssh-copy-id -i %s.pub %s",
			dest, keyPath, keyPath, dest,
		)
	}

	// Host unreachable / no route
	if strings.Contains(stderrMsg, "No route to host") || strings.Contains(stderrMsg, "no route") {
		return fmt.Errorf("SSH %s: хост недоступен — проверьте IP и сетевое подключение", dest)
	}
	// Connection refused
	if strings.Contains(stderrMsg, "Connection refused") {
		port := p.port
		if port == "" {
			port = "22"
		}
		return fmt.Errorf("SSH %s: соединение отклонено (порт %s) — убедитесь, что sshd запущен", dest, port)
	}
	// Host key verification failed
	if strings.Contains(stderrMsg, "Host key verification failed") {
		return fmt.Errorf(
			"SSH %s: несовпадение ключа хоста — удалите старую запись:\n"+
				"  ssh-keygen -R %s",
			dest, p.host,
		)
	}
	// Remote file not found
	if strings.Contains(stderrMsg, "No such file") || strings.Contains(stderrMsg, "no such file") {
		return fmt.Errorf(
			"SSH %s: файл не найден на удалённом хосте: %q\n"+
				"Проверьте путь в DSN",
			dest, p.remotePath,
		)
	}
	// Timeout
	if strings.Contains(runErr.Error(), "context deadline exceeded") || strings.Contains(stderrMsg, "timed out") {
		return fmt.Errorf("SSH %s: таймаут соединения (%s) — хост недоступен или перегружен", dest, p.timeout)
	}

	// Fallback — include raw stderr for diagnostics
	if se := stderrMsg; se != "" {
		return fmt.Errorf("SSH %s: %s", dest, se)
	}
	return fmt.Errorf("SSH %s: %w", dest, runErr)
}

// ─── FreeRADIUS authorize file parser ────────────────────────────────────────

func parseAuthorize(sourceID string, data []byte) (*model.Snapshot, error) {
	snap := &model.Snapshot{
		SourceID:  sourceID,
		CreatedAt: time.Now().UTC(),
		Users:     map[string]*model.RadiusUser{},
		Groups:    map[string]*model.RadiusGroup{},
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	var currentUser string
	var firstAttrRaw string

	flush := func() {
		if currentUser == "" {
			return
		}
		u := ensureUser(snap, currentUser)
		if firstAttrRaw != "" {
			parseAttrLine(u, firstAttrRaw, "user_check", currentUser, snap)
			firstAttrRaw = ""
		}
		currentUser = ""
	}

	for scanner.Scan() {
		line := scanner.Text()

		// Strip inline comments (but preserve # inside quoted values)
		if ci := strings.Index(line, " #"); ci > 0 {
			line = line[:ci]
		}

		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			flush()
			continue
		}

		// Indented → attribute for current entry
		if line[0] == ' ' || line[0] == '\t' {
			if currentUser != "" {
				u := ensureUser(snap, currentUser)
				parseAttrLine(u, stripped, "user_reply", currentUser, snap)
			}
			continue
		}

		// Non-indented → new entry
		flush()

		parts := strings.SplitN(stripped, " ", 2)
		username := strings.ToLower(strings.Trim(parts[0], `"'`))
		if username == "" {
			continue
		}
		currentUser = username
		if len(parts) > 1 {
			firstAttrRaw = strings.TrimSpace(parts[1])
		}
	}
	flush()

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse authorize: %w", err)
	}

	snap.Diagnostics.UserCount = len(snap.Users)
	snap.Diagnostics.GroupCount = len(snap.Groups)
	hash, err := contentHash(snap)
	if err != nil {
		return nil, err
	}
	snap.Diagnostics.Hash = hash
	snap.Revision = hash
	return snap, nil
}

func parseAttrLine(u *model.RadiusUser, line, scope, username string, snap *model.Snapshot) {
	ops := []string{":=", "+=", "-=", "==", "=~", "!~", ">=", "<=", "!=", "="}
	attrName, op, value := "", "", ""
	for _, candidate := range ops {
		if idx := strings.Index(line, candidate); idx >= 0 {
			attrName = strings.TrimSpace(line[:idx])
			op = candidate
			value = strings.TrimSpace(line[idx+len(candidate):])
			if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
				value = value[1 : len(value)-1]
			}
			value = strings.TrimRight(value, ",")
			break
		}
	}
	if attrName == "" || value == "" {
		return
	}

	normalizedAttr := strings.ToLower(attrName)
	isCheck := scope == "user_check" || op == ":=" || op == "=="
	item := model.RadiusAttr{Name: attrName, Op: op, Value: value, Scope: scope}
	if isCheck {
		u.CheckItems = append(u.CheckItems, item)
		if normalizedAttr == "auth-type" && strings.EqualFold(value, "Reject") {
			u.Disabled = true
		}
	} else {
		u.ReplyItems = append(u.ReplyItems, item)
	}

	// Derive group membership from well-known group attributes
	groupAttrs := []string{"filter-id", "class", "mikrotik-group", "group", "user-group", "group-name"}
	for _, ga := range groupAttrs {
		if normalizedAttr == ga && value != "" {
			groupName := strings.ToLower(strings.TrimSpace(value))
			if groupName == username || groupName == "default" {
				continue
			}
			already := false
			for _, g := range u.Groups {
				if g == groupName {
					already = true
					break
				}
			}
			if !already {
				u.Groups = append(u.Groups, groupName)
			}
			ensureGroup(snap, groupName)
		}
	}
}

func ensureUser(snap *model.Snapshot, username string) *model.RadiusUser {
	if u := snap.Users[username]; u != nil {
		return u
	}
	u := &model.RadiusUser{Username: username}
	snap.Users[username] = u
	return u
}

func ensureGroup(snap *model.Snapshot, groupName string) *model.RadiusGroup {
	if g := snap.Groups[groupName]; g != nil {
		return g
	}
	g := &model.RadiusGroup{Name: groupName}
	snap.Groups[groupName] = g
	return g
}
