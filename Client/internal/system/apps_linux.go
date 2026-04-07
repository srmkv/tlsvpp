//go:build linux

package system

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const installedAppsCacheTTL = 2 * time.Minute

type installedAppsCacheEntry struct {
	until time.Time
	apps  []string
}

var (
	installedAppsMu    sync.Mutex
	installedAppsCache installedAppsCacheEntry
)

func ListInstalledApps() ([]string, error) {
	installedAppsMu.Lock()
	defer installedAppsMu.Unlock()
	if time.Now().Before(installedAppsCache.until) && len(installedAppsCache.apps) > 0 {
		return append([]string(nil), installedAppsCache.apps...), nil
	}
	apps, err := listInstalledAppsUncached()
	if err != nil {
		return nil, err
	}
	installedAppsCache = installedAppsCacheEntry{until: time.Now().Add(installedAppsCacheTTL), apps: append([]string(nil), apps...)}
	return append([]string(nil), apps...), nil
}

func ListPolicyAppNames() ([]string, error) {
	seen := map[string]string{}
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; !ok {
			seen[key] = name
		}
	}

	var errs []string
	procs, err := ListProcesses()
	if err == nil {
		for _, p := range procs {
			add(p.Name)
			if base := filepath.Base(strings.TrimSpace(p.Exe)); base != "" && base != "." && base != "/" {
				add(base)
			}
		}
	} else {
		errs = append(errs, err.Error())
	}

	apps, err := ListInstalledApps()
	if err == nil {
		for _, app := range apps {
			add(app)
		}
	} else {
		errs = append(errs, err.Error())
	}

	out := make([]string, 0, len(seen))
	for _, name := range seen {
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	if len(out) > 0 {
		return out, nil
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf(strings.Join(errs, "; "))
	}
	return nil, nil
}

func listInstalledAppsUncached() ([]string, error) {
	seen := map[string]string{}
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; !ok {
			seen[key] = name
		}
	}

	for _, item := range scanDesktopEntries() {
		add(item)
	}
	for _, item := range scanKnownBinaryPaths() {
		add(item)
	}
	for _, item := range scanPackageManagerApps() {
		add(item)
	}

	out := make([]string, 0, len(seen))
	for _, name := range seen {
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out, nil
}

func scanDesktopEntries() []string {
	var dirs []string
	dirs = append(dirs,
		"/usr/share/applications",
		"/usr/local/share/applications",
		"/var/lib/flatpak/exports/share/applications",
		"/var/lib/snapd/desktop/applications",
	)
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		dirs = append(dirs, filepath.Join(home, ".local/share/applications"))
	}
	seen := map[string]string{}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".desktop") {
				continue
			}
			name, execName := parseDesktopFile(filepath.Join(dir, entry.Name()))
			for _, item := range []string{name, execName, strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))} {
				item = strings.TrimSpace(item)
				if item == "" {
					continue
				}
				key := strings.ToLower(item)
				if _, ok := seen[key]; !ok {
					seen[key] = item
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	return out
}

func parseDesktopFile(path string) (string, string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	var name string
	var execName string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "Name=") && name == "" {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name="))
		}
		if strings.HasPrefix(line, "Exec=") && execName == "" {
			raw := strings.TrimSpace(strings.TrimPrefix(line, "Exec="))
			if raw != "" {
				first := strings.Fields(raw)
				if len(first) > 0 {
					execName = filepath.Base(first[0])
				}
			}
		}
		if name != "" && execName != "" {
			break
		}
	}
	return name, execName
}

func scanKnownBinaryPaths() []string {
	candidates := []string{
		"/opt/mattermost-desktop/mattermost-desktop",
		"/opt/Mattermost/mattermost-desktop",
		"/opt/Mattermost/mattermost",
		"/usr/bin/mattermost-desktop",
		"/usr/bin/mattermost",
		"/usr/bin/openvpn",
		"/usr/sbin/openvpn",
		"/usr/bin/wg",
		"/usr/bin/wg-quick",
		"/usr/bin/warp-cli",
		"/usr/bin/tailscale",
		"/usr/bin/zerotier-one",
		"/usr/bin/anydesk",
		"/usr/bin/teamviewer",
		"/usr/bin/rustdesk",
		"/usr/bin/remmina",
		"/usr/bin/forticlient",
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/snap/bin/chromium",
	}
	seen := map[string]string{}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			base := filepath.Base(path)
			seen[strings.ToLower(base)] = base
		}
	}
	out := make([]string, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	return out
}

func scanPackageManagerApps() []string {
	seen := map[string]string{}
	addLines := func(lines []string) {
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			for _, item := range strings.Split(line, "\t") {
				item = strings.TrimSpace(item)
				if item == "" {
					continue
				}
				fields := strings.Fields(item)
				if len(fields) > 0 {
					item = fields[0]
				}
				key := strings.ToLower(item)
				if _, ok := seen[key]; !ok {
					seen[key] = item
				}
			}
		}
	}
	addLines(runInventoryCmd("dpkg-query", "-W", "-f=${binary:Package}\n"))
	addLines(runInventoryCmd("rpm", "-qa", "--qf", "%{NAME}\n"))
	addLines(runInventoryCmd("flatpak", "list", "--app", "--columns=application,name"))
	addLines(runInventoryCmd("snap", "list"))
	out := make([]string, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	return out
}

func runInventoryCmd(name string, args ...string) []string {
	if _, err := exec.LookPath(name); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(string(out), "\n")
	if name == "snap" && len(lines) > 0 && strings.Contains(strings.ToLower(lines[0]), "name") {
		lines = lines[1:]
	}
	return lines
}
