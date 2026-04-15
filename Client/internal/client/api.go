package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tlsclientnative/internal/model"
	"tlsclientnative/internal/state"
	"tlsclientnative/internal/system"
)

func trimJSONBody(body []byte) []byte {
	return bytes.TrimRight(body, "\x00 \t\r\n")
}

var decisionMessageFieldRE = regexp.MustCompile(`(?s)"message"\s*:\s*"((?:\\.|[^"])*)"`)

func extractLooseDecisionMessage(body []byte) string {
	trimmed := strings.TrimSpace(string(trimJSONBody(body)))
	if trimmed == "" {
		return ""
	}
	if m := decisionMessageFieldRE.FindStringSubmatch(trimmed); len(m) > 1 {
		if unq, err := strconv.Unquote("\"" + m[1] + "\""); err == nil {
			if clean := strings.TrimSpace(unq); clean != "" {
				return clean
			}
		}
		if clean := strings.TrimSpace(strings.ReplaceAll(m[1], `\"`, `"`)); clean != "" {
			return clean
		}
	}
	return ""
}

func decodeJSONWithTextFallback[T any](body []byte, out *T) error {
	body = trimJSONBody(body)
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return fmt.Errorf("пустой ответ сервера")
	}
	if loose := extractLooseDecisionMessage(trimmed); loose != "" && trimmed[0] != '{' && trimmed[0] != '[' {
		return fmt.Errorf(loose)
	}
	if trimmed[0] != '{' && trimmed[0] != '[' {
		msg := extractLooseDecisionMessage(trimmed)
		if msg == "" {
			msg = string(trimmed)
			if len(msg) > 500 {
				msg = msg[:500]
			}
		}
		return fmt.Errorf(strings.TrimSpace(msg))
	}
	if err := json.Unmarshal(trimmed, out); err != nil {
		if msg := extractLooseDecisionMessage(trimmed); msg != "" {
			return fmt.Errorf(msg)
		}
		preview := string(trimmed)
		if len(preview) > 500 {
			preview = preview[:500]
		}
		return fmt.Errorf("%w; ответ сервера: %s", err, strings.TrimSpace(preview))
	}
	return nil
}

const (
	DisconnectPath              = "/api/admin/sessions/disconnect"
	HeartbeatPath               = "/api/client/heartbeat"
	VPNFramePath                = "/api/client/vpn-frame"
	VPNPollPath                 = "/api/client/vpn-poll"
	VPNStreamPath               = "/api/client/vpn-stream"
	VPN2FAVerifyPath            = "/api/client/2fa/verify"
	VPN2FAResendPath            = "/api/client/2fa/resend"
	policyBootstrapDefaultPath  = "/api/client/policy-bootstrap"
	policyBootstrapFallbackPath = ""
	policyViolationDefaultPath  = "/api/client/policy-violation"
	policyViolationFallbackPath = "/api/plugin/app-policy/violation"
	frameTypeKeepalive          = 1
	frameTypeIPv4               = 2
)

var (
	activeOpMu      sync.Mutex
	activeMu        sync.RWMutex
	activeClient    *http.Client
	activeTransport *http.Transport
	activeSession   model.ClientSession
	activeConnected bool
	activeRuntime   *runtimeApplier
	activeCancel    context.CancelFunc
	activeWG        sync.WaitGroup
	activeBase      string
	activeStopping  bool
	activeDataConn  io.Closer
	dataplaneLogMu  sync.RWMutex
	dataplaneLogger func(string)
)

type apiErrorEnvelope struct {
	Message string `json:"message"`
	Error   string `json:"error"`
	Detail  string `json:"detail"`
	Reason  string `json:"reason"`
	Code    string `json:"code"`
}

func extractAPIErrorMessage(body []byte) string {
	body = trimJSONBody(body)
	if msg := extractLooseDecisionMessage(body); msg != "" {
		return msg
	}
	var env apiErrorEnvelope
	if err := json.Unmarshal(body, &env); err == nil {
		for _, v := range []string{env.Message, env.Error, env.Detail, env.Reason, env.Code} {
			if clean := strings.TrimSpace(v); clean != "" {
				return clean
			}
		}
	}
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		return ""
	}
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return msg
}

func readableHTTPError(op string, statusCode int, status string, body []byte, fallback string) error {
	msg := strings.TrimSpace(extractAPIErrorMessage(body))
	if msg == "" {
		msg = strings.TrimSpace(fallback)
	}
	switch statusCode {
	case http.StatusBadRequest:
		if msg == "" {
			msg = "Некорректный запрос клиента"
		}
	case http.StatusUnauthorized:
		if msg == "" {
			msg = "Сервер отклонил клиентский сертификат или учётная запись отключена"
		}
	case http.StatusForbidden:
		if msg == "" {
			msg = "Доступ запрещён сервером"
		}
	case http.StatusNotFound:
		if msg == "" {
			msg = "На сервере не найден нужный endpoint"
		}
	case http.StatusConflict:
		if msg == "" {
			msg = "Конфликт состояния на сервере"
		}
	case http.StatusLocked:
		if msg == "" {
			msg = "Подключение заблокировано политикой безопасности"
		}
	case http.StatusTooManyRequests:
		if msg == "" {
			msg = "Сервер временно ограничил число запросов"
		}
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		if msg == "" {
			msg = "Сервер временно недоступен"
		}
	default:
		if statusCode >= 500 && msg == "" {
			msg = "Внутренняя ошибка сервера"
		}
	}
	if msg == "" {
		msg = strings.TrimSpace(status)
	}
	if op = strings.TrimSpace(op); op != "" {
		return fmt.Errorf("%s: %s", op, msg)
	}
	return fmt.Errorf("%s", msg)
}

func readableRequestError(op string, err error) error {
	if err == nil {
		return nil
	}
	msg := HumanizeError(err)
	if op = strings.TrimSpace(op); op != "" {
		lowerOp := strings.ToLower(op)
		lowerMsg := strings.ToLower(msg)
		if strings.Contains(lowerMsg, lowerOp) || strings.HasPrefix(lowerMsg, op+":") {
			return fmt.Errorf("%s", msg)
		}
		return fmt.Errorf("%s: %s", op, msg)
	}
	return fmt.Errorf("%s", msg)
}

func HumanizeError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return "Неизвестная ошибка"
	}
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "unsupported protocol scheme"):
		return "Некорректно задан адрес сервера"
	case strings.Contains(lower, "certificate signed by unknown authority") || strings.Contains(lower, "unknown authority"):
		return "Не удалось проверить сертификат сервера"
	case strings.Contains(lower, "certificate is valid for") || strings.Contains(lower, "hostname") && strings.Contains(lower, "certificate"):
		return "Имя сервера не совпадает с сертификатом. Проверьте поле Server Name"
	case strings.Contains(lower, "remote error: tls: bad certificate"):
		return "Сервер отклонил клиентский сертификат"
	case strings.Contains(lower, "certificate required"):
		return "Сервер требует клиентский сертификат"
	case strings.Contains(lower, "connection refused"):
		return "Сервер недоступен или TLS listener не запущен"
	case strings.Contains(lower, "no such host"):
		return "Не удалось найти адрес сервера"
	case strings.Contains(lower, "context deadline exceeded") || strings.Contains(lower, "timeout"):
		return "Сервер не ответил вовремя"
	case strings.Contains(lower, "eof"):
		return "Соединение было закрыто сервером"
	case strings.Contains(lower, "not connected"):
		return "Соединение не установлено"
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return "Не удалось проверить сертификат сервера"
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return "Имя сервера не совпадает с сертификатом. Проверьте поле Server Name"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "Сервер не ответил вовремя"
	}
	if ue := new(url.Error); errors.As(err, &ue) && ue != nil {
		if ue.Timeout() {
			return "Сервер не ответил вовремя"
		}
		inner := strings.TrimSpace(ue.Err.Error())
		if inner != "" && !strings.EqualFold(inner, msg) {
			return HumanizeError(ue.Err)
		}
	}
	return msg
}

type vpnBindResponse struct {
	OK            bool   `json:"ok"`
	Status        string `json:"status,omitempty"`
	Required      bool   `json:"required,omitempty"`
	ChallengeID   string `json:"challenge_id,omitempty"`
	Method        string `json:"method,omitempty"`
	MaskedEmail   string `json:"masked_email,omitempty"`
	TTLSeconds    int    `json:"ttl_seconds,omitempty"`
	BindNonce     string `json:"bind_nonce,omitempty"`
	TunnelID      uint64 `json:"tunnel_id"`
	AssignedIP    string `json:"assigned_ip"`
	Gateway       string `json:"gateway"`
	DNSServers    string `json:"dns_servers"`
	IncludeRoutes string `json:"include_routes"`
	ExcludeRoutes string `json:"exclude_routes"`
	FullTunnel    bool   `json:"full_tunnel"`
	MTU           uint16 `json:"mtu"`
	MSS           uint16 `json:"mss"`
	LeaseSeconds  uint32 `json:"lease_seconds"`
}

type TwoFAChallenge struct {
	Username    string
	Profile     string
	ClientIP    string
	ChallengeID string
	Method      string
	MaskedEmail string
	TTLSeconds  int
	BindNonce   string
}

type TwoFARequiredError struct {
	Challenge TwoFAChallenge
}

func (e *TwoFARequiredError) Error() string {
	if strings.TrimSpace(e.Challenge.MaskedEmail) != "" {
		return "Требуется код подтверждения из письма, отправленного на " + strings.TrimSpace(e.Challenge.MaskedEmail)
	}
	return "Требуется код подтверждения из электронной почты"
}

type vpnFrameResponse struct {
	OK       bool   `json:"ok"`
	FrameHex string `json:"frame_hex"`
}

func applyClientHeaders(req *http.Request) {
	if req == nil {
		return
	}
	if mac := system.DetectPrimaryMAC(); strings.TrimSpace(mac) != "" {
		req.Header.Set("X-Client-MAC", mac)
	}
	if sysUser := system.DetectSystemUser(); strings.TrimSpace(sysUser) != "" {
		req.Header.Set("X-System-User", sysUser)
	}
	if ip := detectPrimaryIP(); strings.TrimSpace(ip) != "" {
		req.Header.Set("X-Client-IP", ip)
	}
	osType, osVersion := system.DetectOSInfo()
	if strings.TrimSpace(osType) != "" {
		req.Header.Set("X-OS-Type", osType)
	}
	if strings.TrimSpace(osVersion) != "" {
		req.Header.Set("X-OS-Version", osVersion)
	}
	if uptime := system.DetectSystemUptime(); strings.TrimSpace(uptime) != "" && uptime != "—" {
		req.Header.Set("X-System-Uptime", uptime)
	}
}

func detectInterfacesModel() []model.NetworkInterface {
	raw := system.DetectInterfaces()
	if len(raw) == 0 {
		return nil
	}
	out := make([]model.NetworkInterface, 0, len(raw))
	for _, item := range raw {
		iface := model.NetworkInterface{}
		if v, ok := item["name"].(string); ok {
			iface.Name = v
		}
		if v, ok := item["mtu"].(int); ok {
			iface.MTU = v
		}
		if v, ok := item["mac"].(string); ok {
			iface.MAC = v
		}
		if arr, ok := item["flags"].([]string); ok {
			iface.Flags = append([]string(nil), arr...)
		}
		if arr, ok := item["addresses"].([]string); ok {
			iface.Addresses = append([]string(nil), arr...)
		}
		out = append(out, iface)
	}
	return out
}

func checkAppPolicies(cfg state.Config, httpClient *http.Client) error {
	decision, err := evaluateAppPolicies(cfg, httpClient)
	if err != nil {
		return readableRequestError("Проверка политик", err)
	}
	if decision.Allow {
		return nil
	}
	_ = reportPolicyDecisionViolation(cfg, httpClient, decision)
	msg := strings.TrimSpace(decision.Message)
	if msg == "" {
		msg = "У вас обнаружено запрещенное приложение"
	}
	if len(decision.Matches) > 0 {
		first := decision.Matches[0]
		policyName := strings.TrimSpace(first.PolicyName)
		if policyName == "" {
			policyName = strings.TrimSpace(first.PolicyID)
		}
		if policyName != "" {
			msg += "\nПолитика: " + policyName
		}
		if strings.TrimSpace(first.Pattern) != "" {
			msg += "\nШаблон: " + strings.TrimSpace(first.Pattern)
		}
		seen := map[string]struct{}{}
		apps := make([]string, 0, len(decision.Matches))
		for _, m := range decision.Matches {
			app := strings.TrimSpace(m.App)
			if app == "" {
				continue
			}
			key := strings.ToLower(app)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			apps = append(apps, app)
		}
		if len(apps) > 0 {
			msg += "\nСовпадения: " + strings.Join(apps, ", ")
		}
	}
	return fmt.Errorf(msg)
}

func collectPolicyInventory() ([]model.AppInventoryItem, error) {
	seen := map[string]struct{}{}
	out := make([]model.AppInventoryItem, 0, 64)
	add := func(item model.AppInventoryItem) {
		item.Name = strings.TrimSpace(item.Name)
		item.Exe = strings.TrimSpace(item.Exe)
		item.Category = strings.TrimSpace(item.Category)
		if item.Name == "" && item.Exe == "" && item.Category == "" {
			return
		}
		key := strings.ToLower(item.Name + "\n" + item.Exe + "\n" + item.Category)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	var errs []string
	if procs, err := system.ListProcesses(); err == nil {
		for _, pr := range procs {
			add(model.AppInventoryItem{Name: strings.TrimSpace(pr.Name), Exe: strings.TrimSpace(pr.Exe), Category: strings.TrimSpace(pr.Category)})
		}
	} else {
		errs = append(errs, err.Error())
	}
	if installed, err := system.ListInstalledApps(); err == nil {
		for _, name := range installed {
			add(model.AppInventoryItem{Name: strings.TrimSpace(name), Category: "Установлено"})
		}
	} else {
		errs = append(errs, err.Error())
	}
	if len(out) > 0 {
		return out, nil
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf(strings.Join(errs, "; "))
	}
	return nil, nil
}

func evaluateAppPolicies(cfg state.Config, httpClient *http.Client) (model.AppPolicyDecision, error) {
	inventory, err := collectPolicyInventory()
	if err != nil {
		return model.AppPolicyDecision{}, fmt.Errorf("не удалось проверить список приложений: %w", err)
	}
	payload := map[string]any{
		"username": strings.TrimSpace(cfg.Username),
		"profile":  strings.TrimSpace(cfg.Profile),
		"stage":    "client",
		"apps":     inventory,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return model.AppPolicyDecision{}, err
	}
	paths := []string{}
	seen := map[string]struct{}{}
	for _, p := range []string{strings.TrimSpace(cfg.AppPolicyPath), policyBootstrapDefaultPath, policyBootstrapFallbackPath} {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		paths = append(paths, p)
	}
	var lastErr error
	for _, path := range paths {
		req, err := http.NewRequest(http.MethodPost, joinURL(cfg.ServerURL, path), bytes.NewReader(bodyBytes))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		applyClientHeaders(req)
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		body = trimJSONBody(body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			lastErr = fmt.Errorf("policy bootstrap unsupported on %s", path)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = readableHTTPError("Проверка политик", resp.StatusCode, resp.Status, body, "Ошибка проверки политики")
			continue
		}
		var out model.AppPolicyDecision
		if err := decodeJSONWithTextFallback(body, &out); err != nil {
			lastErr = err
			continue
		}
		return out, nil
	}
	if lastErr != nil {
		return model.AppPolicyDecision{}, lastErr
	}
	return model.AppPolicyDecision{Allow: true}, nil
}

func fetchAppPolicies(cfg state.Config, httpClient *http.Client) ([]model.AppPolicy, error) {
	payload := map[string]any{
		"username": strings.TrimSpace(cfg.Username),
		"profile":  strings.TrimSpace(cfg.Profile),
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	paths := []string{}
	seen := map[string]struct{}{}
	for _, p := range []string{strings.TrimSpace(cfg.AppPolicyPath), policyBootstrapDefaultPath, policyBootstrapFallbackPath} {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		paths = append(paths, p)
	}
	var lastErr error
	for _, path := range paths {
		req, err := http.NewRequest(http.MethodPost, joinURL(cfg.ServerURL, path), bytes.NewReader(bodyBytes))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		applyClientHeaders(req)
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		body = trimJSONBody(body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			lastErr = fmt.Errorf("policy bootstrap unsupported on %s", path)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = readableHTTPError("Проверка политик", resp.StatusCode, resp.Status, body, "Ошибка проверки политики")
			continue
		}
		var out model.AppPolicyResolveResponse
		if err := decodeJSONWithTextFallback(body, &out); err != nil {
			lastErr = err
			continue
		}
		if len(out.Policies) == 0 {
			return nil, nil
		}
		return out.Policies, nil
	}
	if lastErr != nil && !strings.Contains(lastErr.Error(), "unsupported") {
		return nil, lastErr
	}
	return nil, nil
}

func wildcardPatternToRegexp(value string) *regexp.Regexp {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil
	}
	quoted := regexp.QuoteMeta(v)
	quoted = strings.ReplaceAll(quoted, `\*`, ".*")
	return regexp.MustCompile(`(?i)` + quoted)
}

func matchPolicyApps(policy model.AppPolicy, apps []string) ([]string, string) {
	matched := []string{}
	for _, pat := range policy.Patterns {
		pv := strings.TrimSpace(pat.Value)
		if pv == "" {
			continue
		}
		ptype := strings.ToLower(strings.TrimSpace(pat.Type))
		if ptype == "" {
			ptype = "contains"
		}
		var re *regexp.Regexp
		switch ptype {
		case "regex":
			compiled, err := regexp.Compile(`(?i)` + pv)
			if err != nil {
				continue
			}
			re = compiled
		default:
			if strings.Contains(pv, "*") {
				re = wildcardPatternToRegexp(pv)
			}
		}
		for _, app := range apps {
			appTrim := strings.TrimSpace(app)
			if appTrim == "" {
				continue
			}
			matchedNow := false
			switch ptype {
			case "regex":
				matchedNow = re != nil && re.MatchString(appTrim)
			default:
				if re != nil {
					matchedNow = re.MatchString(appTrim)
				} else {
					matchedNow = strings.Contains(strings.ToLower(appTrim), strings.ToLower(pv))
				}
			}
			if matchedNow {
				if !containsStringCI(matched, appTrim) {
					matched = append(matched, appTrim)
				}
			}
		}
		if len(matched) > 0 {
			return matched, pv
		}
	}
	return nil, ""
}

func MatchPoliciesForApps(cfg state.Config, apps []string) (map[string]model.AppPolicyMatch, error) {
	httpClient, tr, err := newPersistentMTLSHTTPClient(cfg, 12*time.Second)
	if err != nil {
		return nil, err
	}
	defer tr.CloseIdleConnections()

	policies, err := fetchAppPolicies(cfg, httpClient)
	if err != nil {
		return nil, err
	}
	matches := map[string]model.AppPolicyMatch{}
	if len(policies) == 0 || len(apps) == 0 {
		return matches, nil
	}
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		matchedApps, pattern := matchPolicyApps(policy, apps)
		for _, app := range matchedApps {
			key := strings.ToLower(strings.TrimSpace(app))
			if key == "" {
				continue
			}
			if _, ok := matches[key]; ok {
				continue
			}
			matches[key] = model.AppPolicyMatch{PolicyID: strings.TrimSpace(policy.ID), PolicyName: strings.TrimSpace(policy.Name), Pattern: strings.TrimSpace(pattern), App: strings.TrimSpace(app)}
		}
	}
	return matches, nil
}

func extractDecisionMessage(body []byte, fallback string) string {
	body = trimJSONBody(body)
	var decision model.AppPolicyDecision
	if err := json.Unmarshal(body, &decision); err == nil {
		msg := strings.TrimSpace(decision.Message)
		if msg != "" {
			return msg
		}
	}
	if msg := extractLooseDecisionMessage(body); msg != "" {
		return msg
	}
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = fallback
	}
	return msg
}

func containsStringCI(items []string, target string) bool {
	for _, it := range items {
		if strings.EqualFold(strings.TrimSpace(it), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func CollectMatchedPolicyApps(cfg state.Config) ([]string, error) {
	httpClient, tr, err := newPersistentMTLSHTTPClient(cfg, 12*time.Second)
	if err != nil {
		return nil, err
	}
	defer tr.CloseIdleConnections()

	policies, err := fetchAppPolicies(cfg, httpClient)
	if err != nil || len(policies) == 0 {
		return nil, err
	}
	appNames, invErr := system.ListPolicyAppNames()
	if invErr != nil {
		return nil, invErr
	}
	seen := map[string]string{}
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		matchedApps, _ := matchPolicyApps(policy, appNames)
		for _, app := range matchedApps {
			key := strings.ToLower(strings.TrimSpace(app))
			if key == "" {
				continue
			}
			if _, ok := seen[key]; !ok {
				seen[key] = strings.TrimSpace(app)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for _, app := range seen {
		out = append(out, app)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out, nil
}

func reportPolicyDecisionViolation(cfg state.Config, httpClient *http.Client, decision model.AppPolicyDecision) error {
	policyID := ""
	policyName := ""
	matchedApps := []string{}
	if len(decision.Matches) > 0 {
		policyID = strings.TrimSpace(decision.Matches[0].PolicyID)
		policyName = strings.TrimSpace(decision.Matches[0].PolicyName)
		seen := map[string]struct{}{}
		for _, m := range decision.Matches {
			app := strings.TrimSpace(m.App)
			if app == "" {
				continue
			}
			key := strings.ToLower(app)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			matchedApps = append(matchedApps, app)
		}
	}
	payload := map[string]any{
		"username":     strings.TrimSpace(cfg.Username),
		"profile":      strings.TrimSpace(cfg.Profile),
		"policy_id":    policyID,
		"policy_name":  policyName,
		"message":      strings.TrimSpace(decision.Message),
		"matched_apps": matchedApps,
		"action":       "deny_connect",
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return readableRequestError("Отправка нарушения политики", err)
	}
	for _, path := range []string{policyViolationDefaultPath, policyViolationFallbackPath} {
		req, err := http.NewRequest(http.MethodPost, joinURL(cfg.ServerURL, path), bytes.NewReader(bodyBytes))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		applyClientHeaders(req)
		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
			return nil
		}
	}
	return nil
}

func reportPolicyViolation(cfg state.Config, httpClient *http.Client, policy model.AppPolicy, matchedApps []string) error {
	payload := map[string]any{
		"username":     strings.TrimSpace(cfg.Username),
		"profile":      strings.TrimSpace(cfg.Profile),
		"policy_id":    strings.TrimSpace(policy.ID),
		"policy_name":  strings.TrimSpace(policy.Name),
		"matched_apps": matchedApps,
		"action":       "deny_connect",
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return readableRequestError("Отправка нарушения политики", err)
	}
	for _, path := range []string{policyViolationDefaultPath, policyViolationFallbackPath} {
		req, err := http.NewRequest(http.MethodPost, joinURL(cfg.ServerURL, path), bytes.NewReader(bodyBytes))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		applyClientHeaders(req)
		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
			return nil
		}
	}
	return nil
}

func currentSession() (model.ClientSession, bool) {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if !activeConnected || activeStopping {
		return model.ClientSession{}, false
	}
	s := activeSession
	s.LastSeen = time.Now().UTC().Format(time.RFC3339)
	s.SystemUptime = system.DetectSystemUptime()
	return s, true
}

func setCurrentSession(s model.ClientSession, client *http.Client, tr *http.Transport, applier *runtimeApplier, cancel context.CancelFunc, baseURL string) {
	activeMu.Lock()
	defer activeMu.Unlock()
	activeSession = s
	activeClient = client
	activeTransport = tr
	activeRuntime = applier
	activeCancel = cancel
	activeBase = strings.TrimSpace(baseURL)
	activeStopping = false
	activeConnected = true
}

func setActiveDataConn(c io.Closer) {
	activeMu.Lock()
	activeDataConn = c
	activeMu.Unlock()
}

func dataplaneActiveState() (string, *http.Client, bool) {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return strings.TrimSpace(activeBase), activeClient, activeStopping
}

func dataplaneShouldStop() bool {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeStopping
}

func applyConnectedReply(cfg state.Config, httpClient *http.Client, tr *http.Transport, reply vpnBindResponse) (model.ClientSession, error) {
	applier := newRuntimeApplier()
	if _, err := applier.Apply(context.Background(), runtimeApplyInput{
		AssignedIP:    reply.AssignedIP,
		Gateway:       reply.Gateway,
		DNSServers:    reply.DNSServers,
		IncludeRoutes: reply.IncludeRoutes,
		ExcludeRoutes: reply.ExcludeRoutes,
		FullTunnel:    reply.FullTunnel,
		MTU:           int(reply.MTU),
	}); err != nil {
		tr.CloseIdleConnections()
		return model.ClientSession{}, fmt.Errorf("Подключение: не удалось настроить локальный VPN-интерфейс: %s", HumanizeError(err))
	}
	osType, osVersion := system.DetectOSInfo()
	now := time.Now().UTC().Format(time.RFC3339)
	session := model.ClientSession{
		Username:     strings.TrimSpace(cfg.Username),
		Profile:      strings.TrimSpace(firstNonEmpty(cfg.Profile, "default")),
		SystemUser:   system.DetectSystemUser(),
		OSType:       osType,
		OSVersion:    osVersion,
		SystemUptime: system.DetectSystemUptime(),
		IP:           empty(reply.AssignedIP),
		MAC:          empty(system.DetectPrimaryMAC()),
		Status:       "connected",
		ConnectedAt:  now,
		LastSeen:     now,
		Source:       "mtls-vpn",
		TunnelID:     reply.TunnelID,
		Gateway:      reply.Gateway,
		DNSServers:   reply.DNSServers,
		MTU:          reply.MTU,
		MSS:          reply.MSS,
		LeaseSeconds: reply.LeaseSeconds,
		FullTunnel:   reply.FullTunnel,
	}
	ctx, cancel := context.WithCancel(context.Background())
	setCurrentSession(session, httpClient, tr, applier, cancel, cfg.ServerURL)
	startDataplane(ctx, cfg, session, applier, httpClient)
	return session, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func ConnectVPN(cfg state.Config) (model.ClientSession, error) {
	activeOpMu.Lock()
	defer activeOpMu.Unlock()
	return connectVPNLocked(cfg)
}

func connectVPNLocked(cfg state.Config) (model.ClientSession, error) {
	httpClient, tr, err := newPersistentMTLSHTTPClient(cfg, 15*time.Second)
	if err != nil {
		return model.ClientSession{}, err
	}
	if err := checkAppPolicies(cfg, httpClient); err != nil {
		tr.CloseIdleConnections()
		return model.ClientSession{}, err
	}

	profile := strings.TrimSpace(cfg.Profile)
	if profile == "" {
		profile = "default"
	}
	payload := map[string]any{
		"username":  strings.TrimSpace(cfg.Username),
		"profile":   profile,
		"client_ip": detectPrimaryIP(),
	}
	if payload["client_ip"] == "" {
		payload["client_ip"] = "0.0.0.0"
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return model.ClientSession{}, fmt.Errorf("marshal vpn-bind: %w", err)
	}

	urlValue := joinURL(cfg.ServerURL, cfg.ClientsPath)
	req, err := http.NewRequest(http.MethodPost, urlValue, bytes.NewReader(bodyBytes))
	if err != nil {
		return model.ClientSession{}, readableRequestError("Подключение", err)
	}
	req.Header.Set("Content-Type", "application/json")
	applyClientHeaders(req)

	resp, err := httpClient.Do(req)
	if err != nil {
		return model.ClientSession{}, readableRequestError("Подключение", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode != http.StatusOK {
		return model.ClientSession{}, readableHTTPError("Подключение", resp.StatusCode, resp.Status, body, "Сервер отклонил подключение")
	}
	var reply vpnBindResponse
	if err := decodeJSONWithTextFallback(body, &reply); err != nil {
		return model.ClientSession{}, fmt.Errorf("Подключение: %w", err)
	}
	if reply.Required || strings.EqualFold(strings.TrimSpace(reply.Status), "2fa_required") || strings.TrimSpace(reply.ChallengeID) != "" {
		tr.CloseIdleConnections()
		return model.ClientSession{}, &TwoFARequiredError{Challenge: TwoFAChallenge{
			Username:    strings.TrimSpace(cfg.Username),
			Profile:     profile,
			ClientIP:    fmt.Sprint(payload["client_ip"]),
			ChallengeID: strings.TrimSpace(reply.ChallengeID),
			Method:      strings.TrimSpace(firstNonEmpty(reply.Method, "email")),
			MaskedEmail: strings.TrimSpace(reply.MaskedEmail),
			TTLSeconds:  reply.TTLSeconds,
			BindNonce:   strings.TrimSpace(reply.BindNonce),
		}}
	}
	if !reply.OK {
		return model.ClientSession{}, fmt.Errorf("Подключение: сервер не подтвердил создание VPN-сессии")
	}
	return applyConnectedReply(cfg, httpClient, tr, reply)
}

func CompleteEmail2FA(cfg state.Config, challenge TwoFAChallenge, code string) (model.ClientSession, error) {
	httpClient, tr, err := newPersistentMTLSHTTPClient(cfg, 15*time.Second)
	if err != nil {
		return model.ClientSession{}, err
	}
	payload := map[string]any{
		"username":     strings.TrimSpace(challenge.Username),
		"profile":      strings.TrimSpace(firstNonEmpty(challenge.Profile, cfg.Profile, "default")),
		"client_ip":    strings.TrimSpace(firstNonEmpty(challenge.ClientIP, detectPrimaryIP(), "0.0.0.0")),
		"challenge_id": strings.TrimSpace(challenge.ChallengeID),
		"code":         strings.TrimSpace(code),
		"bind_nonce":   strings.TrimSpace(challenge.BindNonce),
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return model.ClientSession{}, err
	}
	req, err := http.NewRequest(http.MethodPost, joinURL(cfg.ServerURL, VPN2FAVerifyPath), bytes.NewReader(bodyBytes))
	if err != nil {
		return model.ClientSession{}, readableRequestError("Подтверждение кода", err)
	}
	req.Header.Set("Content-Type", "application/json")
	applyClientHeaders(req)
	resp, err := httpClient.Do(req)
	if err != nil {
		return model.ClientSession{}, readableRequestError("Подтверждение кода", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode != http.StatusOK {
		tr.CloseIdleConnections()
		return model.ClientSession{}, readableHTTPError("Подтверждение кода", resp.StatusCode, resp.Status, body, "Код подтверждения отклонён")
	}
	var reply vpnBindResponse
	if err := decodeJSONWithTextFallback(body, &reply); err != nil {
		tr.CloseIdleConnections()
		return model.ClientSession{}, fmt.Errorf("Подтверждение кода: %w", err)
	}
	if !reply.OK {
		tr.CloseIdleConnections()
		return model.ClientSession{}, fmt.Errorf("Подтверждение кода: сервер не подтвердил создание VPN-сессии")
	}
	return applyConnectedReply(cfg, httpClient, tr, reply)
}

func ResendEmail2FA(cfg state.Config, challenge TwoFAChallenge) (TwoFAChallenge, error) {
	httpClient, tr, err := newPersistentMTLSHTTPClient(cfg, 10*time.Second)
	if err != nil {
		return challenge, err
	}
	defer tr.CloseIdleConnections()
	bodyBytes, err := json.Marshal(map[string]any{"challenge_id": strings.TrimSpace(challenge.ChallengeID)})
	if err != nil {
		return challenge, err
	}
	req, err := http.NewRequest(http.MethodPost, joinURL(cfg.ServerURL, VPN2FAResendPath), bytes.NewReader(bodyBytes))
	if err != nil {
		return challenge, readableRequestError("Повторная отправка кода", err)
	}
	req.Header.Set("Content-Type", "application/json")
	applyClientHeaders(req)
	resp, err := httpClient.Do(req)
	if err != nil {
		return challenge, readableRequestError("Повторная отправка кода", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode != http.StatusOK {
		return challenge, readableHTTPError("Повторная отправка кода", resp.StatusCode, resp.Status, body, "Не удалось повторно отправить код")
	}
	var out struct {
		OK          bool   `json:"ok"`
		MaskedEmail string `json:"masked_email,omitempty"`
		TTLSeconds  int    `json:"ttl_seconds,omitempty"`
	}
	if err := decodeJSONWithTextFallback(body, &out); err != nil {
		return challenge, err
	}
	if out.OK {
		if strings.TrimSpace(out.MaskedEmail) != "" {
			challenge.MaskedEmail = strings.TrimSpace(out.MaskedEmail)
		}
		if out.TTLSeconds > 0 {
			challenge.TTLSeconds = out.TTLSeconds
		}
	}
	return challenge, nil
}

func FetchSelfSession(cfg state.Config) (model.ClientSession, error) {
	s, ok := currentSession()
	if !ok {
		return model.ClientSession{}, fmt.Errorf("not connected")
	}
	if err := sendHeartbeat(cfg, s); err != nil {
		return model.ClientSession{}, err
	}
	s2, _ := currentSession()
	return s2, nil
}

func FetchClients(cfg state.Config) ([]model.ClientSession, error) {
	s, err := FetchSelfSession(cfg)
	if err != nil {
		return nil, err
	}
	return []model.ClientSession{s}, nil
}

func FetchCommands(cfg state.Config) ([]model.Command, error) { return nil, nil }

func SendAppsReport(cfg state.Config, report model.AppsReport) error {
	httpClient, _, err := newPersistentMTLSHTTPClient(cfg, 10*time.Second)
	if err != nil {
		return readableRequestError("Передача списка приложений", err)
	}
	payload := struct {
		Username    string                `json:"username"`
		CommandID   string                `json:"command_id,omitempty"`
		GeneratedAt string                `json:"generated_at,omitempty"`
		Stage       string                `json:"stage,omitempty"`
		Apps        []model.AppReportItem `json:"apps"`
	}{Username: strings.TrimSpace(cfg.Username), CommandID: strings.TrimSpace(report.CommandID), GeneratedAt: strings.TrimSpace(report.GeneratedAt), Stage: "server", Apps: report.Apps}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal apps report: %w", err)
	}
	candidates := []string{}
	seen := map[string]struct{}{}
	for _, p := range []string{strings.TrimSpace(cfg.AppsReportPath), "/api/client/apps", "/api/admin/apps/report", "/api/admin/apps"} {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		candidates = append(candidates, p)
	}
	var lastErr error
	for _, path := range candidates {
		urlValue := joinURL(cfg.ServerURL, path)
		req, err := http.NewRequest(http.MethodPost, urlValue, bytes.NewReader(bodyBytes))
		if err != nil {
			lastErr = readableRequestError("Передача списка приложений", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		applyClientHeaders(req)
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = readableRequestError("Передача списка приложений", err)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		body = trimJSONBody(body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		if resp.StatusCode == http.StatusLocked {
			var decision model.AppPolicyDecision
			if err := json.Unmarshal(body, &decision); err == nil && !decision.Allow {
				msg := strings.TrimSpace(decision.Message)
				if msg == "" {
					msg = "У вас обнаружено запрещенное приложение"
				}
				lastErr = fmt.Errorf(msg)
				break
			}
		}
		lastErr = readableHTTPError("Передача списка приложений", resp.StatusCode, resp.Status, body, "Сервер отклонил список приложений")
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("Передача списка приложений: путь endpoint не настроен")
	}
	return lastErr
}

func Disconnect(cfg state.Config) error {
	activeOpMu.Lock()
	defer activeOpMu.Unlock()
	return disconnectLocked(cfg, true)
}

func ReconnectVPN(cfg state.Config, attempts int, baseDelay time.Duration) (model.ClientSession, error) {
	activeOpMu.Lock()
	defer activeOpMu.Unlock()

	if attempts <= 0 {
		attempts = 1
	}
	if baseDelay <= 0 {
		baseDelay = time.Second
	}
	_ = disconnectLocked(cfg, false)

	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			delay := baseDelay * time.Duration(1<<(i-1))
			time.Sleep(delay)
		}
		session, err := connectVPNLocked(cfg)
		if err == nil {
			return session, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("reconnect failed")
	}
	return model.ClientSession{}, lastErr
}

func disconnectLocked(cfg state.Config, notify bool) error {
	activeMu.Lock()
	session := activeSession
	httpClient := activeClient
	cancel := activeCancel
	tr := activeTransport
	applier := activeRuntime
	activeConnected = false
	activeStopping = true
	activeBase = ""
	activeClient = nil
	activeTransport = nil
	activeRuntime = nil
	activeCancel = nil
	dataConn := activeDataConn
	activeDataConn = nil
	activeMu.Unlock()

	if dataConn != nil {
		_ = dataConn.Close()
	}

	if notify && httpClient != nil && strings.TrimSpace(session.Username) != "" {
		_ = sendDisconnectNoticeWithClient(cfg, session, httpClient)
	}

	if cancel != nil {
		cancel()
	}
	if applier != nil {
		_ = applier.Revert(context.Background())
	}
	activeWG.Wait()
	if tr != nil {
		tr.CloseIdleConnections()
	}

	activeMu.Lock()
	activeSession = model.ClientSession{}
	activeStopping = false
	activeBase = ""
	activeMu.Unlock()

	ClearDataplaneSnapshot()
	return nil
}

func sendDisconnectNotice(cfg state.Config, s model.ClientSession) error {
	activeMu.RLock()
	httpClient := activeClient
	activeMu.RUnlock()
	return sendDisconnectNoticeWithClient(cfg, s, httpClient)
}

func sendDisconnectNoticeWithClient(cfg state.Config, s model.ClientSession, httpClient *http.Client) error {
	if httpClient == nil {
		return nil
	}
	payload := model.ClientHeartbeat{
		Username:     strings.TrimSpace(s.Username),
		SystemUser:   system.DetectSystemUser(),
		OSName:       s.OSType,
		OSVersion:    s.OSVersion,
		SystemUptime: system.DetectSystemUptime(),
		IP:           s.IP,
		MAC:          empty(system.DetectPrimaryMAC()),
		Source:       "mtls-vpn",
		Interfaces:   detectInterfacesModel(),
		MTLSVerified: true,
	}
	body := map[string]any{
		"username":       payload.Username,
		"system_user":    payload.SystemUser,
		"os_name":        payload.OSName,
		"os_version":     payload.OSVersion,
		"system_uptime":  payload.SystemUptime,
		"ip":             payload.IP,
		"mac":            payload.MAC,
		"source":         payload.Source,
		"interfaces":     payload.Interfaces,
		"connect_intent": "disconnect",
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return readableRequestError("Отключение", err)
	}
	req, err := http.NewRequest(http.MethodPost, joinURL(cfg.ServerURL, HeartbeatPath), bytes.NewReader(bodyBytes))
	if err != nil {
		return readableRequestError("Отключение", err)
	}
	req.Header.Set("Content-Type", "application/json")
	applyClientHeaders(req)
	resp, err := httpClient.Do(req)
	if err != nil {
		return readableRequestError("Отключение", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 256))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return readableHTTPError("Отключение", resp.StatusCode, resp.Status, body, "Сервер отклонил отключение")
	}
	return nil
}

func sendHeartbeat(cfg state.Config, s model.ClientSession) error {
	activeMu.RLock()
	httpClient := activeClient
	activeMu.RUnlock()
	if httpClient == nil {
		return fmt.Errorf("not connected")
	}
	payload := model.ClientHeartbeat{
		Username:     strings.TrimSpace(s.Username),
		SystemUser:   system.DetectSystemUser(),
		OSName:       s.OSType,
		OSVersion:    s.OSVersion,
		SystemUptime: system.DetectSystemUptime(),
		IP:           s.IP,
		MAC:          empty(system.DetectPrimaryMAC()),
		Source:       "mtls-vpn",
		Interfaces:   detectInterfacesModel(),
		MTLSVerified: true,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, joinURL(cfg.ServerURL, HeartbeatPath), bytes.NewReader(bodyBytes))
	if err != nil {
		return readableRequestError("Heartbeat", err)
	}
	req.Header.Set("Content-Type", "application/json")
	applyClientHeaders(req)
	resp, err := httpClient.Do(req)
	if err != nil {
		return readableRequestError("Heartbeat", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return readableHTTPError("Heartbeat", resp.StatusCode, resp.Status, body, "Сервер отклонил heartbeat")
	}
	return nil
}

func buildMTLSTLSConfig(cfg state.Config) (*tls.Config, error) {
	if !fileExists(cfg.CACertFile) {
		return nil, fmt.Errorf("не найден CA сертификат")
	}
	if !fileExists(cfg.ClientCertFile) {
		return nil, fmt.Errorf("не найден client certificate")
	}
	if !fileExists(cfg.ClientKeyFile) {
		return nil, fmt.Errorf("не найден client key")
	}
	caData, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("invalid CA PEM")
	}
	cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert}}
	if cfg.ServerName != "" {
		tlsCfg.ServerName = cfg.ServerName
	}
	return tlsCfg, nil
}

func openVPNStream(cfg state.Config, s model.ClientSession) (net.Conn, *bufio.Reader, error) {
	base := strings.TrimSpace(cfg.ServerURL)
	u, err := url.Parse(base)
	if err != nil {
		return nil, nil, err
	}
	host := u.Host
	if host == "" {
		return nil, nil, fmt.Errorf("empty host")
	}
	addr := host
	if !strings.Contains(addr, ":") {
		if u.Scheme == "https" || u.Scheme == "" {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}
	tlsCfg, err := buildMTLSTLSConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	if err != nil {
		return nil, nil, err
	}
	path := VPNStreamPath + "?username=" + url.QueryEscape(strings.TrimSpace(s.Username)) + "&tunnel_id=" + url.QueryEscape(fmt.Sprintf("%d", s.TunnelID))
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", path, u.Host)
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, nil, err
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	parts := strings.Split(strings.TrimSpace(line), " ")
	if len(parts) < 2 || parts[1] != "200" {
		body, _ := br.ReadString('\n')
		conn.Close()
		return nil, nil, fmt.Errorf("vpn-stream status: %s %s", strings.TrimSpace(line), strings.TrimSpace(body))
	}
	for {
		line, err = br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		if line == "\r\n" {
			break
		}
	}
	return conn, br, nil
}

func dataplaneStreamWriteLoop(ctx context.Context, conn net.Conn, s model.ClientSession, applier *runtimeApplier, seq *atomic.Uint64) {
	defer activeWG.Done()
	f := applier.TunReadFile()
	if f == nil {
		return
	}
	bw := bufio.NewWriterSize(conn, 256*1024)
	buf := make([]byte, 65535)
	for {
		_ = f.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := f.Read(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if isDataplaneShutdownError(ctx, err) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			dataplaneMarkError(err)
			return
		}
		if n <= 0 {
			continue
		}
		dataplaneCtrs.TunReads.Add(1)
		dataplaneCtrs.TunReadBytes.Add(uint64(n))
		dataplaneMarkFrame()
		frame := buildVPNFrame(frameTypeIPv4, s.TunnelID, seq.Add(1), buf[:n])
		var hdr [4]byte
		binary.LittleEndian.PutUint32(hdr[:], uint32(len(frame)))
		if _, err := bw.Write(hdr[:]); err != nil {
			dataplaneMarkError(err)
			return
		}
		if _, err := bw.Write(frame); err != nil {
			dataplaneMarkError(err)
			return
		}
		if err := bw.Flush(); err != nil {
			dataplaneMarkError(err)
			return
		}
		dataplaneCtrs.FramePosts.Add(1)
	}
}

func dataplaneStreamReadLoop(ctx context.Context, br *bufio.Reader, conn net.Conn, s model.ClientSession, applier *runtimeApplier, seq *atomic.Uint64) {
	defer activeWG.Done()
	f := applier.TunWriteFile()
	if f == nil {
		return
	}
	var hdr [4]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if isDataplaneShutdownError(ctx, err) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			dataplaneMarkError(err)
			return
		}
		frameLen := binary.LittleEndian.Uint32(hdr[:])
		if frameLen == 0 {
			continue
		}
		if frameLen > 8*1024*1024 {
			dataplaneMarkError(fmt.Errorf("stream frame too large: %d", frameLen))
			return
		}
		frame := make([]byte, frameLen)
		if _, err := io.ReadFull(br, frame); err != nil {
			dataplaneMarkError(err)
			return
		}
		dataplaneCtrs.PollFrames.Add(1)
		dataplaneMarkFrame()
		typeID, _, payload, err := parseVPNFrame(frame)
		if err != nil {
			if len(frame) > 0 && (frame[0]>>4) == 4 {
				if n, werr := f.Write(frame); werr == nil {
					dataplaneCtrs.TunWrites.Add(1)
					dataplaneCtrs.TunWriteBytes.Add(uint64(n))
				}
				continue
			}
			dataplaneMarkError(err)
			return
		}
		if typeID == frameTypeIPv4 && len(payload) > 0 {
			if n, werr := f.Write(payload); werr == nil {
				dataplaneCtrs.TunWrites.Add(1)
				dataplaneCtrs.TunWriteBytes.Add(uint64(n))
			}
		}
	}
}

func startDataplane(ctx context.Context, cfg state.Config, s model.ClientSession, applier *runtimeApplier, httpClient *http.Client) {
	resetDataplaneSnapshot(ActiveTunName())
	if applier == nil || applier.TunReadFile() == nil || applier.TunWriteFile() == nil || s.TunnelID == 0 {
		dataplaneLogf("DATAPLANE not started: tun_read=%v tun_write=%v tunnel_id=%d", applier != nil && applier.TunReadFile() != nil, applier != nil && applier.TunWriteFile() != nil, s.TunnelID)
		return
	}
	dataplaneLogf("DATAPLANE started: tunnel=%d vip=%s gw=%s server=%s", s.TunnelID, strings.TrimSpace(s.IP), strings.TrimSpace(s.Gateway), strings.TrimSpace(activeBaseURL()))
	var seq atomic.Uint64
	seq.Store(0)
	if conn, br, err := openVPNStream(cfg, s); err == nil {
		setActiveDataConn(conn)
		dataplaneLogf("DATAPLANE full-duplex stream started: tunnel=%d", s.TunnelID)
		activeWG.Add(2)
		go dataplaneStreamWriteLoop(ctx, conn, s, applier, &seq)
		go dataplaneStreamReadLoop(ctx, br, conn, s, applier, &seq)
		return
	} else {
		dataplaneLogf("DATAPLANE full-duplex stream unavailable, fallback to frame/poll: tunnel=%d err=%v", s.TunnelID, err)
	}
	activeWG.Add(2)
	go func() {
		defer activeWG.Done()
		dataplaneReadLoop(ctx, httpClient, s, applier, &seq)
	}()
	go func() {
		defer activeWG.Done()
		dataplanePollLoop(ctx, httpClient, s, applier, &seq)
	}()
}

func isDataplaneShutdownError(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	if dataplaneShouldStop() {
		return true
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if strings.Contains(msg, "unsupported protocol scheme") {
		return true
	}
	if strings.Contains(msg, "file already closed") || strings.Contains(msg, "use of closed file") {
		return true
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "context canceled")
}

func dataplaneReadLoop(ctx context.Context, httpClient *http.Client, s model.ClientSession, applier *runtimeApplier, seq *atomic.Uint64) {
	f := applier.TunReadFile()
	if f == nil {
		dataplaneLogf("DATAPLANE read loop skipped: tun file missing")
		return
	}
	dataplaneLogf("DATAPLANE read loop started: tunnel=%d fd=%d", s.TunnelID, f.Fd())
	buf := make([]byte, 65535)
	var reads uint64
	for {
		_ = f.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := f.Read(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if isDataplaneShutdownError(ctx, err) {
				return
			}
			continue
		}
		if n <= 0 {
			continue
		}
		reads++
		dataplaneCtrs.TunReads.Add(1)
		dataplaneCtrs.TunReadBytes.Add(uint64(n))
		dataplaneMarkFrame()
		if reads <= 5 || reads%50 == 0 {
			dataplaneLogf("DATAPLANE read from TUN: tunnel=%d bytes=%d", s.TunnelID, n)
		}
		frame := buildVPNFrame(frameTypeIPv4, s.TunnelID, seq.Add(1), buf[:n])
		if err := postFrame(ctx, httpClient, s, frame); err != nil {
			if isDataplaneShutdownError(ctx, err) {
				return
			}
			dataplaneCtrs.FramePostErrors.Add(1)
			dataplaneMarkError(err)
			dataplaneLogf("DATAPLANE post frame failed: tunnel=%d bytes=%d err=%v", s.TunnelID, n, err)
			continue
		}
		if reads <= 5 || reads%50 == 0 {
			dataplaneLogf("DATAPLANE frame sent: tunnel=%d bytes=%d", s.TunnelID, n)
		}
	}
}

func dataplanePollLoop(ctx context.Context, httpClient *http.Client, s model.ClientSession, applier *runtimeApplier, seq *atomic.Uint64) {
	f := applier.TunWriteFile()
	if f == nil {
		dataplaneLogf("DATAPLANE poll loop skipped: tun file missing")
		return
	}
	dataplaneLogf("DATAPLANE poll loop started: tunnel=%d fd=%d", s.TunnelID, f.Fd())
	keepTicker := time.NewTicker(5 * time.Second)
	pollTicker := time.NewTicker(20 * time.Millisecond)
	defer keepTicker.Stop()
	defer pollTicker.Stop()
	var received uint64
	writePayload := func(raw []byte) {
		if len(raw) == 0 {
			return
		}
		received++
		if n, werr := f.Write(raw); werr != nil {
			dataplaneMarkError(werr)
			dataplaneLogf("DATAPLANE write to TUN failed: tunnel=%d bytes=%d err=%v", s.TunnelID, len(raw), werr)
		} else {
			dataplaneCtrs.TunWrites.Add(1)
			dataplaneCtrs.TunWriteBytes.Add(uint64(n))
			dataplaneMarkFrame()
			if received <= 5 || received%50 == 0 {
				dataplaneLogf("DATAPLANE write to TUN: tunnel=%d bytes=%d wrote=%d", s.TunnelID, len(raw), n)
			}
			if received <= 5 || received%50 == 0 {
				dataplaneLogf("DATAPLANE frame received: tunnel=%d bytes=%d", s.TunnelID, len(raw))
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-keepTicker.C:
			seq.Add(1)
			if err := postFrame(ctx, httpClient, s, nil); err != nil {
				if isDataplaneShutdownError(ctx, err) {
					return
				}
				dataplaneCtrs.KeepaliveErrors.Add(1)
				dataplaneMarkError(err)
				dataplaneLogf("DATAPLANE keepalive failed: tunnel=%d err=%v", s.TunnelID, err)
			} else {
				dataplaneCtrs.Keepalives.Add(1)
			}
		case <-pollTicker.C:
			for i := 0; i < 32; i++ {
				dataplaneCtrs.PollRequests.Add(1)
				frameHex, err := pollFrame(ctx, httpClient, s)
				if err != nil {
					if isDataplaneShutdownError(ctx, err) {
						return
					}
					dataplaneCtrs.PollErrors.Add(1)
					dataplaneMarkError(err)
					if i == 0 {
						dataplaneLogf("DATAPLANE poll failed: tunnel=%d err=%v", s.TunnelID, err)
					}
					break
				}
				if strings.TrimSpace(frameHex) == "" {
					break
				}
				dataplaneCtrs.PollFrames.Add(1)
				dataplaneMarkFrame()
				frame, err := hex.DecodeString(frameHex)
				if err != nil {
					dataplaneLogf("DATAPLANE decode poll frame failed: %v", err)
					break
				}
				typeID, _, payload, err := parseVPNFrame(frame)
				if err != nil {
					// Fallback: some plugin builds may return raw IPv4 payload instead of full VPN frame.
					if len(frame) > 0 && (frame[0]>>4) == 4 {
						writePayload(frame)
						continue
					}
					dataplaneLogf("DATAPLANE parse poll frame failed: %v", err)
					break
				}
				if typeID == frameTypeIPv4 && len(payload) > 0 {
					writePayload(payload)
				}
			}
		}
	}
}

func postFrame(ctx context.Context, httpClient *http.Client, s model.ClientSession, frame []byte) error {
	if ctx != nil && ctx.Err() != nil {
		return context.Canceled
	}
	baseURL, activeHTTPClient, stopping := dataplaneActiveState()
	if stopping {
		return context.Canceled
	}
	if httpClient == nil {
		httpClient = activeHTTPClient
	}
	if httpClient == nil || strings.TrimSpace(baseURL) == "" {
		return context.Canceled
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || strings.TrimSpace(parsed.Scheme) == "" || strings.TrimSpace(parsed.Host) == "" {
		return context.Canceled
	}
	payload := map[string]any{
		"username":  strings.TrimSpace(s.Username),
		"tunnel_id": fmt.Sprintf("%d", s.TunnelID),
	}
	if len(frame) > 0 {
		payload["frame_hex"] = hex.EncodeToString(frame)
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return readableRequestError("Передача VPN-кадра", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, joinURL(strings.TrimRight(strings.TrimSpace(baseURL), "/"), VPNFramePath), bytes.NewReader(bodyBytes))
	if err != nil {
		return readableRequestError("Передача VPN-кадра", err)
	}
	req.Header.Set("Content-Type", "application/json")
	applyClientHeaders(req)
	resp, err := httpClient.Do(req)
	if err != nil {
		return readableRequestError("Передача VPN-кадра", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return readableHTTPError("Передача VPN-кадра", resp.StatusCode, resp.Status, body, "Сервер отклонил VPN-кадр")
	}
	dataplaneCtrs.FramePosts.Add(1)
	return nil
}

func pollFrame(ctx context.Context, httpClient *http.Client, s model.ClientSession) (string, error) {
	if ctx != nil && ctx.Err() != nil {
		return "", context.Canceled
	}
	baseURL, activeHTTPClient, stopping := dataplaneActiveState()
	if stopping {
		return "", context.Canceled
	}
	if httpClient == nil {
		httpClient = activeHTTPClient
	}
	if httpClient == nil || strings.TrimSpace(baseURL) == "" {
		return "", context.Canceled
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || strings.TrimSpace(parsed.Scheme) == "" || strings.TrimSpace(parsed.Host) == "" {
		return "", context.Canceled
	}
	q := url.Values{}
	q.Set("tunnel_id", fmt.Sprintf("%d", s.TunnelID))
	q.Set("username", strings.TrimSpace(s.Username))
	urlStr := joinURL(strings.TrimRight(strings.TrimSpace(baseURL), "/"), VPNPollPath) + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return "", err
	}
	applyClientHeaders(req)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", readableHTTPError("Получение VPN-кадра", resp.StatusCode, resp.Status, body, "Сервер отклонил poll-запрос")
	}
	var out vpnFrameResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if !out.OK {
		return "", fmt.Errorf("Получение VPN-кадра: сервер вернул неуспешный ответ")
	}
	return out.FrameHex, nil
}

func activeBaseURL() string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if activeStopping {
		return ""
	}
	return strings.TrimSpace(activeBase)
}

func ActiveTunName() string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if activeRuntime != nil {
		return activeRuntime.InterfaceName()
	}
	return "tlsvpn0"
}

func SetDataplaneLogger(fn func(string)) {
	dataplaneLogMu.Lock()
	dataplaneLogger = fn
	dataplaneLogMu.Unlock()
}

func dataplaneLogf(format string, args ...any) {
	dataplaneLogMu.RLock()
	fn := dataplaneLogger
	dataplaneLogMu.RUnlock()
	if fn == nil {
		return
	}
	fn(fmt.Sprintf(format, args...))
}

func buildVPNFrame(frameType uint8, tunnelID, seq uint64, payload []byte) []byte {
	b := make([]byte, 24+len(payload))
	b[0] = frameType
	b[1] = 0
	binary.LittleEndian.PutUint16(b[2:4], 0)
	binary.LittleEndian.PutUint32(b[4:8], uint32(len(payload)))
	binary.LittleEndian.PutUint64(b[8:16], tunnelID)
	binary.LittleEndian.PutUint64(b[16:24], seq)
	copy(b[24:], payload)
	return b
}

func parseVPNFrame(frame []byte) (uint8, uint64, []byte, error) {
	if len(frame) < 24 {
		return 0, 0, nil, fmt.Errorf("short frame")
	}
	frameType := frame[0]
	payloadLen := binary.LittleEndian.Uint32(frame[4:8])
	tunnelID := binary.LittleEndian.Uint64(frame[8:16])
	if len(frame) < 24+int(payloadLen) {
		return 0, 0, nil, fmt.Errorf("bad frame len")
	}
	payload := append([]byte(nil), frame[24:24+int(payloadLen)]...)
	return frameType, tunnelID, payload, nil
}

func newPersistentMTLSHTTPClient(cfg state.Config, timeout time.Duration) (*http.Client, *http.Transport, error) {
	tlsCfg, err := buildMTLSTLSConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	tr := &http.Transport{
		TLSClientConfig:     tlsCfg,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     30 * time.Minute,
		DisableCompression:  true,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	}
	return &http.Client{Timeout: timeout, Transport: tr}, tr, nil
}

func IsUnauthorizedError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "401 unauthorized") || strings.Contains(s, "status: 401") || strings.Contains(s, "invalid or revoked") || strings.Contains(s, "certificate invalid") || strings.Contains(s, "certificate serial mismatch") || strings.Contains(s, "unknown or disabled user")
}

func joinURL(base, path string) string {
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

func empty(v string) string {
	if strings.TrimSpace(v) == "" {
		return "—"
	}
	return v
}

func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }

func IsBackendUnavailableError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "503 service unavailable") || strings.Contains(s, "status: 503") || strings.Contains(s, "vpp api unavailable") || strings.Contains(s, "connection refused")
}
