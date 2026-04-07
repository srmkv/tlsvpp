package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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
	policyBootstrapDefaultPath  = "/api/client/policy-bootstrap"
	policyBootstrapFallbackPath = ""
	policyViolationDefaultPath  = "/api/client/policy-violation"
	policyViolationFallbackPath = "/api/plugin/app-policy/violation"
	frameTypeKeepalive          = 1
	frameTypeIPv4               = 2
)

var (
	activeMu        sync.RWMutex
	activeClient    *http.Client
	activeTransport *http.Transport
	activeSession   model.ClientSession
	activeConnected bool
	activeRuntime   *runtimeApplier
	activeCancel    context.CancelFunc
	activeWG        sync.WaitGroup
	activeBase      string
)

type vpnBindResponse struct {
	OK            bool   `json:"ok"`
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
		return err
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
			lastErr = fmt.Errorf(extractDecisionMessage(body, "Ошибка проверки политики"))
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
			lastErr = fmt.Errorf(extractDecisionMessage(body, "Ошибка проверки политики"))
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
		"matched_apps": matchedApps,
		"action":       "deny_connect",
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
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
		return err
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
	if !activeConnected {
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
	activeConnected = true
}

func ConnectVPN(cfg state.Config) (model.ClientSession, error) {
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
		return model.ClientSession{}, fmt.Errorf("build vpn-bind request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	applyClientHeaders(req)

	resp, err := httpClient.Do(req)
	if err != nil {
		return model.ClientSession{}, fmt.Errorf("vpn-bind request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if len(body) > 0 {
			return model.ClientSession{}, fmt.Errorf("unexpected status: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		return model.ClientSession{}, fmt.Errorf("unexpected status: %s", resp.Status)
	}
	var reply vpnBindResponse
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return model.ClientSession{}, fmt.Errorf("decode vpn-bind response: %w", err)
	}
	if !reply.OK {
		return model.ClientSession{}, fmt.Errorf("vpn-bind failed")
	}

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
		return model.ClientSession{}, fmt.Errorf("apply linux runtime: %w", err)
	}

	osType, osVersion := system.DetectOSInfo()
	now := time.Now().UTC().Format(time.RFC3339)
	session := model.ClientSession{
		Username:     strings.TrimSpace(cfg.Username),
		Profile:      profile,
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
		return err
	}
	payload := struct {
		Username    string                `json:"username"`
		CommandID   string                `json:"command_id,omitempty"`
		GeneratedAt string                `json:"generated_at,omitempty"`
		Apps        []model.AppReportItem `json:"apps"`
	}{Username: strings.TrimSpace(cfg.Username), CommandID: strings.TrimSpace(report.CommandID), GeneratedAt: strings.TrimSpace(report.GeneratedAt), Apps: report.Apps}
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
			lastErr = fmt.Errorf("build apps report request: %w", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		applyClientHeaders(req)
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("apps report request failed: %w", err)
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
		lastErr = fmt.Errorf(extractDecisionMessage(body, "Сервер отклонил список приложений"))
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("apps report path is not configured")
	}
	return lastErr
}

func Disconnect(cfg state.Config) error {
	activeMu.RLock()
	session := activeSession
	httpClient := activeClient
	activeMu.RUnlock()
	if httpClient != nil && strings.TrimSpace(session.Username) != "" {
		_ = sendDisconnectNotice(cfg, session)
	}

	activeMu.Lock()
	cancel := activeCancel
	tr := activeTransport
	applier := activeRuntime
	activeConnected = false
	activeTransport = nil
	activeClient = nil
	activeRuntime = nil
	activeCancel = nil
	activeSession = model.ClientSession{}
	activeBase = ""
	activeMu.Unlock()
	if cancel != nil {
		cancel()
	}
	activeWG.Wait()
	if applier != nil {
		_ = applier.Revert(context.Background())
	}
	if tr != nil {
		tr.CloseIdleConnections()
	}
	return nil
}

func sendDisconnectNotice(cfg state.Config, s model.ClientSession) error {
	activeMu.RLock()
	httpClient := activeClient
	activeMu.RUnlock()
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
		return err
	}
	req, err := http.NewRequest(http.MethodPost, joinURL(cfg.ServerURL, HeartbeatPath), bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	applyClientHeaders(req)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 256))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("disconnect heartbeat status: %s", resp.Status)
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
		return fmt.Errorf("build heartbeat request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	applyClientHeaders(req)
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if len(body) > 0 {
			return fmt.Errorf("heartbeat status: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		return fmt.Errorf("heartbeat status: %s", resp.Status)
	}
	return nil
}

func startDataplane(ctx context.Context, cfg state.Config, s model.ClientSession, applier *runtimeApplier, httpClient *http.Client) {
	if applier == nil || applier.TunFile() == nil || s.TunnelID == 0 {
		return
	}
	var seq atomic.Uint64
	seq.Store(0)
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

func dataplaneReadLoop(ctx context.Context, httpClient *http.Client, s model.ClientSession, applier *runtimeApplier, seq *atomic.Uint64) {
	f := applier.TunFile()
	if f == nil {
		return
	}
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
			continue
		}
		if n <= 0 {
			continue
		}
		frame := buildVPNFrame(frameTypeIPv4, s.TunnelID, seq.Add(1), buf[:n])
		_ = postFrame(ctx, httpClient, s, frame)
	}
}

func dataplanePollLoop(ctx context.Context, httpClient *http.Client, s model.ClientSession, applier *runtimeApplier, seq *atomic.Uint64) {
	f := applier.TunFile()
	if f == nil {
		return
	}
	keepTicker := time.NewTicker(5 * time.Second)
	pollTicker := time.NewTicker(200 * time.Millisecond)
	defer keepTicker.Stop()
	defer pollTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-keepTicker.C:
			frame := buildVPNFrame(frameTypeKeepalive, s.TunnelID, seq.Add(1), nil)
			_ = postFrame(ctx, httpClient, s, frame)
		case <-pollTicker.C:
			frameHex, err := pollFrame(ctx, httpClient, s)
			if err != nil || strings.TrimSpace(frameHex) == "" {
				continue
			}
			frame, err := hex.DecodeString(frameHex)
			if err != nil {
				continue
			}
			typeID, _, payload, err := parseVPNFrame(frame)
			if err != nil {
				continue
			}
			if typeID == frameTypeIPv4 && len(payload) > 0 {
				_, _ = f.Write(payload)
			}
		}
	}
}

func postFrame(ctx context.Context, httpClient *http.Client, s model.ClientSession, frame []byte) error {
	payload := map[string]any{
		"username":  strings.TrimSpace(s.Username),
		"tunnel_id": s.TunnelID,
		"frame_hex": hex.EncodeToString(frame),
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, joinURL(strings.TrimRight(strings.TrimSpace(activeBaseURL()), "/"), VPNFramePath), bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	applyClientHeaders(req)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("vpn-frame status: %s", resp.Status)
	}
	return nil
}

func pollFrame(ctx context.Context, httpClient *http.Client, s model.ClientSession) (string, error) {
	url := joinURL(strings.TrimRight(strings.TrimSpace(activeBaseURL()), "/"), VPNPollPath) + fmt.Sprintf("?tunnel_id=%d&username=%s", s.TunnelID, strings.TrimSpace(s.Username))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
		return "", fmt.Errorf("vpn-poll status: %s", resp.Status)
	}
	var out vpnFrameResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if !out.OK {
		return "", fmt.Errorf("vpn-poll failed")
	}
	return out.FrameHex, nil
}

func activeBaseURL() string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return strings.TrimSpace(activeBase)
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
	if !fileExists(cfg.CACertFile) {
		return nil, nil, fmt.Errorf("не найден CA сертификат")
	}
	if !fileExists(cfg.ClientCertFile) {
		return nil, nil, fmt.Errorf("не найден client certificate")
	}
	if !fileExists(cfg.ClientKeyFile) {
		return nil, nil, fmt.Errorf("не найден client key")
	}
	caData, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca cert: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(caData) {
		return nil, nil, fmt.Errorf("invalid CA PEM")
	}
	cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load client certificate: %w", err)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert}}
	if cfg.ServerName != "" {
		tlsCfg.ServerName = cfg.ServerName
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
