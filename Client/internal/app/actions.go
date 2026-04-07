package app

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tlsclientnative/internal/client"
	"tlsclientnative/internal/model"
	"tlsclientnative/internal/state"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

func (u *UI) toggleConnect() {
	u.mu.RLock()
	connected := u.connected
	u.mu.RUnlock()
	if connected {
		u.disconnectOnce()
		return
	}
	u.connectOnce()
}

func (u *UI) loadBundle() {
	d := dialog.NewFileOpen(func(r fyne.URIReadCloser, err error) {
		if err != nil {
			dialog.ShowError(err, u.window)
			return
		}
		if r == nil {
			return
		}
		defer r.Close()
		cfg, err := importBundleReader(r, u.cfg)
		if err != nil {
			dialog.ShowError(err, u.window)
			u.setStatus("Ошибка конфигурации: " + err.Error())
			u.appendLog("Ошибка конфигурации: " + err.Error())
			u.updateConnectionUI(false, "error")
			return
		}
		u.mu.Lock()
		u.cfg = cfg
		u.mu.Unlock()
		u.serverURL.SetText(cfg.ServerURL)
		u.serverName.SetText(cfg.ServerName)
		u.clientsPath.SetText(cfg.ClientsPath)
		u.username.SetText(cfg.Username)
		u.profile.SetText(cfg.Profile)
		u.appsReportPath.SetText(cfg.AppsReportPath)
		u.bundleStatus.SetText(u.bundleStatusText())
		u.renderSelfState()
		u.setStatus("Конфигурация загружена")
		u.appendLog("Конфигурация успешно загружена")
	}, u.window)
	d.SetFilter(storageZipFilter{})
	d.Show()
}

func (u *UI) connectOnce() {
	if err := u.syncFormToConfig(); err != nil {
		dialog.ShowError(err, u.window)
		return
	}
	u.setStatus("Подключение...")
	u.appendLog("Попытка подключения к VPN plugin")
	u.updateConnectionUI(false, "pending")
	go func() {
		session, err := client.ConnectVPN(u.cfg)
		if err != nil {
			u.setStatus("Ошибка подключения: " + err.Error())
			u.appendLog("Ошибка подключения: " + err.Error())
			u.showConnectErrorDialog(err)
			if client.IsUnauthorizedError(err) {
				u.markDisconnectedLocalReason("сертификат отклонён сервером: требуется новая конфигурация", "disconnected")
			} else if client.IsBackendUnavailableError(err) {
				u.markDisconnectedLocalReason("backend недоступен: VPP выключен или недоступен", "disconnected")
			} else {
				u.markDisconnectedLocalReason("ошибка подключения: "+err.Error(), "error")
			}
			return
		}
		u.mu.Lock()
		u.self = session
		u.lastSuccess = time.Now().UTC()
		u.connected = true
		u.monitorFailures = 0
		u.lastMonitorError = ""
		u.mu.Unlock()
		u.renderSelfState()
		u.updateConnectionUI(true, "connected")
		u.setStatus("Подключено")
		u.appendLog("VPN bind выполнен, tunnel_id=" + strings.TrimSpace(formatTunnelID(session.TunnelID)))
		go u.refreshProcesses()
	}()
}

func formatTunnelID(id uint64) string { return strconv.FormatUint(id, 10) }

var policyMessageFieldRE = regexp.MustCompile(`(?s)"message"\s*:\s*"((?:\\.|[^"])*)"`)

func extractPolicyMessageLoose(msg string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return ""
	}
	if m := policyMessageFieldRE.FindStringSubmatch(msg); len(m) > 1 {
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

func cleanConnectErrorMessage(err error) string {
	if err == nil {
		return "Неизвестная ошибка подключения"
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return "Неизвестная ошибка подключения"
	}
	if loose := extractPolicyMessageLoose(msg); loose != "" {
		return loose
	}
	for _, candidate := range []string{msg, strings.TrimSpace(extractJSONTail(msg))} {
		if candidate == "" {
			continue
		}
		var decision model.AppPolicyDecision
		if err := json.Unmarshal([]byte(candidate), &decision); err == nil {
			if clean := strings.TrimSpace(decision.Message); clean != "" {
				return clean
			}
			return "У вас обнаружено запрещенное приложение"
		}
	}
	if idx := strings.Index(msg, "ответ сервера:"); idx >= 0 {
		rest := strings.TrimSpace(msg[idx+len("ответ сервера:"):])
		if rest != "" {
			if tail := strings.TrimSpace(extractJSONTail(rest)); tail != "" {
				var decision model.AppPolicyDecision
				if err := json.Unmarshal([]byte(tail), &decision); err == nil {
					if clean := strings.TrimSpace(decision.Message); clean != "" {
						return clean
					}
					return "У вас обнаружено запрещенное приложение"
				}
			}
			msg = rest
		} else {
			msg = strings.TrimSpace(msg[:idx])
		}
	}
	if loose := extractPolicyMessageLoose(msg); loose != "" {
		return loose
	}
	if strings.HasPrefix(msg, "policy bootstrap status") {
		if colon := strings.Index(msg, ":"); colon >= 0 && colon+1 < len(msg) {
			msg = strings.TrimSpace(msg[colon+1:])
		}
	}
	if tail := strings.TrimSpace(extractJSONTail(msg)); tail != "" {
		var decision model.AppPolicyDecision
		if err := json.Unmarshal([]byte(tail), &decision); err == nil {
			if clean := strings.TrimSpace(decision.Message); clean != "" {
				return clean
			}
			return "У вас обнаружено запрещенное приложение"
		}
	}
	if loose := extractPolicyMessageLoose(msg); loose != "" {
		return loose
	}
	if strings.HasPrefix(strings.TrimSpace(msg), "{") || strings.Contains(msg, "{\"") {
		return "У вас обнаружено запрещенное приложение"
	}
	return msg
}

func extractJSONTail(msg string) string {
	idx := strings.Index(msg, "{")
	if idx < 0 || idx >= len(msg) {
		return ""
	}
	return strings.TrimSpace(msg[idx:])
}

func (u *UI) showConnectErrorDialog(err error) {
	if err == nil || u == nil || u.window == nil {
		return
	}
	msg := cleanConnectErrorMessage(err)
	title := "Ошибка подключения"
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "запрещ") || strings.Contains(lower, "policy") || strings.Contains(lower, "blocked") || strings.Contains(lower, "deny") {
		title = "Подключение заблокировано политикой"
	}
	body := widget.NewLabel(msg)
	body.Wrapping = fyne.TextWrapWord
	fyne.Do(func() {
		dialog.NewCustom(title, "Закрыть", container.NewVBox(body), u.window).Show()
	})
}

func (u *UI) disconnectOnce() {
	if err := u.syncFormToConfig(); err != nil {
		dialog.ShowError(err, u.window)
		return
	}
	u.setStatus("Отключение...")
	u.appendLog("Запрошено отключение")
	go func() {
		err := client.Disconnect(u.cfg)
		u.mu.Lock()
		u.connected = false
		u.monitorFailures = 0
		u.lastMonitorError = ""
		u.mu.Unlock()
		if err != nil {
			u.setStatus("Ошибка отключения: " + err.Error())
			u.appendLog("Ошибка отключения: " + err.Error())
			u.markDisconnectedLocalReason("ошибка отключения: "+err.Error(), "error")
			return
		}
		u.markDisconnectedLocalReason("ручное отключение", "disconnected")
		u.setStatus("Клиент отключён")
		u.appendLog("Клиент отключён")
	}()
}

func (u *UI) toggleAutoRefresh() {
	u.mu.Lock()
	u.autoRefresh = !u.autoRefresh
	current := u.autoRefresh
	u.mu.Unlock()
	if current {
		fyne.Do(func() { u.autoButton.SetText("Автообновление: ВКЛ") })
		u.setStatus("Автообновление локальных данных включено")
		u.appendLog("Автообновление локальных данных включено")
		return
	}
	fyne.Do(func() { u.autoButton.SetText("Автообновление") })
	u.setStatus("Автообновление локальных данных выключено")
	u.appendLog("Автообновление локальных данных выключено")
}

func (u *UI) monitorLoop() {
	for {
		select {
		case <-u.stopCh:
			return
		case <-time.After(1 * time.Second):
		}
		u.mu.RLock()
		connected := u.connected
		cfg := u.cfg
		closing := u.closing
		autoRefresh := u.autoRefresh
		u.mu.RUnlock()
		if closing {
			return
		}
		if !connected {
			continue
		}
		session, err := client.FetchSelfSession(cfg)
		if err != nil {
			u.handleMonitorFailure(err)
			continue
		}
		u.mu.Lock()
		prevErr := u.lastMonitorError
		u.self = session
		u.lastSuccess = time.Now().UTC()
		u.monitorFailures = 0
		u.lastMonitorError = ""
		u.mu.Unlock()
		if prevErr != "" {
			u.appendLog("Связь с VPN plugin восстановлена")
		}
		u.renderSelfState()
		u.updateConnectionUI(true, "connected")
		if autoRefresh {
			go u.refreshProcesses()
		}
		for i := 0; i < cfg.PollSeconds*10; i++ {
			u.mu.RLock()
			stillConnected := u.connected
			closing = u.closing
			u.mu.RUnlock()
			if closing || !stillConnected {
				break
			}
			select {
			case <-u.stopCh:
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
}

func (u *UI) processPendingCommands(cfg state.Config) error { return nil }

func (u *UI) handleMonitorFailure(err error) {
	reason := err.Error()
	u.mu.Lock()
	u.monitorFailures++
	count := u.monitorFailures
	last := u.lastMonitorError
	cfg := u.cfg
	u.lastMonitorError = reason
	u.mu.Unlock()
	if count == 1 || last != reason {
		u.appendLog("Проблема связи с VPN plugin: " + reason)
		u.setStatus("Проблема связи с сервером")
	}
	if count >= 3 {
		_ = client.Disconnect(cfg)
		u.markDisconnectedLocalReason("нет связи с VPN plugin: "+reason, "error")
	}
}

func (u *UI) cleanupSeenCommands() {}
func isAppsCommand(t string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(t)), "app") || strings.Contains(strings.ToLower(strings.TrimSpace(t)), "process")
}

func (u *UI) quitApp() {
	u.mu.Lock()
	if u.closing {
		u.mu.Unlock()
		return
	}
	u.closing = true
	u.connected = false
	u.autoRefresh = false
	u.mu.Unlock()
	select {
	case <-u.stopCh:
	default:
		close(u.stopCh)
	}
	_ = u.syncFormToConfig()
	u.setStatus("Выход...")
	u.appendLog("Выход из приложения")
	go func() { _ = client.Disconnect(u.cfg); fyne.Do(func() { u.app.Quit() }) }()
}
