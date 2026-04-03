package app

import (
	"strconv"
	"strings"
	"time"

	"tlsclientnative/internal/client"
	"tlsclientnative/internal/state"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
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
	}()
}

func formatTunnelID(id uint64) string { return strconv.FormatUint(id, 10) }

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
