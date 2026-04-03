package app

import (
	"fmt"
	"image/color"
	"os"
	"sort"
	"strings"
	"time"
	"tlsclientnative/internal/client"
	"tlsclientnative/internal/model"

	"tlsclientnative/internal/state"
	"tlsclientnative/internal/system"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func (u *UI) bundleStatusText() string {
	parts := make([]string, 0, 3)
	if fileExists(u.cfg.CACertFile) {
		parts = append(parts, "CA: ok")
	} else {
		parts = append(parts, "CA: нет")
	}
	if fileExists(u.cfg.ClientCertFile) {
		parts = append(parts, "CRT: ok")
	} else {
		parts = append(parts, "CRT: нет")
	}
	if fileExists(u.cfg.ClientKeyFile) {
		parts = append(parts, "KEY: ok")
	} else {
		parts = append(parts, "KEY: нет")
	}
	return strings.Join(parts, " | ")
}

func (u *UI) setStatus(msg string) {
	fyne.Do(func() { u.status.SetText(msg) })
}

func (u *UI) appendLog(msg string) {
	line := time.Now().Format("15:04:05") + "  " + msg
	u.mu.Lock()
	u.logLines = append(u.logLines, line)
	u.mu.Unlock()
	u.refreshLogView()
}

func (u *UI) refreshLogView() {
	u.mu.RLock()
	filter := strings.ToLower(strings.TrimSpace(u.logFilter.Text))
	lines := make([]string, 0, len(u.logLines))
	for _, line := range u.logLines {
		if filter == "" || strings.Contains(strings.ToLower(line), filter) {
			lines = append(lines, line)
		}
	}
	u.mu.RUnlock()
	fyne.Do(func() { u.logOutput.SetText(strings.Join(lines, "\n")) })
}

func (u *UI) setConnectedControls(connected bool) {
	fyne.Do(func() {
		u.autoButton.Enable()
		if connected {
			u.connectButton.SetText("Отключить")
			u.connectButton.SetIcon(theme.CancelIcon())
			u.connectButton.Importance = widget.DangerImportance
		} else {
			u.connectButton.SetText("Подключить")
			u.connectButton.SetIcon(theme.MediaPlayIcon())
			u.connectButton.Importance = widget.SuccessImportance
			u.autoButton.SetText("Автообновление")
		}
		u.connectButton.Refresh()
	})
}

func (u *UI) updateConnectionUI(connected bool, rawStatus string) {
	fill := color.NRGBA{R: 100, G: 116, B: 139, A: 255}
	text := "ОТКЛ"
	hint := "Загрузите конфигурацию и нажмите «Подключить»."
	sidebarText := "Статус: выключено"
	switch strings.ToLower(strings.TrimSpace(rawStatus)) {
	case "connected":
		fill = color.NRGBA{R: 22, G: 163, B: 74, A: 255}
		text = "ВКЛ"
		hint = "Соединение активно."
		sidebarText = "Статус: включено"
	case "disconnected":
		fill = color.NRGBA{R: 220, G: 38, B: 38, A: 255}
		text = "ОТКЛ"
		hint = "Соединение отключено."
		sidebarText = "Статус: выключено"
	case "error":
		fill = color.NRGBA{R: 234, G: 179, B: 8, A: 255}
		text = "ОШИБКА"
		hint = "Проверьте адрес сервера и сертификаты."
		sidebarText = "Статус: ошибка"
	case "pending":
		fill = color.NRGBA{R: 59, G: 130, B: 246, A: 255}
		text = "ПОДКЛ"
		hint = "Идёт установка соединения."
		sidebarText = "Статус: подключение"
	}
	fyne.Do(func() {
		u.statusRect.FillColor = fill
		u.statusRect.Refresh()
		u.statusText.Text = text
		u.statusText.Refresh()
		u.statusHint.SetText(hint)
		u.sidebarStatus.SetText(sidebarText)
	})
	u.setConnectedControls(connected)
}

func (u *UI) syncFormToConfig() error {
	u.cfg.ServerURL = strings.TrimSpace(u.serverURL.Text)
	u.cfg.ServerName = strings.TrimSpace(u.serverName.Text)
	u.cfg.ClientsPath = strings.TrimSpace(u.clientsPath.Text)
	if u.cfg.ClientsPath == "" {
		u.cfg.ClientsPath = "/api/client/vpn-bind"
	}
	u.cfg.Username = strings.TrimSpace(u.username.Text)
	var poll int
	if _, err := fmt.Sscanf(strings.TrimSpace(u.pollSeconds.Text), "%d", &poll); err != nil || poll <= 0 {
		poll = 5
		fyne.Do(func() { u.pollSeconds.SetText("5") })
	}
	u.cfg.PollSeconds = poll
	if err := state.Save(u.cfg); err != nil {
		return err
	}
	u.renderSelfState()
	return nil
}

func (u *UI) markDisconnectedLocalReason(reason string, rawStatus string) {
	u.mu.Lock()
	now := time.Now().UTC().Format(time.RFC3339)
	if strings.TrimSpace(u.self.Username) == "" {
		u.self.Username = u.cfg.Username
	}
	if strings.TrimSpace(u.self.Source) == "" {
		u.self.Source = "mtls-vpn"
	}
	if strings.TrimSpace(u.self.IP) == "" {
		u.self.IP = "—"
	}
	if strings.TrimSpace(u.self.MAC) == "" {
		if mac := system.DetectPrimaryMAC(); mac != "" {
			u.self.MAC = mac
		} else {
			u.self.MAC = "—"
		}
	}
	u.self.Status = rawStatus
	u.self.LastSeen = now
	u.connected = false
	u.mu.Unlock()
	u.renderSelfState()
	u.updateConnectionUI(false, rawStatus)
	if strings.TrimSpace(reason) != "" {
		u.appendLog("Соединение разорвано: " + reason)
		u.setStatus("Соединение разорвано")
	}
}

func (u *UI) markDisconnectedLocal() {
	u.markDisconnectedLocalReason("соединение разорвано", "disconnected")
}

func (u *UI) renderSelfState() {
	u.mu.RLock()
	cfg := u.cfg
	self := u.self
	lastSuccess := u.lastSuccess
	u.mu.RUnlock()
	stateText := "выключено"
	switch strings.ToLower(strings.TrimSpace(self.Status)) {
	case "connected":
		stateText = "включено"
	case "disconnected":
		stateText = "выключено"
	case "error":
		stateText = "ошибка"
	case "":
		stateText = "выключено"
	default:
		stateText = self.Status
	}
	username := cfg.Username
	if strings.TrimSpace(self.Username) != "" {
		username = self.Username
	}
	if strings.TrimSpace(self.Profile) != "" {
		username = username + " [" + self.Profile + "]"
	}
	systemUser := empty(self.SystemUser)
	if systemUser == "—" {
		systemUser = empty(system.DetectSystemUser())
	}
	osType := empty(self.OSType)
	osVersion := empty(self.OSVersion)
	if osType == "—" || osVersion == "—" {
		detectedType, detectedVersion := system.DetectOSInfo()
		if osType == "—" {
			osType = empty(detectedType)
		}
		if osVersion == "—" {
			osVersion = empty(detectedVersion)
		}
	}
	server := cfg.ServerURL
	ip := empty(self.IP)
	mac := empty(self.MAC)
	if mac == "—" {
		if localMAC := system.DetectPrimaryMAC(); localMAC != "" {
			mac = localMAC
		}
	}
	connectedAt := formatTime(self.ConnectedAt)
	lastSeen := formatTime(self.LastSeen)
	source := empty(self.Source)
	lastUpdate := "—"
	if !lastSuccess.IsZero() {
		lastUpdate = formatTimeRFC3339Value(lastSuccess)
	}
	fyne.Do(func() {
		u.bundleStatus.SetText(u.bundleStatusText())
		u.statusValue.SetText(stateText)
		u.selfUsername.SetText(empty(username))
		u.selfSystemUser.SetText(systemUser)
		u.selfOSType.SetText(osType)
		u.selfOSVersion.SetText(osVersion)
		u.selfServer.SetText(empty(server))
		u.selfIP.SetText(ip)
		u.selfMAC.SetText(mac)
		u.selfConnectedAt.SetText(connectedAt)
		u.selfLastSeen.SetText(lastSeen)
		u.selfSource.SetText(source)
		u.selfLastUpdate.SetText(lastUpdate)
		if u.sidebarUptime != nil {
			u.sidebarUptime.SetText("Аптайм системы: " + system.DetectSystemUptime())
		}
	})
}

func (u *UI) refreshProcesses() {
	rows, err := system.ListProcesses()
	if err != nil {
		u.setStatus("Ошибка чтения процессов: " + err.Error())
		u.appendLog("Ошибка чтения процессов: " + err.Error())
		return
	}
	result := make([]ProcessRow, 0, len(rows))
	reportItems := make([]model.AppReportItem, 0, len(rows))
	for _, p := range rows {
		exe := p.Exe
		if strings.TrimSpace(exe) == "" {
			exe = "—"
		}
		uptime := system.FormatUptime(p.Uptime)
		name := empty(p.Name)
		category := empty(p.Category)
		result = append(result, ProcessRow{
			Name:     name,
			Category: category,
			PID:      formatPID(p.PID),
			Uptime:   uptime,
			Exe:      exe,
		})
		reportItems = append(reportItems, model.AppReportItem{
			Name:     name,
			Category: category,
			PID:      p.PID,
			Uptime:   uptime,
			Exe:      exe,
		})
	}
	u.mu.Lock()
	cfg := u.cfg
	connected := u.connected
	u.processRows = result
	u.mu.Unlock()

	u.refreshProcessCategoryOptions()
	u.applyProcessFilter()
	u.setStatus("Список приложений обновлён")

	if connected && strings.TrimSpace(cfg.AppsReportPath) != "" {
		report := model.AppsReport{
			Username:    strings.TrimSpace(cfg.Username),
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Apps:        reportItems,
		}
		if err := client.SendAppsReport(cfg, report); err != nil {
			u.appendLog("Не удалось передать список приложений: " + err.Error())
		} else {
			u.appendLog("Список приложений передан")
		}
	}
}
func (u *UI) refreshProcessCategoryOptions() {
	u.mu.RLock()
	seen := map[string]struct{}{}
	for _, p := range u.processRows {
		cat := strings.TrimSpace(p.Category)
		if cat != "" && cat != "—" {
			seen[cat] = struct{}{}
		}
	}
	u.mu.RUnlock()

	options := []string{"Все категории"}
	cats := make([]string, 0, len(seen))
	for cat := range seen {
		cats = append(cats, cat)
	}
	sort.Strings(cats)
	options = append(options, cats...)

	selected := "Все категории"
	if u.processCategory != nil && strings.TrimSpace(u.processCategory.Selected) != "" {
		selected = u.processCategory.Selected
	}
	keepSelected := false
	for _, opt := range options {
		if opt == selected {
			keepSelected = true
			break
		}
	}
	if !keepSelected {
		selected = "Все категории"
	}

	fyne.Do(func() {
		if u.processCategory != nil {
			u.processCategory.Options = options
			u.processCategory.Refresh()
			u.processCategory.SetSelected(selected)
		}
	})
}

func (u *UI) applyProcessFilter() {
	q := strings.ToLower(strings.TrimSpace(u.processSearch.Text))
	selectedCategory := "Все категории"
	if u.processCategory != nil && strings.TrimSpace(u.processCategory.Selected) != "" {
		selectedCategory = u.processCategory.Selected
	}

	u.mu.Lock()
	filtered := make([]ProcessRow, 0, len(u.processRows))
	for _, p := range u.processRows {
		if selectedCategory != "Все категории" && p.Category != selectedCategory {
			continue
		}
		if q != "" {
			hay := strings.ToLower(p.Name + " " + p.Category + " " + p.Exe + " " + p.PID)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		filtered = append(filtered, p)
	}
	u.filteredProcess = filtered
	count := len(u.filteredProcess)
	u.mu.Unlock()

	fyne.Do(func() {
		if u.processCount != nil {
			u.processCount.SetText("Приложений: " + formatPID(count))
		}
		if u.processTable != nil {
			u.processTable.Refresh()
		}
	})
}

func empty(v string) string {
	if strings.TrimSpace(v) == "" {
		return "—"
	}
	return v
}
func formatTime(v string) string {
	if strings.TrimSpace(v) == "" {
		return "—"
	}
	if strings.HasSuffix(v, "Z") {
		v = strings.TrimSuffix(v, "Z") + "+00:00"
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return v
	}
	return t.Local().Format("2006-01-02 15:04:05")
}
func formatTimeRFC3339Value(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}
func formatPID(v int) string { return fmt.Sprintf("%d", v) }
func formatPoll(v int) string {
	if v <= 0 {
		return "5"
	}
	return fmt.Sprintf("%d", v)
}
func isConnected(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), "connected")
}
func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }
