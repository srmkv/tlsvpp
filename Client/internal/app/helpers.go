package app

import (
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

func (u *UI) setConnectedControls(connected bool, rawStatus string) {
	state := strings.ToLower(strings.TrimSpace(rawStatus))
	fyne.Do(func() {
		u.autoButton.Enable()
		switch state {
		case "pending":
			if connected {
				u.connectButton.SetText("Восстановление...")
			} else {
				u.connectButton.SetText("Подключение...")
			}
			u.connectButton.SetIcon(theme.ViewRefreshIcon())
			u.connectButton.Importance = widget.MediumImportance
			u.connectButton.Disable()
		case "disconnecting":
			u.connectButton.SetText("Отключение...")
			u.connectButton.SetIcon(theme.ViewRefreshIcon())
			u.connectButton.Importance = widget.MediumImportance
			u.connectButton.Disable()
		default:
			u.connectButton.Enable()
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
	case "disconnecting":
		fill = color.NRGBA{R: 249, G: 115, B: 22, A: 255}
		text = "ОТКЛ"
		hint = "Идёт корректное отключение."
		sidebarText = "Статус: отключение"
	}
	fyne.Do(func() {
		u.statusRect.FillColor = fill
		u.statusRect.Refresh()
		u.statusText.Text = text
		u.statusText.Refresh()
		u.statusHint.SetText(hint)
		u.sidebarStatus.SetText(sidebarText)
	})
	u.setConnectedControls(connected, rawStatus)
}

func (u *UI) syncFormToConfig() error {
	u.cfg.ServerURL = strings.TrimSpace(u.serverURL.Text)
	u.cfg.ServerName = strings.TrimSpace(u.serverName.Text)
	u.cfg.ClientsPath = strings.TrimSpace(u.clientsPath.Text)
	if u.cfg.ClientsPath == "" {
		u.cfg.ClientsPath = "/api/client/vpn-bind"
	}
	u.cfg.Username = strings.TrimSpace(u.username.Text)
	u.cfg.Profile = strings.TrimSpace(u.profile.Text)
	if u.cfg.Profile == "" {
		u.cfg.Profile = "default"
	}
	u.cfg.AppsReportPath = strings.TrimSpace(u.appsReportPath.Text)
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
	u.self.IP = ""
	u.self.TunnelID = 0
	u.self.Gateway = ""
	u.self.DNSServers = ""
	u.self.MTU = 0
	u.self.MSS = 0
	u.self.LeaseSeconds = 0
	u.self.FullTunnel = false
	u.self.ConnectedAt = ""
	u.connected = false
	u.reconnecting = false
	u.disconnecting = false
	if rawStatus != "disconnected" || reason != "ручное отключение" {
		u.manualDisconnectWanted = false
	}
	u.mu.Unlock()
	u.renderSelfState()
	u.clearVPNDetailsView()
	u.updateConnectionUI(false, rawStatus)
	if strings.TrimSpace(reason) != "" {
		u.appendLog("Соединение разорвано: " + reason)
		u.setStatus("Соединение разорвано")
	}
}

func (u *UI) markDisconnectedLocal() {
	u.markDisconnectedLocalReason("соединение разорвано", "disconnected")
}

func (u *UI) clearVPNDetailsView() {
	fyne.Do(func() {
		u.vpnIfaceName.SetText("tlsvpn0")
		u.vpnIfaceState.SetText("нет")
		u.vpnIfaceAddrs.SetText("—")
		u.vpnIfaceMAC.SetText("—")
		u.vpnIfaceMTU.SetText("—")
		u.vpnLastFrame.SetText("—")
		u.vpnLastError.SetText("—")
		u.vpnKernelStats.SetText("—")
		u.vpnRoutes.SetText("—")
		u.vpnDataplaneStats.SetText("—")
	})
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
	profile := strings.TrimSpace(self.Profile)
	if profile == "" {
		profile = strings.TrimSpace(cfg.Profile)
	}
	if profile != "" {
		username = username + " [" + profile + "]"
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
	tunnelID := "—"
	if self.TunnelID != 0 {
		tunnelID = fmt.Sprintf("%d", self.TunnelID)
	}
	gateway := empty(self.Gateway)
	dns := empty(self.DNSServers)
	mtu := "—"
	if self.MTU > 0 || self.MSS > 0 {
		mtu = fmt.Sprintf("%d / %d", self.MTU, self.MSS)
	}
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
		u.selfTunnelID.SetText(tunnelID)
		u.selfGateway.SetText(gateway)
		u.selfDNS.SetText(dns)
		u.selfMTU.SetText(mtu)
		u.selfConnectedAt.SetText(connectedAt)
		u.selfLastSeen.SetText(lastSeen)
		u.selfSource.SetText(source)
		u.selfLastUpdate.SetText(lastUpdate)
		if u.sidebarUptime != nil {
			u.sidebarUptime.SetText("Аптайм системы: " + system.DetectSystemUptime())
		}
	})
}

func (u *UI) refreshVPNDetails() {
	ifaceName := client.ActiveTunName()
	if strings.TrimSpace(ifaceName) == "" {
		ifaceName = "tlsvpn0"
	}
	snap := system.DetectInterfaceSnapshot(ifaceName)
	routes := system.DetectRoutesByInterface(ifaceName)
	dp := client.SnapshotDataplane()
	stateText := "нет"
	if snap.Exists {
		stateText = "есть"
		if snap.Up {
			stateText = "up"
		} else {
			stateText = "down"
		}
	}
	addrText := "—"
	if len(snap.Addresses) > 0 {
		addrText = strings.Join(snap.Addresses, "\n")
	}
	routesText := "—"
	if len(routes) > 0 {
		routesText = strings.Join(routes, "\n")
	}
	kernelText := "Интерфейс не найден"
	if snap.Exists {
		kernelText = strings.Join([]string{
			"RX bytes: " + formatUint64(snap.RxBytes),
			"TX bytes: " + formatUint64(snap.TxBytes),
			"RX packets: " + formatUint64(snap.RxPackets),
			"TX packets: " + formatUint64(snap.TxPackets),
		}, "\n")
	}
	dpLines := []string{
		"Старт: " + empty(formatTime(dp.StartedAt)),
		"TUN read: " + formatUint64(dp.TunReads) + " кадров / " + formatUint64(dp.TunReadBytes) + " байт",
		"Frame POST: " + formatUint64(dp.FramePosts) + " ok / errors " + formatUint64(dp.FramePostErrors),
		"Keepalive: " + formatUint64(dp.Keepalives) + " ok / errors " + formatUint64(dp.KeepaliveErrors),
		"Poll: " + formatUint64(dp.PollRequests) + " запросов / " + formatUint64(dp.PollFrames) + " кадров / errors " + formatUint64(dp.PollErrors),
		"TUN write: " + formatUint64(dp.TunWrites) + " кадров / " + formatUint64(dp.TunWriteBytes) + " байт",
	}
	lastFrame := formatTime(dp.LastFrameAt)
	lastErr := empty(strings.TrimSpace(dp.LastError))
	if strings.TrimSpace(dp.InterfaceName) != "" {
		ifaceName = dp.InterfaceName
	}
	dpEmpty := strings.TrimSpace(dp.StartedAt) == "" && strings.TrimSpace(dp.LastFrameAt) == "" && strings.TrimSpace(dp.LastError) == "" &&
		dp.TunReads == 0 && dp.TunReadBytes == 0 && dp.FramePosts == 0 && dp.FramePostErrors == 0 &&
		dp.Keepalives == 0 && dp.KeepaliveErrors == 0 && dp.PollRequests == 0 && dp.PollFrames == 0 && dp.PollErrors == 0 &&
		dp.TunWrites == 0 && dp.TunWriteBytes == 0
	if !snap.Exists && dpEmpty {
		kernelText = "—"
		routesText = "—"
		lastFrame = "—"
		lastErr = "—"
		dpLines = []string{"—"}
	}
	fyne.Do(func() {
		u.vpnIfaceName.SetText(ifaceName)
		u.vpnIfaceState.SetText(stateText)
		u.vpnIfaceAddrs.SetText(addrText)
		u.vpnIfaceMAC.SetText(empty(snap.MAC))
		if snap.MTU > 0 {
			u.vpnIfaceMTU.SetText(formatPID(snap.MTU))
		} else {
			u.vpnIfaceMTU.SetText("—")
		}
		u.vpnLastFrame.SetText(lastFrame)
		u.vpnLastError.SetText(lastErr)
		u.vpnKernelStats.SetText(kernelText)
		u.vpnRoutes.SetText(routesText)
		u.vpnDataplaneStats.SetText(strings.Join(dpLines, "\n"))
	})
}

func (u *UI) currentVPNDiagnosticText() string {
	parts := []string{
		"Интерфейс: " + strings.TrimSpace(u.vpnIfaceName.Text),
		"Состояние: " + strings.TrimSpace(u.vpnIfaceState.Text),
		"Адреса: " + strings.ReplaceAll(strings.TrimSpace(u.vpnIfaceAddrs.Text), "\n", "; "),
		"MAC: " + strings.TrimSpace(u.vpnIfaceMAC.Text),
		"MTU: " + strings.TrimSpace(u.vpnIfaceMTU.Text),
		"Последний кадр: " + strings.TrimSpace(u.vpnLastFrame.Text),
		"Последняя ошибка: " + strings.TrimSpace(u.vpnLastError.Text),
		"Dataplane:\n" + strings.TrimSpace(u.vpnDataplaneStats.Text),
		"Kernel:\n" + strings.TrimSpace(u.vpnKernelStats.Text),
		"Routes:\n" + strings.TrimSpace(u.vpnRoutes.Text),
	}
	return strings.Join(parts, "\n")
}

func (u *UI) refreshProcesses() {
	rows, err := system.ListProcesses()
	if err != nil {
		u.setStatus("Ошибка чтения процессов: " + err.Error())
		u.appendLog("Ошибка чтения процессов: " + err.Error())
		return
	}
	result := make([]ProcessRow, 0, len(rows))
	reportItems := make([]model.AppReportItem, 0, len(rows)+8)
	seenNames := map[string]struct{}{}
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
		if key := strings.ToLower(strings.TrimSpace(name)); key != "" {
			seenNames[key] = struct{}{}
		}
	}

	u.mu.Lock()
	cfg := u.cfg
	connected := u.connected
	u.mu.Unlock()

	markedRows, markErr := applyPolicyMarks(cfg, result)
	if markErr != nil {
		u.appendLog("Не удалось применить политики к списку приложений: " + markErr.Error())
		markedRows = result
	}

	u.mu.Lock()
	u.processRows = markedRows
	u.mu.Unlock()

	if connected {
		matchedApps, matchErr := client.CollectMatchedPolicyApps(cfg)
		if matchErr != nil {
			u.appendLog("Не удалось собрать приложения по политикам: " + matchErr.Error())
		} else if len(matchedApps) > 0 {
			added := 0
			for _, appName := range matchedApps {
				name := strings.TrimSpace(appName)
				if name == "" {
					continue
				}
				key := strings.ToLower(name)
				if _, ok := seenNames[key]; ok {
					continue
				}
				seenNames[key] = struct{}{}
				reportItems = append(reportItems, model.AppReportItem{
					Name:     name,
					Category: "Установлено",
					PID:      0,
					Uptime:   "—",
					Exe:      "—",
				})
				added++
			}
			if added > 0 {
				u.appendLog("Добавлены приложения по политикам: " + strconv.Itoa(added))
			}
		}
	}

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
			if strings.Contains(strings.ToLower(err.Error()), "запрещенное приложение") {
				go client.Disconnect(cfg)
				u.markDisconnectedLocalReason(err.Error(), "error")
			}
		} else {
			u.appendLog("Список приложений передан")
		}
	}
}

func (u *UI) sendAppsNow() {
	u.mu.RLock()
	cfg := u.cfg
	connected := u.connected
	rows := append([]ProcessRow(nil), u.processRows...)
	u.mu.RUnlock()
	if !connected {
		u.appendLog("Список приложений не отправлен: соединение не активно")
		return
	}
	reportItems := make([]model.AppReportItem, 0, len(rows)+8)
	seenNames := map[string]struct{}{}
	for _, p := range rows {
		reportItems = append(reportItems, model.AppReportItem{
			Name:     p.Name,
			Category: p.Category,
			PID:      parsePIDText(p.PID),
			Uptime:   p.Uptime,
			Exe:      p.Exe,
		})
		if key := strings.ToLower(strings.TrimSpace(p.Name)); key != "" {
			seenNames[key] = struct{}{}
		}
	}
	matchedApps, matchErr := client.CollectMatchedPolicyApps(cfg)
	if matchErr != nil {
		u.appendLog("Не удалось собрать приложения по политикам: " + matchErr.Error())
	} else if len(matchedApps) > 0 {
		for _, appName := range matchedApps {
			name := strings.TrimSpace(appName)
			if name == "" {
				continue
			}
			key := strings.ToLower(name)
			if _, ok := seenNames[key]; ok {
				continue
			}
			seenNames[key] = struct{}{}
			reportItems = append(reportItems, model.AppReportItem{
				Name:     name,
				Category: "Установлено",
				PID:      0,
				Uptime:   "—",
				Exe:      "—",
			})
		}
	}
	report := model.AppsReport{
		Username:    strings.TrimSpace(cfg.Username),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Apps:        reportItems,
	}
	if err := client.SendAppsReport(cfg, report); err != nil {
		u.appendLog("Не удалось передать список приложений: " + err.Error())
		if strings.Contains(strings.ToLower(err.Error()), "запрещенное приложение") {
			go client.Disconnect(cfg)
			u.markDisconnectedLocalReason(err.Error(), "error")
		}
		return
	}
	u.appendLog("Список приложений передан по запросу")
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
	blockedCount := 0
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
		if p.Blocked {
			blockedCount++
		}
	}
	u.filteredProcess = filtered
	count := len(u.filteredProcess)
	u.mu.Unlock()

	fyne.Do(func() {
		if u.processCount != nil {
			u.processCount.SetText("Приложений: " + formatPID(count) + " · Запрещено: " + formatPID(blockedCount))
		}
		if u.processTable != nil {
			u.processTable.Refresh()
		}
	})
}

func applyPolicyMarks(cfg state.Config, rows []ProcessRow) ([]ProcessRow, error) {
	candidates := make([]string, 0, len(rows)*3)
	seenCandidate := map[string]struct{}{}
	addCandidate := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || v == "—" {
			return
		}
		key := strings.ToLower(v)
		if _, ok := seenCandidate[key]; ok {
			return
		}
		seenCandidate[key] = struct{}{}
		candidates = append(candidates, v)
	}
	for _, row := range rows {
		addCandidate(row.Name)
		addCandidate(row.Exe)
		if base := strings.TrimSpace(filepath.Base(row.Exe)); base != "" && base != "." && base != "/" {
			addCandidate(base)
		}
	}
	matches, err := client.MatchPoliciesForApps(cfg, candidates)
	if err != nil {
		return rows, err
	}
	for i := range rows {
		row := &rows[i]
		for _, probe := range []string{row.Name, row.Exe, filepath.Base(row.Exe)} {
			key := strings.ToLower(strings.TrimSpace(probe))
			if key == "" || key == "—" {
				continue
			}
			if match, ok := matches[key]; ok {
				row.Blocked = true
				row.PolicyName = strings.TrimSpace(match.PolicyName)
				if row.PolicyName == "" {
					row.PolicyName = strings.TrimSpace(match.PolicyID)
				}
				row.Pattern = strings.TrimSpace(match.Pattern)
				break
			}
		}
	}
	appNames, invErr := system.ListPolicyAppNames()
	if invErr == nil {
		fullMatches, matchErr := client.MatchPoliciesForApps(cfg, appNames)
		if matchErr == nil {
			seenRow := map[string]struct{}{}
			for _, row := range rows {
				if key := strings.ToLower(strings.TrimSpace(row.Name)); key != "" {
					seenRow[key] = struct{}{}
				}
			}
			for key, match := range fullMatches {
				if _, ok := seenRow[key]; ok {
					continue
				}
				rows = append(rows, ProcessRow{Name: match.App, Category: "Установлено", PID: "—", Uptime: "—", Exe: "—", Blocked: true, PolicyName: strings.TrimSpace(match.PolicyName), Pattern: strings.TrimSpace(match.Pattern)})
			}
		}
	}
	return rows, nil
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
func formatPID(v int) string       { return fmt.Sprintf("%d", v) }
func formatUint64(v uint64) string { return fmt.Sprintf("%d", v) }

func parsePIDText(s string) int {
	s = strings.TrimSpace(s)
	if s == "" || s == "—" {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return 0
	}
	return v
}
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
