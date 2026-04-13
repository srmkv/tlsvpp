package app

import (
	"image/color"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"tlsclientnative/internal/model"
	"tlsclientnative/internal/state"
	"tlsclientnative/internal/system"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type ProcessRow struct {
	Name       string
	Category   string
	PID        string
	Uptime     string
	Exe        string
	Blocked    bool
	PolicyName string
	Pattern    string
}

type UI struct {
	app    fyne.App
	window fyne.Window

	mu                     sync.RWMutex
	cfg                    state.Config
	self                   model.ClientSession
	lastSuccess            time.Time
	autoRefresh            bool
	stopCh                 chan struct{}
	closing                bool
	hasTray                bool
	seenCmdIDs             map[string]time.Time
	connected              bool
	reconnecting           bool
	disconnecting          bool
	manualDisconnectWanted bool
	monitorFailures        int
	lastMonitorError       string
	lastCommandError       string
	adminMode              bool
	currentPage            string

	serverURL      *widget.Entry
	serverName     *widget.Entry
	clientsPath    *widget.Entry
	pollSeconds    *widget.Entry
	username       *widget.Entry
	profile        *widget.Entry
	appsReportPath *widget.Entry

	bundleStatus *widget.Label
	status       *widget.Label

	connectButton *widget.Button
	autoButton    *widget.Button

	statusRect  *canvas.Rectangle
	statusText  *canvas.Text
	statusHint  *widget.Label
	statusValue *widget.Label

	headerSection *widget.Label
	sidebarStatus *widget.Label
	sidebarUptime *widget.Label

	selfUsername    *widget.Label
	selfSystemUser  *widget.Label
	selfOSType      *widget.Label
	selfOSVersion   *widget.Label
	selfServer      *widget.Label
	selfIP          *widget.Label
	selfMAC         *widget.Label
	selfTunnelID    *widget.Label
	selfGateway     *widget.Label
	selfDNS         *widget.Label
	selfMTU         *widget.Label
	selfConnectedAt *widget.Label
	selfLastSeen    *widget.Label
	selfSource      *widget.Label
	selfLastUpdate  *widget.Label

	logFilter *widget.Entry
	logOutput *widget.Entry
	logLines  []string

	processSearch   *widget.Entry
	processCategory *widget.Select
	processCount    *widget.Label
	processTable    *widget.Table
	processRows     []ProcessRow
	filteredProcess []ProcessRow

	vpnIfaceName      *widget.Label
	vpnIfaceState     *widget.Label
	vpnIfaceAddrs     *widget.Label
	vpnIfaceMAC       *widget.Label
	vpnIfaceMTU       *widget.Label
	vpnLastFrame      *widget.Label
	vpnLastError      *widget.Label
	vpnKernelStats    *widget.Entry
	vpnRoutes         *widget.Entry
	vpnDataplaneStats *widget.Entry

	modeLabel     *widget.Label
	modeButton    *widget.Button
	navList       *widget.List
	adminSections []fyne.CanvasObject

	pages     map[string]fyne.CanvasObject
	pageNames []string
}

func NewUI(app fyne.App, window fyne.Window, cfg state.Config) *UI {
	return &UI{app: app, window: window, cfg: cfg, stopCh: make(chan struct{}), pageNames: []string{"Стартовая", "VPN", "Конфигурация", "Приложения", "Журнал"}, seenCmdIDs: make(map[string]time.Time)}
}

const adminModePassword = "s-terra"

func (u *UI) visiblePageNames() []string {
	if u == nil {
		return nil
	}
	u.mu.RLock()
	admin := u.adminMode
	u.mu.RUnlock()
	if admin {
		return append([]string(nil), u.pageNames...)
	}
	return []string{"Стартовая", "Конфигурация", "Журнал"}
}

func (u *UI) canAccessPage(name string) bool {
	for _, item := range u.visiblePageNames() {
		if item == name {
			return true
		}
	}
	return false
}

func (u *UI) setMode(admin bool) {
	u.mu.Lock()
	u.adminMode = admin
	current := u.currentPage
	u.mu.Unlock()
	if !u.canAccessPage(current) {
		current = "Стартовая"
	}
	if u.modeLabel != nil {
		if admin {
			fyne.Do(func() { u.modeLabel.SetText("Режим: администратор") })
		} else {
			fyne.Do(func() { u.modeLabel.SetText("Режим: пользователь") })
		}
	}
	if u.modeButton != nil {
		fyne.Do(func() {
			if admin {
				u.modeButton.SetText("Режим пользователя")
			} else {
				u.modeButton.SetText("Режим администратора")
			}
		})
	}
	for _, obj := range u.adminSections {
		if obj == nil {
			continue
		}
		if admin {
			obj.Show()
		} else {
			obj.Hide()
		}
	}
	if u.navList != nil {
		fyne.Do(func() {
			u.navList.Refresh()
			pages := u.visiblePageNames()
			idx := 0
			for i, page := range pages {
				if page == current {
					idx = i
					break
				}
			}
			u.navList.Select(idx)
		})
	}
	u.setupMenus()
	u.showPage(current)
}

func (u *UI) switchToUserMode() {
	u.mu.RLock()
	wasAdmin := u.adminMode
	u.mu.RUnlock()
	u.setMode(false)
	if wasAdmin {
		u.setStatus("Включён пользовательский режим")
		u.appendLog("Включён пользовательский режим")
	}
}

func (u *UI) promptAdminMode() {
	u.mu.RLock()
	admin := u.adminMode
	u.mu.RUnlock()
	if admin {
		u.switchToUserMode()
		return
	}
	pass := widget.NewPasswordEntry()
	pass.SetPlaceHolder("Введите пароль")
	info := widget.NewLabel("Для расширенного режима введите пароль администратора.")
	info.Wrapping = fyne.TextWrapWord
	content := container.NewVBox(info, pass)
	d := dialog.NewCustomConfirm("Режим администратора", "Включить", "Отмена", content, func(ok bool) {
		if !ok {
			return
		}
		if strings.TrimSpace(pass.Text) != adminModePassword {
			dialog.ShowInformation("Неверный пароль", "Пароль администратора указан неверно.", u.window)
			u.appendLog("Неудачная попытка входа в режим администратора")
			return
		}
		u.setMode(true)
		u.setStatus("Включён режим администратора")
		u.appendLog("Включён режим администратора")
	}, u.window)
	d.Show()
}

func (u *UI) Build() {
	u.initWidgets()
	u.setupTray()
	startPage := u.wrapPage(u.buildStartPage())
	vpnPage := u.wrapPage(u.buildVPNPage())
	configPage := u.wrapPage(u.buildConfigPage())
	appsPage := u.wrapPage(u.buildAppsPage())
	journalPage := u.wrapPage(u.buildJournalPage())
	u.pages = map[string]fyne.CanvasObject{"Стартовая": startPage, "VPN": vpnPage, "Конфигурация": configPage, "Приложения": appsPage, "Журнал": journalPage}
	contentStack := container.NewMax(startPage, vpnPage, configPage, appsPage, journalPage)

	u.navList = widget.NewList(
		func() int { return len(u.visiblePageNames()) },
		func() fyne.CanvasObject { return widget.NewLabel("Template") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			pages := u.visiblePageNames()
			if i >= 0 && i < len(pages) {
				o.(*widget.Label).SetText(pages[i])
			}
		},
	)
	u.navList.OnSelected = func(id widget.ListItemID) {
		pages := u.visiblePageNames()
		if id >= 0 && id < len(pages) {
			u.showPage(pages[id])
		}
	}
	u.navList.Select(0)

	sidebarTop := container.NewVBox(
		widget.NewLabelWithStyle("TLS Client", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		u.modeButton,
		widget.NewSeparator(),
	)
	sidebarBottom := container.NewVBox(widget.NewSeparator(), u.sidebarStatus, u.sidebarUptime)
	navWrap := container.NewVScroll(u.navList)
	navWrap.SetMinSize(fyne.NewSize(180, 280))
	sidebarInner := container.NewBorder(sidebarTop, sidebarBottom, nil, nil, navWrap)
	sidebar := widget.NewCard("", "", sidebarInner)

	headerRight := widget.NewLabel("mTLS клиент для VPP plugin")
	header := widget.NewCard("", "", container.NewBorder(nil, nil, u.headerSection, headerRight))
	mainAreaInner := container.NewBorder(header, widget.NewCard("", "", u.status), nil, nil, contentStack)
	split := container.NewHSplit(sidebar, mainAreaInner)
	split.Offset = 0.22
	u.window.SetContent(split)
	u.setMode(false)
	u.renderSelfState()
	u.refreshVPNDetails()
	u.updateConnectionUI(false, "")
	u.setConnectedControls(false, "")
	u.appendLog("Клиент запущен")
	go u.monitorLoop()
	u.window.SetCloseIntercept(func() {
		if u.hasTray {
			u.appendLog("Окно скрыто в системный трей")
			u.window.Hide()
			return
		}
		u.quitApp()
	})
}

func (u *UI) initWidgets() {
	u.serverURL = widget.NewEntry()
	u.serverURL.SetText(u.cfg.ServerURL)
	u.serverURL.SetPlaceHolder("https://127.0.0.1:9443")
	u.serverName = widget.NewEntry()
	u.serverName.SetText(u.cfg.ServerName)
	u.serverName.SetPlaceHolder("localhost")
	u.clientsPath = widget.NewEntry()
	u.clientsPath.SetText(u.cfg.ClientsPath)
	u.clientsPath.SetPlaceHolder("/api/client/vpn-bind")
	u.pollSeconds = widget.NewEntry()
	u.pollSeconds.SetText(formatPoll(u.cfg.PollSeconds))
	u.pollSeconds.SetPlaceHolder("5")
	u.username = widget.NewEntry()
	u.username.SetText(u.cfg.Username)
	u.username.SetPlaceHolder("ivanov")
	u.profile = widget.NewEntry()
	u.profile.SetText(u.cfg.Profile)
	u.profile.SetPlaceHolder("default")
	u.appsReportPath = widget.NewEntry()
	u.appsReportPath.SetText(u.cfg.AppsReportPath)
	u.appsReportPath.SetPlaceHolder("/api/client/apps")
	u.bundleStatus = widget.NewLabel(u.bundleStatusText())
	u.status = widget.NewLabel("Готово")
	u.statusRect = canvas.NewRectangle(color.NRGBA{R: 100, G: 116, B: 139, A: 255})
	u.statusRect.SetMinSize(fyne.NewSize(0, 48))
	u.statusText = canvas.NewText("ОТКЛ", color.White)
	u.statusText.Alignment = fyne.TextAlignCenter
	u.statusText.TextSize = 20
	u.statusText.TextStyle = fyne.TextStyle{Bold: true}
	u.statusHint = widget.NewLabel("Загрузите конфигурацию и нажмите «Подключить».")
	u.statusValue = widget.NewLabel("выключено")
	u.headerSection = widget.NewLabelWithStyle("Стартовая", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	u.sidebarStatus = widget.NewLabel("Статус: выключено")
	u.sidebarUptime = widget.NewLabel("Uptime: " + system.DetectSystemUptime())
	u.selfUsername = widget.NewLabel(empty(u.cfg.Username))
	osType, osVersion := system.DetectOSInfo()
	u.selfSystemUser = widget.NewLabel(empty(system.DetectSystemUser()))
	u.selfOSType = widget.NewLabel(empty(osType))
	u.selfOSVersion = widget.NewLabel(empty(osVersion))
	u.selfServer = widget.NewLabel(empty(u.cfg.ServerURL))
	u.selfIP = widget.NewLabel("—")
	u.selfMAC = widget.NewLabel(empty(system.DetectPrimaryMAC()))
	u.selfTunnelID = widget.NewLabel("—")
	u.selfGateway = widget.NewLabel("—")
	u.selfDNS = widget.NewLabel("—")
	u.selfMTU = widget.NewLabel("—")
	u.selfConnectedAt = widget.NewLabel("—")
	u.selfLastSeen = widget.NewLabel("—")
	u.selfSource = widget.NewLabel("tls")
	u.selfLastUpdate = widget.NewLabel("—")
	u.vpnIfaceName = widget.NewLabel("tlsvpn0")
	u.vpnIfaceState = widget.NewLabel("нет")
	u.vpnIfaceAddrs = widget.NewLabel("—")
	u.vpnIfaceMAC = widget.NewLabel("—")
	u.vpnIfaceMTU = widget.NewLabel("—")
	u.vpnLastFrame = widget.NewLabel("—")
	u.vpnLastError = widget.NewLabel("—")
	u.vpnKernelStats = widget.NewMultiLineEntry()
	u.vpnKernelStats.Disable()
	u.vpnKernelStats.Wrapping = fyne.TextWrapWord
	u.vpnRoutes = widget.NewMultiLineEntry()
	u.vpnRoutes.Disable()
	u.vpnRoutes.Wrapping = fyne.TextWrapWord
	u.vpnDataplaneStats = widget.NewMultiLineEntry()
	u.vpnDataplaneStats.Disable()
	u.vpnDataplaneStats.Wrapping = fyne.TextWrapWord
	for _, lbl := range []*widget.Label{
		u.statusHint,
		u.selfUsername,
		u.selfSystemUser,
		u.selfOSType,
		u.selfOSVersion,
		u.selfServer,
		u.selfIP,
		u.selfMAC,
		u.selfTunnelID,
		u.selfGateway,
		u.selfDNS,
		u.selfMTU,
		u.selfConnectedAt,
		u.selfLastSeen,
		u.selfSource,
		u.selfLastUpdate,
		u.sidebarUptime,
		u.vpnIfaceName,
		u.vpnIfaceState,
		u.vpnIfaceAddrs,
		u.vpnIfaceMAC,
		u.vpnIfaceMTU,
		u.vpnLastFrame,
		u.vpnLastError,
	} {
		if lbl != nil {
			lbl.Wrapping = fyne.TextWrapWord
		}
	}
	u.logFilter = widget.NewEntry()
	u.logFilter.SetPlaceHolder("Поиск по журналу")
	u.logFilter.OnChanged = func(string) { u.refreshLogView() }
	u.logOutput = widget.NewMultiLineEntry()
	u.logOutput.Disable()
	u.logOutput.Wrapping = fyne.TextWrapWord
	u.processSearch = widget.NewEntry()
	u.processSearch.SetPlaceHolder("Поиск по имени, категории или пути")
	u.processSearch.OnChanged = func(string) { u.applyProcessFilter() }

	u.processCategory = widget.NewSelect([]string{"Все категории"}, nil)
	u.processCategory.SetSelected("Все категории")
	u.processCategory.OnChanged = func(string) { u.applyProcessFilter() }

	u.processCount = widget.NewLabel("Приложений: 0")
	u.modeLabel = widget.NewLabel("Режим: пользователь")
	u.modeButton = widget.NewButton("Режим администратора", u.promptAdminMode)
	u.connectButton = widget.NewButtonWithIcon("Подключить", theme.MediaPlayIcon(), u.toggleConnect)
	u.connectButton.Importance = widget.SuccessImportance
	u.autoButton = widget.NewButtonWithIcon("Автообновление", theme.ViewRefreshIcon(), u.toggleAutoRefresh)
}

func (u *UI) setupMenus() {
	sectionItems := []*fyne.MenuItem{}
	for _, page := range u.visiblePageNames() {
		pageName := page
		sectionItems = append(sectionItems, fyne.NewMenuItem(pageName, func() { u.showPage(pageName) }))
	}
	mainMenu := fyne.NewMainMenu(
		fyne.NewMenu("Файл", fyne.NewMenuItem("Загрузить конфигурацию", func() { u.loadBundle() }), fyne.NewMenuItemSeparator(), fyne.NewMenuItem("Скрыть окно", func() { u.window.Hide() }), fyne.NewMenuItem("Выход", func() { u.quitApp() })),
		fyne.NewMenu("Подключение", fyne.NewMenuItem("Подключить / отключить", func() { u.toggleConnect() }), fyne.NewMenuItem("Автообновление", func() { u.toggleAutoRefresh() })),
		fyne.NewMenu("Режим", fyne.NewMenuItem("Пользовательский режим", func() { u.switchToUserMode() }), fyne.NewMenuItem("Режим администратора", func() { u.promptAdminMode() })),
		fyne.NewMenu("Разделы", sectionItems...),
	)
	u.window.SetMainMenu(mainMenu)
}

func (u *UI) setupTray() {
	if os.Getenv("TLSCLIENT_DISABLE_TRAY") == "1" || os.Geteuid() == 0 {
		u.appendLog("Tray отключён для root/явного запрета")
		return
	}
	if strings.TrimSpace(os.Getenv("DBUS_SESSION_BUS_ADDRESS")) == "" {
		if _, err := exec.LookPath("dbus-launch"); err != nil {
			u.appendLog("Tray отключён: нет DBUS_SESSION_BUS_ADDRESS и не найден dbus-launch")
			return
		}
	}
	desk, ok := u.app.(desktop.App)
	if !ok {
		return
	}
	u.hasTray = true
	desk.SetSystemTrayIcon(theme.InfoIcon())
	desk.SetSystemTrayMenu(fyne.NewMenu("TLS Client",
		fyne.NewMenuItem("Показать окно", func() { u.window.Show(); u.window.RequestFocus() }),
		fyne.NewMenuItem("Скрыть окно", func() { u.window.Hide() }),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Подключить / отключить", func() { u.toggleConnect() }),
		fyne.NewMenuItem("Автообновление", func() { u.toggleAutoRefresh() }),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Выход", func() { u.quitApp() }),
	))
}

func (u *UI) wrapPage(obj fyne.CanvasObject) fyne.CanvasObject {
	scroll := container.NewVScroll(obj)
	scroll.SetMinSize(fyne.NewSize(pageW, pageH))
	return container.NewPadded(scroll)
}

func (u *UI) showPage(name string) {
	if !u.canAccessPage(name) {
		name = "Стартовая"
	}
	u.mu.Lock()
	u.currentPage = name
	u.mu.Unlock()
	for pageName, obj := range u.pages {
		if pageName == name {
			obj.Show()
		} else {
			obj.Hide()
		}
	}
	u.headerSection.SetText(name)
	if name == "Приложения" {
		go u.refreshProcesses()
	}
	if name == "VPN" {
		go u.refreshVPNDetails()
	}
}

func (u *UI) buildStartPage() fyne.CanvasObject {
	loadBtn := widget.NewButtonWithIcon("Конфигурация", theme.FolderOpenIcon(), u.loadBundle)

	actions := widget.NewCard("Действия", "", container.NewVBox(
		loadBtn,
		u.connectButton,
		u.autoButton,
	))

	statusBlock := widget.NewCard("Состояние подключения", "", container.NewVBox(
		container.NewMax(u.statusRect, container.NewCenter(u.statusText)),
		u.statusHint,
	))

	identityForm := container.New(layout.NewFormLayout(),
		widget.NewLabel("Состояние"), u.statusValue,
		widget.NewLabel("Учетная запись"), u.selfUsername,
		widget.NewLabel("Пользователь системы"), u.selfSystemUser,
		widget.NewLabel("Сервер"), u.selfServer,
		widget.NewLabel("Источник"), u.selfSource,
		widget.NewLabel("Tunnel ID"), u.selfTunnelID,
	)

	systemForm := container.New(layout.NewFormLayout(),
		widget.NewLabel("Тип ОС"), u.selfOSType,
		widget.NewLabel("Версия ОС"), u.selfOSVersion,
		widget.NewLabel("IP"), u.selfIP,
		widget.NewLabel("MAC"), u.selfMAC,
		widget.NewLabel("Подключен с"), u.selfConnectedAt,
		widget.NewLabel("Последняя активность"), u.selfLastSeen,
		widget.NewLabel("Обновление"), u.selfLastUpdate,
	)

	vpnCard := widget.NewCard("VPN параметры", "", container.New(layout.NewFormLayout(),
		widget.NewLabel("Шлюз"), u.selfGateway,
		widget.NewLabel("DNS"), u.selfDNS,
		widget.NewLabel("MTU / MSS"), u.selfMTU,
	))

	identityCard := widget.NewCard("Идентификация", "", identityForm)
	systemCard := widget.NewCard("Система и сеть", "", systemForm)

	return container.NewVBox(
		container.NewGridWithColumns(2, statusBlock, actions),
		container.NewGridWithColumns(2, identityCard, systemCard),
		vpnCard,
	)
}

func (u *UI) buildVPNPage() fyne.CanvasObject {
	refreshBtn := widget.NewButtonWithIcon("Обновить диагностику", theme.ViewRefreshIcon(), func() { go u.refreshVPNDetails() })
	copyBtn := widget.NewButtonWithIcon("В журнал", theme.ContentCopyIcon(), func() {
		u.appendLog("VPN-диагностика:\n" + u.currentVPNDiagnosticText())
		u.setStatus("VPN-диагностика добавлена в журнал")
	})
	ifaceCard := widget.NewCard("Интерфейс tlsvpn0", "", container.New(layout.NewFormLayout(),
		widget.NewLabel("Имя"), u.vpnIfaceName,
		widget.NewLabel("Состояние"), u.vpnIfaceState,
		widget.NewLabel("Адреса"), u.vpnIfaceAddrs,
		widget.NewLabel("MAC"), u.vpnIfaceMAC,
		widget.NewLabel("MTU"), u.vpnIfaceMTU,
		widget.NewLabel("Последний кадр"), u.vpnLastFrame,
		widget.NewLabel("Последняя ошибка"), u.vpnLastError,
	))
	statsCard := widget.NewCard("Счётчики dataplane", "", container.NewGridWrap(fyne.NewSize(660, 120), u.vpnDataplaneStats))
	kernelCard := widget.NewCard("Счётчики ядра", "", container.NewGridWrap(fyne.NewSize(660, 95), u.vpnKernelStats))
	routesCard := widget.NewCard("Маршруты через VPN", "", container.NewGridWrap(fyne.NewSize(660, 120), u.vpnRoutes))
	toolbar := widget.NewCard("Действия", "", container.NewHBox(refreshBtn, copyBtn))
	return container.NewVBox(toolbar, ifaceCard, statsCard, kernelCard, routesCard)
}

func (u *UI) buildConfigPage() fyne.CanvasObject {
	mainForm := container.New(layout.NewFormLayout(), widget.NewLabel("Адрес сервера"), u.serverURL, widget.NewLabel("Учетная запись"), u.username, widget.NewLabel("Профиль"), u.profile, widget.NewLabel("Конфигурация"), u.bundleStatus)
	advancedForm := container.New(layout.NewFormLayout(), widget.NewLabel("Имя сервера"), u.serverName, widget.NewLabel("Путь bind"), u.clientsPath, widget.NewLabel("Путь команд"), widget.NewLabel(u.cfg.CommandsPath), widget.NewLabel("Путь отчета приложений"), u.appsReportPath, widget.NewLabel("Интервал опроса, сек"), u.pollSeconds)
	saveBtn := widget.NewButtonWithIcon("Сохранить", theme.DocumentSaveIcon(), func() {
		if err := u.syncFormToConfig(); err != nil {
			dialog.ShowError(err, u.window)
			u.appendLog("Ошибка сохранения конфига: " + err.Error())
			return
		}
		u.setStatus("Конфигурация сохранена")
		u.appendLog("Конфигурация сохранена")
	})
	loadBtn := widget.NewButtonWithIcon("Загрузить конфигурацию", theme.FolderOpenIcon(), u.loadBundle)
	left := widget.NewCard("Основное", "", mainForm)
	right := widget.NewCard("Дополнительно", "", advancedForm)
	actions := widget.NewCard("Действия", "", container.NewHBox(loadBtn, saveBtn))
	note := widget.NewCard("Описание", "", widget.NewLabel("Адрес сервера — адрес TLS API.\nУчетная запись — имя клиента из конфигурации и сертификата.\nИмя сервера — имя сертификата сервера.\nПуть clients — endpoint VPN bind.\nДополнительные сетевые пути доступны только в режиме администратора."))
	u.adminSections = append(u.adminSections, right)
	return container.NewVBox(container.NewGridWithColumns(2, left, right), actions, note)
}

func (u *UI) buildAppsPage() fyne.CanvasObject {
	refreshBtn := widget.NewButtonWithIcon("Обновить", theme.ViewRefreshIcon(), func() { go u.refreshProcesses() })
	sendBtn := widget.NewButtonWithIcon("Передать на сервер", theme.MailSendIcon(), func() { go u.sendAppsNow() })

	filters := container.NewGridWithColumns(2,
		u.processSearch,
		u.processCategory,
	)
	toolbar := container.NewBorder(
		nil,
		nil,
		container.NewHBox(widget.NewIcon(theme.SearchIcon()), u.processCount),
		container.NewHBox(refreshBtn, sendBtn),
		filters,
	)

	u.processTable = widget.NewTable(
		func() (int, int) { u.mu.RLock(); defer u.mu.RUnlock(); return len(u.filteredProcess) + 1, 6 },
		func() fyne.CanvasObject {
			bg := canvas.NewRectangle(color.Transparent)
			label := canvas.NewText("", color.NRGBA{R: 15, G: 23, B: 42, A: 255})
			label.TextSize = 13
			return container.NewMax(bg, label)
		},
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			cell := obj.(*fyne.Container)
			bg := cell.Objects[0].(*canvas.Rectangle)
			label := cell.Objects[1].(*canvas.Text)
			headers := []string{"Приложение", "Категория", "PID", "Время работы", "Путь", "Политика"}
			if id.Row == 0 {
				bg.FillColor = color.NRGBA{R: 241, G: 245, B: 249, A: 255}
				bg.Refresh()
				label.Color = color.NRGBA{R: 15, G: 23, B: 42, A: 255}
				label.TextStyle = fyne.TextStyle{Bold: true}
				if id.Col >= 0 && id.Col < len(headers) {
					label.Text = headers[id.Col]
				} else {
					label.Text = ""
				}
				label.Refresh()
				return
			}
			u.mu.RLock()
			defer u.mu.RUnlock()
			if id.Row <= 0 || id.Row-1 >= len(u.filteredProcess) {
				bg.FillColor = color.Transparent
				bg.Refresh()
				label.Text = ""
				label.Color = color.NRGBA{R: 15, G: 23, B: 42, A: 255}
				label.TextStyle = fyne.TextStyle{}
				label.Refresh()
				return
			}
			row := u.filteredProcess[id.Row-1]
			policyText := strings.TrimSpace(row.PolicyName)
			if strings.TrimSpace(row.Pattern) != "" {
				if policyText != "" {
					policyText += " · "
				}
				policyText += strings.TrimSpace(row.Pattern)
			}
			vals := []string{row.Name, row.Category, row.PID, row.Uptime, row.Exe, policyText}
			if id.Col >= 0 && id.Col < len(vals) {
				label.Text = vals[id.Col]
			} else {
				label.Text = ""
			}
			if row.Blocked {
				bg.FillColor = color.NRGBA{R: 254, G: 226, B: 226, A: 255}
				label.Color = color.NRGBA{R: 153, G: 27, B: 27, A: 255}
			} else {
				bg.FillColor = color.Transparent
				label.Color = color.NRGBA{R: 15, G: 23, B: 42, A: 255}
			}
			bg.Refresh()
			label.TextStyle = fyne.TextStyle{}
			label.Refresh()
		},
	)
	u.processTable.SetColumnWidth(0, 150)
	u.processTable.SetColumnWidth(1, 130)
	u.processTable.SetColumnWidth(2, 60)
	u.processTable.SetColumnWidth(3, 110)
	u.processTable.SetColumnWidth(4, 210)
	u.processTable.SetColumnWidth(5, 180)

	hint := widget.NewLabel("Категории определяются эвристически по имени процесса и пути. Это не системная классификация Linux и она может ошибаться.")
	return container.NewVBox(
		toolbar,
		hint,
		widget.NewCard("Запущенные приложения / процессы", "", container.NewGridWrap(fyne.NewSize(660, 360), u.processTable)),
	)
}

func (u *UI) buildJournalPage() fyne.CanvasObject {
	clearBtn := widget.NewButtonWithIcon("Очистить", theme.DeleteIcon(), func() {
		u.mu.Lock()
		u.logLines = nil
		u.mu.Unlock()
		u.refreshLogView()
		u.setStatus("Журнал очищен")
	})
	toolbar := container.NewBorder(nil, nil, widget.NewIcon(theme.SearchIcon()), clearBtn, u.logFilter)
	logCard := widget.NewCard("Журнал событий", "", u.logOutput)
	return container.NewVBox(toolbar, container.NewGridWrap(fyne.NewSize(660, 390), logCard))
}
