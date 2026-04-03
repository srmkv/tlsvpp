package app

import (
	"image/color"
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
	Name     string
	Category string
	PID      string
	Uptime   string
	Exe      string
}

type UI struct {
	app    fyne.App
	window fyne.Window

	mu               sync.RWMutex
	cfg              state.Config
	self             model.ClientSession
	lastSuccess      time.Time
	autoRefresh      bool
	stopCh           chan struct{}
	closing          bool
	hasTray          bool
	seenCmdIDs       map[string]time.Time
	connected        bool
	monitorFailures  int
	lastMonitorError string
	lastCommandError string

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

	pages     map[string]fyne.CanvasObject
	pageNames []string
}

func NewUI(app fyne.App, window fyne.Window, cfg state.Config) *UI {
	return &UI{app: app, window: window, cfg: cfg, stopCh: make(chan struct{}), pageNames: []string{"Стартовая", "Конфигурация", "Приложения", "Журнал"}, seenCmdIDs: make(map[string]time.Time)}
}

func (u *UI) Build() {
	u.initWidgets()
	u.setupMenus()
	u.setupTray()
	startPage := u.wrapPage(u.buildStartPage())
	configPage := u.wrapPage(u.buildConfigPage())
	appsPage := u.wrapPage(u.buildAppsPage())
	journalPage := u.wrapPage(u.buildJournalPage())
	u.pages = map[string]fyne.CanvasObject{"Стартовая": startPage, "Конфигурация": configPage, "Приложения": appsPage, "Журнал": journalPage}
	contentStack := container.NewMax(startPage, configPage, appsPage, journalPage)
	u.showPage("Стартовая")

	navList := widget.NewList(
		func() int { return len(u.pageNames) },
		func() fyne.CanvasObject { return widget.NewLabel("Template") },
		func(i widget.ListItemID, o fyne.CanvasObject) { o.(*widget.Label).SetText(u.pageNames[i]) },
	)
	navList.OnSelected = func(id widget.ListItemID) {
		if id >= 0 && id < len(u.pageNames) {
			u.showPage(u.pageNames[id])
		}
	}
	navList.Select(0)

	sidebarTop := container.NewVBox(widget.NewLabelWithStyle("TLS Client", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), widget.NewLabel("Linux"), widget.NewSeparator())
	sidebarBottom := container.NewVBox(widget.NewSeparator(), u.sidebarStatus, u.sidebarUptime)
	navWrap := container.NewGridWrap(fyne.NewSize(180, 280), navList)
	sidebarInner := container.NewBorder(sidebarTop, sidebarBottom, nil, nil, navWrap)
	sidebar := container.NewGridWrap(fyne.NewSize(sidebarW, windowH), widget.NewCard("", "", sidebarInner))

	headerRight := widget.NewLabel("mTLS клиент для VPP plugin")
	header := widget.NewCard("", "", container.NewBorder(nil, nil, u.headerSection, headerRight))
	mainAreaInner := container.NewBorder(header, widget.NewCard("", "", u.status), nil, nil, contentStack)
	mainArea := container.NewGridWrap(fyne.NewSize(mainW, mainH), mainAreaInner)
	u.window.SetContent(container.NewHBox(sidebar, mainArea))
	u.renderSelfState()
	u.updateConnectionUI(false, "")
	u.setConnectedControls(false)
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
	u.sidebarUptime = widget.NewLabel("Аптайм системы: " + system.DetectSystemUptime())
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
	u.connectButton = widget.NewButtonWithIcon("Подключить", theme.MediaPlayIcon(), u.toggleConnect)
	u.connectButton.Importance = widget.SuccessImportance
	u.autoButton = widget.NewButtonWithIcon("Автообновление", theme.ViewRefreshIcon(), u.toggleAutoRefresh)
}

func (u *UI) setupMenus() {
	mainMenu := fyne.NewMainMenu(
		fyne.NewMenu("Файл", fyne.NewMenuItem("Загрузить конфигурацию", func() { u.loadBundle() }), fyne.NewMenuItemSeparator(), fyne.NewMenuItem("Скрыть окно", func() { u.window.Hide() }), fyne.NewMenuItem("Выход", func() { u.quitApp() })),
		fyne.NewMenu("Подключение", fyne.NewMenuItem("Подключить / отключить", func() { u.toggleConnect() }), fyne.NewMenuItem("Автообновление", func() { u.toggleAutoRefresh() })),
		fyne.NewMenu("Разделы", fyne.NewMenuItem("Стартовая", func() { u.showPage("Стартовая") }), fyne.NewMenuItem("Конфигурация", func() { u.showPage("Конфигурация") }), fyne.NewMenuItem("Приложения", func() { u.showPage("Приложения") }), fyne.NewMenuItem("Журнал", func() { u.showPage("Журнал") })),
	)
	u.window.SetMainMenu(mainMenu)
}

func (u *UI) setupTray() {
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
	return container.NewGridWrap(fyne.NewSize(pageW, pageH), obj)
}

func (u *UI) showPage(name string) {
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
	note := widget.NewCard("Описание", "", widget.NewLabel("Адрес сервера — адрес TLS API.\nУчетная запись — имя клиента из конфигурации и сертификата.\nИмя сервера — имя сертификата сервера.\nПуть клиентов — endpoint списка клиентов.\nПуть команд и путь отчета приложений используются сервером для управления списком приложений."))
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
		func() (int, int) { u.mu.RLock(); defer u.mu.RUnlock(); return len(u.filteredProcess) + 1, 5 },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			label := obj.(*widget.Label)
			label.Wrapping = fyne.TextTruncate
			headers := []string{"Приложение", "Категория", "PID", "Время работы", "Путь"}
			if id.Row == 0 {
				label.TextStyle = fyne.TextStyle{Bold: true}
				if id.Col >= 0 && id.Col < len(headers) {
					label.SetText(headers[id.Col])
				} else {
					label.SetText("")
				}
				return
			}
			label.TextStyle = fyne.TextStyle{}
			u.mu.RLock()
			defer u.mu.RUnlock()
			if id.Row <= 0 || id.Row-1 >= len(u.filteredProcess) {
				label.SetText("")
				return
			}
			row := u.filteredProcess[id.Row-1]
			vals := []string{row.Name, row.Category, row.PID, row.Uptime, row.Exe}
			if id.Col >= 0 && id.Col < len(vals) {
				label.SetText(vals[id.Col])
			} else {
				label.SetText("")
			}
		},
	)
	u.processTable.SetColumnWidth(0, 150)
	u.processTable.SetColumnWidth(1, 130)
	u.processTable.SetColumnWidth(2, 60)
	u.processTable.SetColumnWidth(3, 110)
	u.processTable.SetColumnWidth(4, 210)

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
