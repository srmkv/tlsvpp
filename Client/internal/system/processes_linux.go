//go:build linux

package system

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const linuxClockTicks = 100

type ProcessInfo struct {
	Name     string
	Category string
	PID      int
	Uptime   time.Duration
	Exe      string
}

func ListProcesses() ([]ProcessInfo, error) {
	bootTime, err := readBootTime()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}
	now := time.Now()
	out := make([]ProcessInfo, 0, 128)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		name, startTicks, err := readProcStat(pid)
		if err != nil {
			continue
		}
		exe, _ := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if exe != "" {
			if base := filepath.Base(exe); base != "" && base != "." && base != "/" {
				name = base
			}
		}
		startTime := bootTime.Add(time.Duration(startTicks) * time.Second / linuxClockTicks)
		uptime := now.Sub(startTime)
		if uptime < 0 {
			uptime = 0
		}
		out = append(out, ProcessInfo{Name: name, Category: classifyProcess(name, exe), PID: pid, Uptime: uptime, Exe: exe})
	}
	sort.Slice(out, func(i, j int) bool {
		li := strings.ToLower(out[i].Name)
		lj := strings.ToLower(out[j].Name)
		if li == lj {
			return out[i].PID < out[j].PID
		}
		return li < lj
	})
	return out, nil
}

func readBootTime() (time.Time, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}, fmt.Errorf("open /proc/stat: %w", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "btime ") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "btime "))
			sec, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return time.Time{}, fmt.Errorf("parse btime: %w", err)
			}
			return time.Unix(sec, 0), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return time.Time{}, fmt.Errorf("scan /proc/stat: %w", err)
	}
	return time.Time{}, fmt.Errorf("btime not found")
}

func readProcStat(pid int) (string, uint64, error) {
	path := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	text := string(data)
	openIdx := strings.Index(text, "(")
	closeIdx := strings.LastIndex(text, ")")
	if openIdx < 0 || closeIdx < 0 || closeIdx <= openIdx {
		return "", 0, fmt.Errorf("invalid stat format")
	}
	name := text[openIdx+1 : closeIdx]
	rest := strings.Fields(strings.TrimSpace(text[closeIdx+1:]))
	if len(rest) < 20 {
		return "", 0, fmt.Errorf("stat too short")
	}
	startTicks, err := strconv.ParseUint(rest[19], 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("parse start ticks: %w", err)
	}
	return name, startTicks, nil
}

func FormatUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	total := int(d.Seconds())
	days := total / 86400
	total %= 86400
	hours := total / 3600
	total %= 3600
	minutes := total / 60
	seconds := total % 60
	if days > 0 {
		return fmt.Sprintf("%dd %02d:%02d:%02d", days, hours, minutes, seconds)
	}
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

func classifyProcess(name, exe string) string {
	nameL := strings.ToLower(strings.TrimSpace(name))
	exeL := strings.ToLower(strings.TrimSpace(exe))
	hay := nameL + " " + exeL

	containsAny := func(items ...string) bool {
		for _, it := range items {
			if strings.Contains(hay, it) {
				return true
			}
		}
		return false
	}

	switch {
	case containsAny("firefox", "chrome", "chromium", "brave", "opera", "vivaldi", "yandex_browser", "browser"):
		return "Браузеры"
	case containsAny("telegram", "discord", "slack", "teams", "zoom", "skype", "signal", "whatsapp", "viber"):
		return "Связь"
	case containsAny("code", "codium", "idea", "pycharm", "goland", "webstorm", "android-studio", "sublime", "vim", "nvim", "emacs", "gitkraken"):
		return "Разработка"
	case containsAny("libreoffice", "writer", "calc", "impress", "evince", "okular", "wps"):
		return "Офис"
	case containsAny("vlc", "mpv", "obs", "spotify", "audacious", "rhythmbox", "kodi"):
		return "Мультимедиа"
	case containsAny("gnome-terminal", "konsole", "xterm", "kitty", "alacritty", "wezterm", "tilix", "bash", "zsh", "fish", "sh"):
		return "Терминалы"
	case containsAny("docker", "containerd", "podman", "qemu", "libvirtd", "virt-"):
		return "Контейнеры/VM"
	case strings.HasPrefix(exeL, "/usr/sbin/") || strings.HasPrefix(exeL, "/sbin/") || containsAny("systemd", "dbus", "networkmanager", "polkit", "udevd", "udisks", "bluetoothd", "cron", "rsyslog", "avahi", "pipewire", "pulseaudio"):
		return "Система"
	case strings.HasPrefix(exeL, "/usr/lib/") || strings.HasPrefix(exeL, "/lib/"):
		return "Службы"
	case strings.HasPrefix(exeL, "/home/") || strings.HasPrefix(exeL, "/opt/") || strings.HasPrefix(exeL, "/usr/bin/"):
		return "Пользовательские"
	default:
		return "Другое"
	}
}
