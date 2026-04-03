//go:build linux

package system

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func DetectSystemUser() string {
	if u, err := user.Current(); err == nil {
		if strings.TrimSpace(u.Username) != "" {
			return u.Username
		}
		if strings.TrimSpace(u.Name) != "" {
			return u.Name
		}
	}
	if v := strings.TrimSpace(os.Getenv("USER")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("LOGNAME")); v != "" {
		return v
	}
	return "—"
}

func DetectOSInfo() (string, string) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return runtime.GOOS, "—"
	}
	defer f.Close()

	vals := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		k := strings.TrimSpace(parts[0])
		v := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		vals[k] = v
	}

	osType := strings.TrimSpace(vals["NAME"])
	if osType == "" {
		osType = runtime.GOOS
	}
	osVersion := strings.TrimSpace(vals["VERSION"])
	if osVersion == "" {
		osVersion = strings.TrimSpace(vals["VERSION_ID"])
	}
	if osVersion == "" {
		osVersion = "—"
	}
	return osType, osVersion
}

func DetectSystemUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "—"
	}
	parts := strings.Fields(string(data))
	if len(parts) == 0 {
		return "—"
	}
	secsFloat, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return "—"
	}
	total := int(time.Duration(secsFloat * float64(time.Second)).Seconds())
	days := total / 86400
	total %= 86400
	hours := total / 3600
	total %= 3600
	minutes := total / 60
	if days > 0 {
		return fmt.Sprintf("%d д %02d ч %02d м", days, hours, minutes)
	}
	return fmt.Sprintf("%02d ч %02d м", hours, minutes)
}
