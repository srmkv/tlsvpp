//go:build linux

package system

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func DetectInterfaceSnapshot(name string) InterfaceSnapshot {
	name = strings.TrimSpace(name)
	if name == "" {
		return InterfaceSnapshot{}
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return InterfaceSnapshot{Name: name}
	}
	addrs, _ := iface.Addrs()
	addrList := make([]string, 0, len(addrs))
	for _, a := range addrs {
		addrList = append(addrList, a.String())
	}
	flags := make([]string, 0, 6)
	if iface.Flags&net.FlagUp != 0 {
		flags = append(flags, "up")
	}
	if iface.Flags&net.FlagBroadcast != 0 {
		flags = append(flags, "broadcast")
	}
	if iface.Flags&net.FlagLoopback != 0 {
		flags = append(flags, "loopback")
	}
	if iface.Flags&net.FlagPointToPoint != 0 {
		flags = append(flags, "pointtopoint")
	}
	if iface.Flags&net.FlagMulticast != 0 {
		flags = append(flags, "multicast")
	}
	return InterfaceSnapshot{
		Name:      name,
		Exists:    true,
		Up:        iface.Flags&net.FlagUp != 0,
		MTU:       iface.MTU,
		MAC:       iface.HardwareAddr.String(),
		Flags:     flags,
		Addresses: addrList,
		RxBytes:   readUint(filepath.Join("/sys/class/net", name, "statistics/rx_bytes")),
		TxBytes:   readUint(filepath.Join("/sys/class/net", name, "statistics/tx_bytes")),
		RxPackets: readUint(filepath.Join("/sys/class/net", name, "statistics/rx_packets")),
		TxPackets: readUint(filepath.Join("/sys/class/net", name, "statistics/tx_packets")),
	}
}

func DetectRoutesByInterface(name string) []string {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	out, err := exec.Command("ip", "route", "show", "dev", name).Output()
	if err != nil {
		return nil
	}
	s := bufio.NewScanner(strings.NewReader(string(out)))
	lines := make([]string, 0, 8)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func readUint(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func FormatInterfaceSnapshot(s InterfaceSnapshot) string {
	state := "missing"
	if s.Exists {
		if s.Up {
			state = "up"
		} else {
			state = "down"
		}
	}
	return fmt.Sprintf("iface=%s state=%s mtu=%d rx=%d/%d tx=%d/%d", s.Name, state, s.MTU, s.RxPackets, s.RxBytes, s.TxPackets, s.TxBytes)
}
