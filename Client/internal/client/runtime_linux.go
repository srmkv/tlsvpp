//go:build linux

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

type runtimeApplyInput struct {
	AssignedIP    string
	Gateway       string
	DNSServers    string
	IncludeRoutes string
	ExcludeRoutes string
	FullTunnel    bool
	MTU           int
}

type runtimeApplier struct {
	ifName string
	mu     sync.RWMutex
	state  *runtimeState
}

type runtimeState struct {
	ifName string
	tun    *os.File
}

func newRuntimeApplier() *runtimeApplier { return &runtimeApplier{ifName: "tlsvpn0"} }

func (a *runtimeApplier) Apply(ctx context.Context, in runtimeApplyInput) (*runtimeState, error) {
	if strings.TrimSpace(in.AssignedIP) == "" {
		st := &runtimeState{ifName: a.ifName}
		a.mu.Lock()
		a.state = st
		a.mu.Unlock()
		return st, nil
	}
	_ = run(ctx, "ip", "link", "set", a.ifName, "down")
	_ = run(ctx, "ip", "link", "del", a.ifName)
	_ = run(ctx, "ip", "tuntap", "del", "dev", a.ifName, "mode", "tun")

	tun, err := createTun(a.ifName)
	if err != nil {
		return nil, err
	}
	if err := run(ctx, "ip", "addr", "flush", "dev", a.ifName); err != nil {
		_ = tun.Close()
		return nil, err
	}
	cidr := strings.TrimSpace(in.AssignedIP)
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}
	if err := run(ctx, "ip", "addr", "add", cidr, "dev", a.ifName); err != nil {
		_ = tun.Close()
		return nil, err
	}
	if in.MTU > 0 {
		_ = run(ctx, "ip", "link", "set", "dev", a.ifName, "mtu", strconv.Itoa(in.MTU))
	}
	if err := run(ctx, "ip", "link", "set", "dev", a.ifName, "up"); err != nil {
		_ = tun.Close()
		return nil, err
	}

	for _, rt := range splitCSV(in.IncludeRoutes) {
		_ = run(ctx, "ip", "route", "replace", rt, "dev", a.ifName)
	}
	if in.FullTunnel {
		_ = run(ctx, "ip", "route", "replace", "default", "dev", a.ifName)
	} else if strings.TrimSpace(in.Gateway) != "" {
		_ = run(ctx, "ip", "route", "replace", strings.TrimSpace(in.Gateway)+"/32", "dev", a.ifName)
	}

	dns := splitCSV(in.DNSServers)
	if len(dns) > 0 {
		args := append([]string{"dns", a.ifName}, dns...)
		_ = run(ctx, "resolvectl", args...)
		_ = run(ctx, "resolvectl", "domain", a.ifName, "~.")
	}

	st := &runtimeState{ifName: a.ifName, tun: tun}
	a.mu.Lock()
	a.state = st
	a.mu.Unlock()
	return st, nil
}

func (a *runtimeApplier) Revert(ctx context.Context) error {
	a.mu.Lock()
	st := a.state
	a.state = nil
	a.mu.Unlock()
	if st != nil && st.tun != nil {
		_ = st.tun.Close()
	}
	_ = run(ctx, "ip", "route", "del", "default", "dev", a.ifName)
	_ = run(ctx, "ip", "addr", "flush", "dev", a.ifName)
	_ = run(ctx, "ip", "link", "set", "dev", a.ifName, "down")
	_ = run(ctx, "ip", "link", "del", a.ifName)
	_ = run(ctx, "ip", "tuntap", "del", "dev", a.ifName, "mode", "tun")
	return nil
}

func (a *runtimeApplier) TunFile() *os.File {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.state == nil {
		return nil
	}
	return a.state.tun
}

const (
	ifnamsiz  = 16
	iffTun    = 0x0001
	iffNoPI   = 0x1000
	tunsetiff = 0x400454ca
)

type ifreq struct {
	Name  [ifnamsiz]byte
	Flags uint16
	_     [24 - ifnamsiz - 2]byte
}

func createTun(name string) (*os.File, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var req ifreq
	copy(req.Name[:], name)
	req.Flags = iffTun | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tunsetiff), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		_ = f.Close()
		if errors.Is(errno, syscall.EBUSY) {
			return nil, fmt.Errorf("create runtime tun %s: device busy", name)
		}
		return nil, fmt.Errorf("create runtime tun %s: %v", name, errno)
	}
	return f, nil
}

func detectPrimaryIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return ""
}

func splitCSV(s string) []string {
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if v != "" && v != "-" {
			out = append(out, v)
		}
	}
	return out
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.Error); ok {
			return fmt.Errorf("%s not available: %w", name, ee)
		}
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
