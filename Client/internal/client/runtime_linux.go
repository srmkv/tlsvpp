//go:build linux

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
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
	ifName   string
	tunCtl   *os.File
	tunRead  *os.File
	tunWrite *os.File
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

	_ = a.deleteInterface()

	tunCtl, tunRead, tunWrite, err := createTun(a.ifName)
	if err != nil {
		return nil, err
	}
	cleanup := func(err error) (*runtimeState, error) {
		_ = tunCtl.Close()
		_ = tunRead.Close()
		_ = tunWrite.Close()
		_ = a.deleteInterface()
		return nil, err
	}

	link, err := netlink.LinkByName(a.ifName)
	if err != nil {
		return cleanup(fmt.Errorf("link lookup %s: %w", a.ifName, err))
	}

	cidr := strings.TrimSpace(in.AssignedIP)
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return cleanup(fmt.Errorf("parse assigned ip %s: %w", cidr, err))
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return cleanup(fmt.Errorf("addr replace %s on %s: %w", cidr, a.ifName, err))
	}
	dataplaneLogf("RUNTIME apply: iface=%s addr=%s", a.ifName, cidr)

	if in.MTU > 0 {
		if err := netlink.LinkSetMTU(link, in.MTU); err != nil {
			return cleanup(fmt.Errorf("set mtu %d on %s: %w", in.MTU, a.ifName, err))
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return cleanup(fmt.Errorf("set link up %s: %w", a.ifName, err))
	}

	gw := strings.TrimSpace(in.Gateway)
	if !in.FullTunnel && gw != "" {
		if err := replaceRoute(link, gw+"/32", "", netlink.SCOPE_LINK); err != nil {
			return cleanup(fmt.Errorf("gateway host route %s on %s: %w", gw, a.ifName, err))
		}
		dataplaneLogf("RUNTIME gateway host route applied: %s dev %s", gw+"/32", a.ifName)
	}
	for _, rt := range splitCSV(in.IncludeRoutes) {
		if err := replaceRoute(link, rt, gw, netlink.SCOPE_UNIVERSE); err != nil {
			dataplaneLogf("RUNTIME route replace failed: %s via %s dev %s err=%v", rt, gw, a.ifName, err)
		} else {
			dataplaneLogf("RUNTIME route applied: %s via %s dev %s", rt, gw, a.ifName)
		}
	}
	if in.FullTunnel {
		if err := replaceDefaultRoute(link, gw); err != nil {
			dataplaneLogf("RUNTIME default route failed: %v", err)
		} else {
			dataplaneLogf("RUNTIME default route applied via %s", a.ifName)
		}
	}

	dns := splitCSV(in.DNSServers)
	if len(dns) > 0 {
		applyDNS(ctx, a.ifName, dns)
	}

	st := &runtimeState{ifName: a.ifName, tunCtl: tunCtl, tunRead: tunRead, tunWrite: tunWrite}
	dataplaneLogf("RUNTIME tun ready: iface=%s ctl_fd=%d read_fd=%d write_fd=%d", a.ifName, tunCtl.Fd(), tunRead.Fd(), tunWrite.Fd())
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
	if st != nil {
		if st.tunCtl != nil {
			_ = st.tunCtl.Close()
		}
		if st.tunRead != nil {
			_ = st.tunRead.Close()
		}
		if st.tunWrite != nil {
			_ = st.tunWrite.Close()
		}
	}
	return a.deleteInterface()
}

func (a *runtimeApplier) deleteInterface() error {
	link, err := netlink.LinkByName(a.ifName)
	if err != nil {
		var nlErr netlink.LinkNotFoundError
		if errors.As(err, &nlErr) {
			return nil
		}
		return nil
	}
	_ = netlink.LinkSetDown(link)
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete link %s: %w", a.ifName, err)
	}
	return nil
}

func replaceRoute(link netlink.Link, dstCIDR, gateway string, scope netlink.Scope) error {
	_, dst, err := net.ParseCIDR(strings.TrimSpace(dstCIDR))
	if err != nil {
		return fmt.Errorf("parse route %s: %w", dstCIDR, err)
	}
	route := netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Scope:     scope,
	}
	if gw := net.ParseIP(strings.TrimSpace(gateway)); gw != nil {
		route.Gw = gw
		route.Flags = int(netlink.FLAG_ONLINK)
	}
	return netlink.RouteReplace(&route)
}

func replaceDefaultRoute(link netlink.Link, gateway string) error {
	route := netlink.Route{LinkIndex: link.Attrs().Index}
	if gw := net.ParseIP(strings.TrimSpace(gateway)); gw != nil {
		route.Gw = gw
		route.Flags = int(netlink.FLAG_ONLINK)
	}
	return netlink.RouteReplace(&route)
}

func applyDNS(ctx context.Context, ifName string, dns []string) {
	args := append([]string{"dns", ifName}, dns...)
	if err := run(ctx, "resolvectl", args...); err != nil {
		dataplaneLogf("RUNTIME resolvectl dns failed: %v", err)
	}
	if err := run(ctx, "resolvectl", "domain", ifName, "~."); err != nil {
		dataplaneLogf("RUNTIME resolvectl domain failed: %v", err)
	}
}

func (a *runtimeApplier) TunFile() *os.File {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.state == nil {
		return nil
	}
	if a.state.tunRead != nil {
		return a.state.tunRead
	}
	return a.state.tunCtl
}

func (a *runtimeApplier) TunReadFile() *os.File {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.state == nil {
		return nil
	}
	return a.state.tunRead
}

func (a *runtimeApplier) TunWriteFile() *os.File {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.state == nil {
		return nil
	}
	return a.state.tunWrite
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

func createTun(name string) (*os.File, *os.File, *os.File, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var req ifreq
	copy(req.Name[:], name)
	req.Flags = iffTun | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(tunsetiff), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		_ = syscall.Close(fd)
		if errors.Is(errno, syscall.EBUSY) {
			return nil, nil, nil, fmt.Errorf("create runtime tun %s: device busy", name)
		}
		return nil, nil, nil, fmt.Errorf("create runtime tun %s: %v", name, errno)
	}
	dupR, err := syscall.Dup(fd)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, nil, nil, fmt.Errorf("dup tun read fd: %w", err)
	}
	dupW, err := syscall.Dup(fd)
	if err != nil {
		_ = syscall.Close(fd)
		_ = syscall.Close(dupR)
		return nil, nil, nil, fmt.Errorf("dup tun write fd: %w", err)
	}
	ctl := os.NewFile(uintptr(fd), "/dev/net/tun")
	readF := os.NewFile(uintptr(dupR), "/dev/net/tun-read")
	writeF := os.NewFile(uintptr(dupW), "/dev/net/tun-write")
	return ctl, readF, writeF, nil
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

func (a *runtimeApplier) InterfaceName() string {
	if a == nil {
		return "tlsvpn0"
	}
	if strings.TrimSpace(a.ifName) == "" {
		return "tlsvpn0"
	}
	return a.ifName
}
