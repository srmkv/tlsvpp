//go:build linux

package system

import "net"

func DetectPrimaryMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		return iface.HardwareAddr.String()
	}
	return ""
}

func DetectInterfaces() []map[string]any {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]map[string]any, 0, len(ifaces))
	for _, iface := range ifaces {
		flags := make([]string, 0, 6)
		if iface.Flags&net.FlagUp != 0 { flags = append(flags, "up") }
		if iface.Flags&net.FlagBroadcast != 0 { flags = append(flags, "broadcast") }
		if iface.Flags&net.FlagLoopback != 0 { flags = append(flags, "loopback") }
		if iface.Flags&net.FlagPointToPoint != 0 { flags = append(flags, "pointtopoint") }
		if iface.Flags&net.FlagMulticast != 0 { flags = append(flags, "multicast") }
		addrs, _ := iface.Addrs()
		addrList := make([]string, 0, len(addrs))
		for _, a := range addrs { addrList = append(addrList, a.String()) }
		out = append(out, map[string]any{
			"name": iface.Name,
			"mtu": iface.MTU,
			"mac": iface.HardwareAddr.String(),
			"flags": flags,
			"addresses": addrList,
		})
	}
	return out
}
