//go:build !linux

package system

func DetectInterfaceSnapshot(name string) InterfaceSnapshot { return InterfaceSnapshot{Name: name} }
func DetectRoutesByInterface(name string) []string          { return nil }
func FormatInterfaceSnapshot(s InterfaceSnapshot) string    { return "" }
