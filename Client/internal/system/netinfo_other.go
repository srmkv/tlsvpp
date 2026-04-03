//go:build !linux

package system

func DetectPrimaryMAC() string { return "" }
func DetectInterfaces() []map[string]any { return nil }
