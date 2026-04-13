package system

type InterfaceSnapshot struct {
	Name      string
	Exists    bool
	Up        bool
	MTU       int
	MAC       string
	Flags     []string
	Addresses []string
	RxBytes   uint64
	TxBytes   uint64
	RxPackets uint64
	TxPackets uint64
}
