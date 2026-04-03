package model

type NetworkInterface struct {
	Name      string   `json:"name"`
	MTU       int      `json:"mtu"`
	MAC       string   `json:"mac"`
	Flags     []string `json:"flags"`
	Addresses []string `json:"addresses"`
}

type ClientSession struct {
	Username     string `json:"username"`
	Profile      string `json:"profile,omitempty"`
	SystemUser   string `json:"system_user"`
	OSType       string `json:"os_type"`
	OSVersion    string `json:"os_version"`
	SystemUptime string `json:"system_uptime"`
	IP           string `json:"ip"`
	MAC          string `json:"mac"`
	Status       string `json:"status"`
	ConnectedAt  string `json:"connected_at"`
	LastSeen     string `json:"last_seen"`
	Source       string `json:"source"`
	TunnelID     uint64 `json:"tunnel_id,omitempty"`
	Gateway      string `json:"gateway,omitempty"`
	DNSServers   string `json:"dns_servers,omitempty"`
	MTU          uint16 `json:"mtu,omitempty"`
	MSS          uint16 `json:"mss,omitempty"`
	LeaseSeconds uint32 `json:"lease_seconds,omitempty"`
	FullTunnel   bool   `json:"full_tunnel,omitempty"`
}

type ClientListResponse struct {
	Clients     []ClientSession `json:"clients"`
	GeneratedAt string          `json:"generated_at"`
}

type Command struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload,omitempty"`
}

type CommandsResponse struct {
	Commands []Command `json:"commands,omitempty"`
	Items    []Command `json:"items,omitempty"`
}

type AppReportItem struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	PID      int    `json:"pid"`
	Uptime   string `json:"uptime"`
	Exe      string `json:"exe"`
}

type AppsReport struct {
	Username    string          `json:"username"`
	CommandID   string          `json:"command_id,omitempty"`
	GeneratedAt string          `json:"generated_at"`
	Apps        []AppReportItem `json:"apps"`
}

type ClientHeartbeat struct {
	Username     string `json:"username"`
	CertSerial   string `json:"cert_serial,omitempty"`
	SystemUser   string `json:"system_user"`
	OSName       string `json:"os_name"`
	OSVersion    string `json:"os_version"`
	SystemUptime string `json:"system_uptime"`
	IP           string `json:"ip"`
	MAC          string `json:"mac"`
	Source       string             `json:"source"`
	Interfaces   []NetworkInterface `json:"interfaces,omitempty"`
	MTLSVerified bool               `json:"mtls_verified,omitempty"`
}
