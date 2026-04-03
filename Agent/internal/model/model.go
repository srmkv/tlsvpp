package model

import "time"

type NetworkInterface struct {
	Name      string   `json:"name"`
	MTU       int      `json:"mtu"`
	MAC       string   `json:"mac"`
	Flags     []string `json:"flags"`
	Addresses []string `json:"addresses"`
}

type User struct {
	Username   string    `json:"username"`
	CertSerial string    `json:"cert_serial"`
	Enabled    bool      `json:"enabled"`
	Profile    string    `json:"profile,omitempty"`
	Generation uint64    `json:"generation"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastSeen   time.Time `json:"last_seen"`
}

type VPNProfile struct {
	Name          string    `json:"name"`
	PoolName      string    `json:"pool_name,omitempty"`
	PoolSubnet    string    `json:"pool_subnet,omitempty"`
	PoolGateway   string    `json:"pool_gateway,omitempty"`
	LeaseSeconds  int       `json:"lease_seconds,omitempty"`
	FullTunnel    bool      `json:"full_tunnel"`
	DNSServers    string    `json:"dns_servers,omitempty"`
	IncludeRoutes string    `json:"include_routes,omitempty"`
	ExcludeRoutes string    `json:"exclude_routes,omitempty"`
	MTU           int       `json:"mtu"`
	MSSClamp      int       `json:"mss_clamp"`
	Note          string    `json:"note,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Session struct {
	Username      string             `json:"username"`
	CertSerial    string             `json:"cert_serial"`
	SystemUser    string             `json:"system_user"`
	OSName        string             `json:"os_name"`
	OSVersion     string             `json:"os_version"`
	SystemUptime  string             `json:"system_uptime"`
	IP            string             `json:"ip"`
	MAC           string             `json:"mac"`
	Source        string             `json:"source"`
	Interfaces    []NetworkInterface `json:"interfaces,omitempty"`
	Connected     bool               `json:"connected"`
	ConnectedAt   time.Time          `json:"connected_at"`
	LastSeen      time.Time          `json:"last_seen"`
	AppsCount     int                `json:"apps_count"`
	AppsUpdatedAt time.Time          `json:"apps_updated_at"`
}

type AppInfo struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	PID      int    `json:"pid"`
	Uptime   string `json:"uptime"`
	Exe      string `json:"exe"`
}

type Command struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	CreatedAt time.Time      `json:"created_at"`
	Payload   map[string]any `json:"payload,omitempty"`
}

type AppsSnapshot struct {
	Username    string    `json:"username"`
	CommandID   string    `json:"command_id,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
	Apps        []AppInfo `json:"apps"`
}

type AppsView struct {
	Username string        `json:"username"`
	Pending  bool          `json:"pending"`
	Command  *Command      `json:"command,omitempty"`
	Report   *AppsSnapshot `json:"report,omitempty"`
}

type ClientHeartbeat struct {
	Username      string             `json:"username"`
	CertSerial    string             `json:"cert_serial"`
	SystemUser    string             `json:"system_user"`
	OSName        string             `json:"os_name"`
	OSVersion     string             `json:"os_version"`
	SystemUptime  string             `json:"system_uptime"`
	IP            string             `json:"ip"`
	MAC           string             `json:"mac"`
	Source        string             `json:"source"`
	Interfaces    []NetworkInterface `json:"interfaces,omitempty"`
	ConnectIntent string             `json:"connect_intent,omitempty"`
	MTLSVerified  bool               `json:"mtls_verified"`
}
