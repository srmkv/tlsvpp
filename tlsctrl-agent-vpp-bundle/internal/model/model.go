package model

import "time"

type User struct {
	Username   string    `json:"username"`
	CertSerial string    `json:"cert_serial"`
	Enabled    bool      `json:"enabled"`
	Generation uint64    `json:"generation"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastSeen   time.Time `json:"last_seen"`
}

type Session struct {
	Username     string    `json:"username"`
	CertSerial   string    `json:"cert_serial"`
	SystemUser   string    `json:"system_user"`
	OSName       string    `json:"os_name"`
	OSVersion    string    `json:"os_version"`
	SystemUptime string    `json:"system_uptime"`
	IP           string    `json:"ip"`
	MAC          string    `json:"mac"`
	Source       string    `json:"source"`
	Connected    bool      `json:"connected"`
	ConnectedAt  time.Time `json:"connected_at"`
	LastSeen     time.Time `json:"last_seen"`
	AppsCount    int       `json:"apps_count"`
}

type AppInfo struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	PID      int    `json:"pid"`
	Uptime   string `json:"uptime"`
	Exe      string `json:"exe"`
}

type Command struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

type ClientHeartbeat struct {
	Username     string `json:"username"`
	CertSerial   string `json:"cert_serial"`
	SystemUser   string `json:"system_user"`
	OSName       string `json:"os_name"`
	OSVersion    string `json:"os_version"`
	SystemUptime string `json:"system_uptime"`
	IP           string `json:"ip"`
	MAC          string `json:"mac"`
	Source       string `json:"source"`
	MTLSVerified bool   `json:"mtls_verified"`
}
