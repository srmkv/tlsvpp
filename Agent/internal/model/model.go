package model

import (
	"encoding/json"
	"strings"
	"time"
)

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
	Username          string             `json:"username"`
	CertSerial        string             `json:"cert_serial"`
	SystemUser        string             `json:"system_user"`
	OSName            string             `json:"os_name"`
	OSVersion         string             `json:"os_version"`
	SystemUptime      string             `json:"system_uptime"`
	IP                string             `json:"ip"`
	MAC               string             `json:"mac"`
	Source            string             `json:"source"`
	Interfaces        []NetworkInterface `json:"interfaces,omitempty"`
	Connected         bool               `json:"connected"`
	ConnectedAt       time.Time          `json:"connected_at"`
	LastSeen          time.Time          `json:"last_seen"`
	AppsCount         int                `json:"apps_count"`
	AppsUpdatedAt     time.Time          `json:"apps_updated_at"`
	PolicyBlocked     bool               `json:"policy_blocked,omitempty"`
	PolicyBlockedAt   time.Time          `json:"policy_blocked_at,omitempty"`
	PolicyName        string             `json:"policy_name,omitempty"`
	PolicyMessage     string             `json:"policy_message,omitempty"`
	PolicyMatchedApps []string           `json:"policy_matched_apps,omitempty"`
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
	Username            string              `json:"username"`
	Pending             bool                `json:"pending"`
	Command             *Command            `json:"command,omitempty"`
	Report              *AppsSnapshot       `json:"report,omitempty"`
	LastPolicyViolation *AppPolicyViolation `json:"last_policy_violation,omitempty"`
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

type AppPolicyPattern struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
}

func (p *AppPolicyPattern) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err == nil {
		p.Type = "contains"
		p.Value = strings.TrimSpace(raw)
		return nil
	}
	type alias AppPolicyPattern
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	p.Type = strings.TrimSpace(a.Type)
	p.Value = strings.TrimSpace(a.Value)
	return nil
}

type AppPolicyScope struct {
	Profiles []string `json:"profiles,omitempty"`
	Users    []string `json:"users,omitempty"`
	AllUsers bool     `json:"all_users,omitempty"`
}

type AppPolicy struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Enabled       bool               `json:"enabled"`
	Mode          string             `json:"mode"`
	CheckOnClient bool               `json:"check_on_client,omitempty"`
	CheckOnServer bool               `json:"check_on_server,omitempty"`
	Patterns      []AppPolicyPattern `json:"patterns,omitempty"`
	Message       string             `json:"message,omitempty"`
	Scope         AppPolicyScope     `json:"scope,omitempty"`
	UpdatedAt     time.Time          `json:"updated_at"`
}

type AppPolicyResolved struct {
	PolicyVersion string      `json:"policy_version"`
	Username      string      `json:"username,omitempty"`
	Profile       string      `json:"profile,omitempty"`
	Policies      []AppPolicy `json:"policies"`
}

type AppPolicyViolation struct {
	Username    string    `json:"username"`
	Profile     string    `json:"profile,omitempty"`
	PolicyID    string    `json:"policy_id,omitempty"`
	PolicyName  string    `json:"policy_name,omitempty"`
	Message     string    `json:"message,omitempty"`
	MatchedApps []string  `json:"matched_apps,omitempty"`
	Action      string    `json:"action,omitempty"`
	Source      string    `json:"source,omitempty"`
	OccurredAt  time.Time `json:"occurred_at"`
}

type AppInventoryItem struct {
	Name     string `json:"name,omitempty"`
	Exe      string `json:"exe,omitempty"`
	Category string `json:"category,omitempty"`
}

type AppInventoryList []AppInventoryItem

func (l *AppInventoryList) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	items := make([]AppInventoryItem, 0, len(raw))
	for _, r := range raw {
		var s string
		if err := json.Unmarshal(r, &s); err == nil {
			s = strings.TrimSpace(s)
			if s != "" {
				items = append(items, AppInventoryItem{Name: s})
			}
			continue
		}
		var it AppInventoryItem
		if err := json.Unmarshal(r, &it); err != nil {
			return err
		}
		it.Name = strings.TrimSpace(it.Name)
		it.Exe = strings.TrimSpace(it.Exe)
		it.Category = strings.TrimSpace(it.Category)
		if it.Name != "" || it.Exe != "" || it.Category != "" {
			items = append(items, it)
		}
	}
	*l = AppInventoryList(items)
	return nil
}

type AppPolicyEvaluateRequest struct {
	Username string           `json:"username"`
	Profile  string           `json:"profile,omitempty"`
	Stage    string           `json:"stage,omitempty"`
	Apps     AppInventoryList `json:"apps,omitempty"`
}

type AppPolicyMatch struct {
	PolicyID   string `json:"policy_id,omitempty"`
	PolicyName string `json:"policy_name,omitempty"`
	Pattern    string `json:"pattern,omitempty"`
	App        string `json:"app,omitempty"`
}

type AppPolicyDecision struct {
	PolicyVersion string           `json:"policy_version,omitempty"`
	Username      string           `json:"username,omitempty"`
	Profile       string           `json:"profile,omitempty"`
	Allow         bool             `json:"allow"`
	Message       string           `json:"message,omitempty"`
	Matches       []AppPolicyMatch `json:"matches,omitempty"`
	Policies      []AppPolicy      `json:"policies,omitempty"`
}
