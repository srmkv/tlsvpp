package vppclient

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/srmkv/tlsctrl-agent/internal/model"
)

type MemoryClient struct {
	mu           sync.RWMutex
	users        map[string]model.User
	sessions     map[string]model.Session
	commands     map[string]model.Command
	apps         map[string]model.AppsSnapshot
	adminBlocked map[string]bool
}

func NewMemoryClient() *MemoryClient {
	return &MemoryClient{
		users:        make(map[string]model.User),
		sessions:     make(map[string]model.Session),
		commands:     make(map[string]model.Command),
		apps:         make(map[string]model.AppsSnapshot),
		adminBlocked: make(map[string]bool),
	}
}

func (m *MemoryClient) UpsertUser(ctx context.Context, user model.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	old, ok := m.users[user.Username]
	if ok {
		user.CreatedAt = old.CreatedAt
		if user.Generation == 0 {
			user.Generation = old.Generation
		}
	} else {
		user.CreatedAt = now
		if user.Generation == 0 {
			user.Generation = 1
		}
	}
	user.UpdatedAt = now
	m.users[user.Username] = user
	return nil
}

func (m *MemoryClient) DeleteUser(ctx context.Context, username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.users, username)
	delete(m.sessions, username)
	delete(m.commands, username)
	delete(m.apps, username)
	delete(m.adminBlocked, username)
	return nil
}

func (m *MemoryClient) ReissueUser(ctx context.Context, username, certSerial string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	u, ok := m.users[username]
	if !ok {
		return errors.New("user not found")
	}
	u.CertSerial = certSerial
	u.Generation++
	u.UpdatedAt = time.Now().UTC()
	m.users[username] = u

	if s, ok := m.sessions[username]; ok {
		s.Connected = false
		s.LastSeen = time.Now().UTC()
		m.sessions[username] = s
	}
	delete(m.commands, username)
	return nil
}

func (m *MemoryClient) ListUsers(ctx context.Context) ([]model.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

func (m *MemoryClient) ListSessions(ctx context.Context) ([]model.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Connected != out[j].Connected {
			return out[i].Connected
		}
		return out[i].Username < out[j].Username
	})
	return out, nil
}

func (m *MemoryClient) ListVPNTunnels(ctx context.Context) ([]model.VPNTunnel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.VPNTunnel, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, model.VPNTunnel{
			TunnelID:   0,
			Username:   s.Username,
			Profile:    "",
			AssignedIP: s.IP,
			ClientIP:   s.IP,
			Running:    s.Connected,
			LastSeen:   s.LastSeen,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Running != out[j].Running {
			return out[i].Running
		}
		return out[i].Username < out[j].Username
	})
	return out, nil
}

func (m *MemoryClient) DisconnectSession(ctx context.Context, username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	m.adminBlocked[username] = true
	if s, ok := m.sessions[username]; ok {
		s.Connected = false
		s.LastSeen = now
		m.sessions[username] = s
	}
	m.commands[username] = model.Command{
		ID:        fmt.Sprintf("disconnect-%d", now.UnixNano()),
		Type:      "disconnect",
		CreatedAt: now,
		Payload:   map[string]any{"reason": "admin_disconnect"},
	}
	return nil
}

func (m *MemoryClient) ClientHeartbeat(ctx context.Context, hb model.ClientHeartbeat) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	u, ok := m.users[hb.Username]
	if !ok || !u.Enabled {
		return errors.New("unknown or disabled user")
	}
	if !hb.MTLSVerified {
		return errors.New("mtls not verified")
	}
	if hb.CertSerial == "" || hb.CertSerial != u.CertSerial {
		if s, ok := m.sessions[hb.Username]; ok {
			s.Connected = false
			s.LastSeen = time.Now().UTC()
			m.sessions[hb.Username] = s
		}
		return errors.New("certificate serial mismatch")
	}

	if m.adminBlocked[hb.Username] {
		if hb.ConnectIntent == "manual_connect" {
			delete(m.adminBlocked, hb.Username)
			if cmd, ok := m.commands[hb.Username]; ok && cmd.Type == "disconnect" {
				delete(m.commands, hb.Username)
			}
		} else {
			if s, ok := m.sessions[hb.Username]; ok {
				s.Connected = false
				s.LastSeen = time.Now().UTC()
				m.sessions[hb.Username] = s
			}
			return errors.New("disconnected by admin")
		}
	}

	now := time.Now().UTC()
	u.LastSeen = now
	m.users[hb.Username] = u

	s := m.sessions[hb.Username]
	if s.ConnectedAt.IsZero() || !s.Connected {
		s.ConnectedAt = now
	}
	s.Username = hb.Username
	s.CertSerial = hb.CertSerial
	s.SystemUser = hb.SystemUser
	s.OSName = hb.OSName
	s.OSVersion = hb.OSVersion
	s.SystemUptime = hb.SystemUptime
	s.IP = hb.IP
	s.MAC = hb.MAC
	s.Source = hb.Source
	s.Interfaces = append([]model.NetworkInterface(nil), hb.Interfaces...)
	s.Connected = true
	s.LastSeen = now
	if snap, ok := m.apps[hb.Username]; ok {
		s.AppsCount = len(snap.Apps)
		s.AppsUpdatedAt = snap.GeneratedAt
	}
	m.sessions[hb.Username] = s
	return nil
}

func (m *MemoryClient) SetClientApps(ctx context.Context, username string, commandID string, generatedAt time.Time, apps []model.AppInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	snap := model.AppsSnapshot{
		Username:    username,
		CommandID:   commandID,
		GeneratedAt: generatedAt,
		Apps:        append([]model.AppInfo(nil), apps...),
	}
	m.apps[username] = snap

	s := m.sessions[username]
	s.Username = username
	s.AppsCount = len(apps)
	s.AppsUpdatedAt = generatedAt
	m.sessions[username] = s

	if cmd, ok := m.commands[username]; ok {
		if commandID == "" || cmd.ID == "" || commandID == cmd.ID {
			delete(m.commands, username)
		}
	}
	return nil
}

func (m *MemoryClient) GetApps(ctx context.Context, username string) (model.AppsSnapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.apps[username], nil
}

func (m *MemoryClient) SetCommand(ctx context.Context, username string, cmd model.Command) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.commands[username] = cmd
	return nil
}

func (m *MemoryClient) GetCommand(ctx context.Context, username string) (model.Command, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.commands[username], nil
}

func (m *MemoryClient) ForceDisconnectAll(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for username, s := range m.sessions {
		s.Connected = false
		s.LastSeen = now
		m.sessions[username] = s
	}
	return nil
}

func (m *MemoryClient) SetListenerConfig(ctx context.Context, listenAddr string, listenPort int, serverCertPEM, serverKeyPEM, caCertPEM string) error {
	return nil
}

func (m *MemoryClient) SetVPNPool(ctx context.Context, name, subnet, gateway string, leaseSeconds int) error {
	return nil
}

func (m *MemoryClient) SetVPNProfile(ctx context.Context, name, pool string, fullTunnel bool, dnsServers, includeRoutes, excludeRoutes string, mtu, mssClamp int) error {
	return nil
}
