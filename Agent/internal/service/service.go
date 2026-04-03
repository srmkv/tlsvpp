package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/srmkv/tlsctrl-agent/internal/model"
	"github.com/srmkv/tlsctrl-agent/internal/pki"
	"github.com/srmkv/tlsctrl-agent/internal/vppclient"
)

type forceDisconnectAller interface {
	ForceDisconnectAll(ctx context.Context) error
}

type Service struct {
	backend    vppclient.Client
	pki        *pki.Manager
	vppSocket  string
	requireVPP bool
}

func New(backend vppclient.Client, pkiManager *pki.Manager, vppSocket string, requireVPP bool) *Service {
	return &Service{
		backend:    backend,
		pki:        pkiManager,
		vppSocket:  strings.TrimSpace(vppSocket),
		requireVPP: requireVPP,
	}
}

func shortSerial(serial string) string {
	serial = strings.TrimSpace(serial)
	if len(serial) <= 12 {
		return serial
	}
	return serial[:12] + "..."
}

func sinceMs(start time.Time) int64 { return time.Since(start).Milliseconds() }

func certSerialHex(cert *x509.Certificate) string {
	if cert == nil || cert.SerialNumber == nil {
		return ""
	}
	return strings.ToLower(cert.SerialNumber.Text(16))
}

func (s *Service) profilesPath() string {
	if s.pki == nil || strings.TrimSpace(s.pki.DataDir) == "" {
		return filepath.Join(".", "agent-data", "profiles.json")
	}
	return filepath.Join(s.pki.DataDir, "profiles.json")
}

func (s *Service) userMetaPath() string {
	if s.pki == nil || strings.TrimSpace(s.pki.DataDir) == "" {
		return filepath.Join(".", "agent-data", "users-meta.json")
	}
	return filepath.Join(s.pki.DataDir, "users-meta.json")
}

type userMeta struct {
	Profile string `json:"profile,omitempty"`
}

type persistedUser struct {
	Username   string    `json:"username"`
	CertSerial string    `json:"cert_serial"`
	Enabled    bool      `json:"enabled"`
	Profile    string    `json:"profile,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (s *Service) usersPath() string {
	if s.pki == nil || strings.TrimSpace(s.pki.DataDir) == "" {
		return filepath.Join(".", "agent-data", "users.json")
	}
	return filepath.Join(s.pki.DataDir, "users.json")
}

func (s *Service) loadPersistedUsers() (map[string]persistedUser, error) {
	path := s.usersPath()
	if err := ensureDir(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]persistedUser{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out map[string]persistedUser
	if len(raw) == 0 {
		return map[string]persistedUser{}, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]persistedUser{}
	}
	return out, nil
}

func (s *Service) savePersistedUsers(users map[string]persistedUser) error {
	path := s.usersPath()
	if err := ensureDir(path); err != nil {
		return err
	}
	b, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func (s *Service) persistUserRecord(username, certSerial string, enabled bool, profile string) error {
	users, err := s.loadPersistedUsers()
	if err != nil {
		return err
	}
	if strings.TrimSpace(profile) == "" {
		profile = "default"
	}
	users[username] = persistedUser{
		Username: username,
		CertSerial: certSerial,
		Enabled: enabled,
		Profile: profile,
		UpdatedAt: time.Now().UTC(),
	}
	return s.savePersistedUsers(users)
}

func (s *Service) deletePersistedUser(username string) error {
	users, err := s.loadPersistedUsers()
	if err != nil {
		return err
	}
	delete(users, username)
	return s.savePersistedUsers(users)
}

func (s *Service) SyncPersistedUsers(ctx context.Context) error {
	users, err := s.loadPersistedUsers()
	if err != nil {
		return err
	}
	for _, u := range users {
		profile := strings.TrimSpace(u.Profile)
		if profile == "" {
			profile = "default"
		}
		if !s.profileExists(profile) {
			continue
		}
		if err := s.backend.UpsertUser(ctx, model.User{
			Username: u.Username,
			CertSerial: u.CertSerial,
			Enabled: u.Enabled,
			Profile: profile,
		}); err != nil {
			return fmt.Errorf("sync persisted user %q: %w", u.Username, err)
		}
		if err := s.setUserProfile(u.Username, profile); err != nil {
			return err
		}
	}
	return nil
}

func ensureDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o700)
}

func (s *Service) loadProfiles() ([]model.VPNProfile, error) {
	path := s.profilesPath()
	if err := ensureDir(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		def := []model.VPNProfile{{
			Name:         "default",
			PoolName:     "corp",
			PoolSubnet:   "10.90.0.0/24",
			PoolGateway:  "10.90.0.1",
			LeaseSeconds: 3600,
			FullTunnel:   true,
			DNSServers:   "1.1.1.1,8.8.8.8",
			MTU:          1400,
			MSSClamp:     1360,
			UpdatedAt:    time.Now().UTC(),
		}}
		_ = s.saveProfiles(def)
		return def, nil
	}
	if err != nil {
		return nil, err
	}
	var out []model.VPNProfile
	if len(raw) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		out = []model.VPNProfile{{
			Name:         "default",
			PoolName:     "corp",
			PoolSubnet:   "10.90.0.0/24",
			PoolGateway:  "10.90.0.1",
			LeaseSeconds: 3600,
			FullTunnel:   true,
			DNSServers:   "1.1.1.1,8.8.8.8",
			MTU:          1400,
			MSSClamp:     1360,
			UpdatedAt:    time.Now().UTC(),
		}}
		_ = s.saveProfiles(out)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Service) saveProfiles(profiles []model.VPNProfile) error {
	path := s.profilesPath()
	if err := ensureDir(path); err != nil {
		return err
	}
	b, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func (s *Service) loadUserMeta() (map[string]userMeta, error) {
	path := s.userMetaPath()
	if err := ensureDir(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]userMeta{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out map[string]userMeta
	if len(raw) == 0 {
		return map[string]userMeta{}, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]userMeta{}
	}
	return out, nil
}

func (s *Service) saveUserMeta(meta map[string]userMeta) error {
	path := s.userMetaPath()
	if err := ensureDir(path); err != nil {
		return err
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func (s *Service) profileExists(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return true
	}
	profiles, err := s.loadProfiles()
	if err != nil {
		return false
	}
	for _, p := range profiles {
		if strings.EqualFold(strings.TrimSpace(p.Name), name) {
			return true
		}
	}
	return false
}

func (s *Service) userProfile(username string) string {
	meta, err := s.loadUserMeta()
	if err != nil {
		return "default"
	}
	if v, ok := meta[username]; ok && strings.TrimSpace(v.Profile) != "" {
		return v.Profile
	}
	return "default"
}

func (s *Service) setUserProfile(username, profile string) error {
	meta, err := s.loadUserMeta()
	if err != nil {
		return err
	}
	if strings.TrimSpace(profile) == "" {
		profile = "default"
	}
	meta[username] = userMeta{Profile: profile}
	return s.saveUserMeta(meta)
}

func (s *Service) deleteUserProfile(username string) error {
	meta, err := s.loadUserMeta()
	if err != nil {
		return err
	}
	delete(meta, username)
	return s.saveUserMeta(meta)
}

func (s *Service) EnsurePKI() error {
	start := time.Now()
	if s.pki == nil {
		err := errors.New("pki manager is not configured")
		log.Printf("service EnsurePKI error=%v", err)
		return err
	}
	err := s.pki.Ensure()
	if err != nil {
		log.Printf("service EnsurePKI failed ms=%d error=%v", sinceMs(start), err)
		return err
	}
	_, _ = s.loadProfiles()
	log.Printf("service EnsurePKI ok ms=%d", sinceMs(start))
	return nil
}

func (s *Service) ServerTLSConfig() (*tls.Config, error) {
	if s.pki == nil {
		return nil, errors.New("pki manager is not configured")
	}
	return s.pki.ServerTLSConfig()
}

func (s *Service) CurrentSettings() (pki.RuntimeSettings, error) {
	if s.pki == nil {
		return pki.RuntimeSettings{}, errors.New("pki manager is not configured")
	}
	return s.pki.CurrentSettings()
}

func (s *Service) UpdateSettings(ctx context.Context, clientPublicURL, serverName string, extraSANs []string, pluginListenAddr string, pluginListenPort int) (pki.RuntimeSettings, error) {
	start := time.Now()
	if s.pki == nil {
		err := errors.New("pki manager is not configured")
		log.Printf("service UpdateSettings error=%v", err)
		return pki.RuntimeSettings{}, err
	}
	log.Printf("service UpdateSettings start client-url=%q server-name=%q plugin=%s:%d extra-sans=%d", clientPublicURL, serverName, pluginListenAddr, pluginListenPort, len(extraSANs))
	st, err := s.pki.UpdateSettings(clientPublicURL, serverName, extraSANs, pluginListenAddr, pluginListenPort)
	if err != nil {
		log.Printf("service UpdateSettings pki-update failed ms=%d error=%v", sinceMs(start), err)
		return pki.RuntimeSettings{}, err
	}
	if err := s.SyncPluginRuntime(ctx); err != nil {
		log.Printf("service UpdateSettings sync-plugin failed ms=%d error=%v", sinceMs(start), err)
		return pki.RuntimeSettings{}, err
	}
	if err := s.SyncVPNProfiles(ctx); err != nil {
		log.Printf("service UpdateSettings sync-vpn-profiles failed ms=%d error=%v", sinceMs(start), err)
		return pki.RuntimeSettings{}, err
	}
	log.Printf("service UpdateSettings ok ms=%d", sinceMs(start))
	return st, nil
}

func (s *Service) SyncPluginRuntime(ctx context.Context) error {
	start := time.Now()
	if s.pki == nil || s.backend == nil {
		err := errors.New("plugin runtime sync is not configured")
		log.Printf("service SyncPluginRuntime error=%v", err)
		return err
	}
	mat, err := s.pki.PluginMaterial()
	if err != nil {
		log.Printf("service SyncPluginRuntime plugin-material failed ms=%d error=%v", sinceMs(start), err)
		return err
	}
	log.Printf("service SyncPluginRuntime start addr=%s port=%d cert-len=%d key-len=%d ca-len=%d", mat.ListenAddr, mat.ListenPort, len(mat.ServerCertPEM), len(mat.ServerKeyPEM), len(mat.CACertPEM))
	err = s.backend.SetListenerConfig(ctx, mat.ListenAddr, mat.ListenPort, mat.ServerCertPEM, mat.ServerKeyPEM, mat.CACertPEM)
	if err != nil {
		log.Printf("service SyncPluginRuntime failed ms=%d error=%v", sinceMs(start), err)
		return err
	}
	log.Printf("service SyncPluginRuntime ok ms=%d", sinceMs(start))
	return nil
}

func (s *Service) normalizeProfile(p model.VPNProfile) model.VPNProfile {
	if strings.TrimSpace(p.PoolName) == "" {
		if strings.EqualFold(strings.TrimSpace(p.Name), "default") {
			p.PoolName = "corp"
		} else {
			p.PoolName = p.Name
		}
	}
	if strings.TrimSpace(p.PoolSubnet) == "" {
		p.PoolSubnet = "10.90.0.0/24"
	}
	if strings.TrimSpace(p.PoolGateway) == "" {
		p.PoolGateway = "10.90.0.1"
	}
	if p.LeaseSeconds <= 0 {
		p.LeaseSeconds = 3600
	}
	if p.MTU <= 0 {
		p.MTU = 1400
	}
	if p.MSSClamp <= 0 {
		p.MSSClamp = 1360
	}
	return p
}

func (s *Service) SyncVPNProfiles(ctx context.Context) error {
	start := time.Now()
	profiles, err := s.loadProfiles()
	if err != nil {
		log.Printf("service SyncVPNProfiles load failed ms=%d error=%v", sinceMs(start), err)
		return err
	}
	for _, raw := range profiles {
		p := s.normalizeProfile(raw)
		if err := s.backend.SetVPNPool(ctx, p.PoolName, p.PoolSubnet, p.PoolGateway, p.LeaseSeconds); err != nil {
			log.Printf("service SyncVPNProfiles pool failed profile=%q ms=%d error=%v", p.Name, sinceMs(start), err)
			return err
		}
		if err := s.backend.SetVPNProfile(ctx, p.Name, p.PoolName, p.FullTunnel, p.DNSServers, p.IncludeRoutes, p.ExcludeRoutes, p.MTU, p.MSSClamp); err != nil {
			log.Printf("service SyncVPNProfiles profile failed profile=%q ms=%d error=%v", p.Name, sinceMs(start), err)
			return err
		}
	}
	log.Printf("service SyncVPNProfiles ok ms=%d count=%d", sinceMs(start), len(profiles))
	return nil
}

func (s *Service) vppAvailable() bool {
	if !s.requireVPP {
		return true
	}
	if strings.TrimSpace(s.vppSocket) == "" {
		return false
	}
	if _, err := os.Stat(s.vppSocket); err != nil {
		return false
	}
	conn, err := net.DialTimeout("unix", s.vppSocket, 700*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (s *Service) forceDisconnectAll(ctx context.Context) {
	if fd, ok := s.backend.(forceDisconnectAller); ok {
		_ = fd.ForceDisconnectAll(ctx)
	}
}

func (s *Service) ensureVPP(ctx context.Context) error {
	if s.vppAvailable() {
		return nil
	}
	s.forceDisconnectAll(ctx)
	return errors.New("vpp api unavailable")
}

func (s *Service) UpsertUser(ctx context.Context, username, certSerial string, enabled bool, profile string) error {
	start := time.Now()
	if username == "" {
		err := errors.New("username is required")
		log.Printf("service UpsertUser error=%v", err)
		return err
	}
	if strings.TrimSpace(profile) == "" {
		profile = "default"
	}
	if !s.profileExists(profile) {
		return fmt.Errorf("profile %q not found", profile)
	}
	log.Printf("service UpsertUser start username=%q enabled=%v profile=%q serial=%s", username, enabled, profile, shortSerial(certSerial))
	if err := s.backend.UpsertUser(ctx, model.User{
		Username:   username,
		CertSerial: certSerial,
		Enabled:    enabled,
		Profile:    profile,
	}); err != nil {
		log.Printf("service UpsertUser failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return fmt.Errorf("upsert user %q to vpp: %w", username, err)
	}
	if err := s.setUserProfile(username, profile); err != nil {
		return err
	}
	if err := s.persistUserRecord(username, certSerial, enabled, profile); err != nil {
		return err
	}
	log.Printf("service UpsertUser ok username=%q ms=%d", username, sinceMs(start))
	return nil
}

func (s *Service) IssueBundle(ctx context.Context, username string, enabled bool, profile string) ([]byte, string, error) {
	start := time.Now()
	if username == "" {
		err := errors.New("username is required")
		log.Printf("service IssueBundle error=%v", err)
		return nil, "", err
	}
	if strings.TrimSpace(profile) == "" {
		profile = s.userProfile(username)
	}
	if strings.TrimSpace(profile) == "" {
		profile = "default"
	}
	if !s.profileExists(profile) {
		return nil, "", fmt.Errorf("profile %q not found", profile)
	}
	log.Printf("service IssueBundle start username=%q enabled=%v profile=%q", username, enabled, profile)
	bundle, serial, err := s.pki.IssueBundle(username, profile)
	if err != nil {
		log.Printf("service IssueBundle pki failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return nil, "", err
	}
	if err := s.backend.UpsertUser(ctx, model.User{
		Username:   username,
		CertSerial: serial,
		Enabled:    enabled,
		Profile:    profile,
	}); err != nil {
		log.Printf("service IssueBundle sync-vpp failed username=%q serial=%s ms=%d error=%v", username, shortSerial(serial), sinceMs(start), err)
		return nil, "", fmt.Errorf("bundle issued but vpp user sync failed for %q: %w", username, err)
	}
	if err := s.setUserProfile(username, profile); err != nil {
		return nil, "", err
	}
	if err := s.persistUserRecord(username, serial, enabled, profile); err != nil {
		return nil, "", err
	}
	log.Printf("service IssueBundle ok username=%q serial=%s ms=%d", username, shortSerial(serial), sinceMs(start))
	return bundle, serial, nil
}

func (s *Service) ReissueBundle(ctx context.Context, username string, profile string) ([]byte, string, error) {
	start := time.Now()
	if username == "" {
		err := errors.New("username is required")
		log.Printf("service ReissueBundle error=%v", err)
		return nil, "", err
	}
	if strings.TrimSpace(profile) == "" {
		profile = s.userProfile(username)
	}
	if strings.TrimSpace(profile) == "" {
		profile = "default"
	}
	if !s.profileExists(profile) {
		return nil, "", fmt.Errorf("profile %q not found", profile)
	}
	log.Printf("service ReissueBundle start username=%q profile=%q", username, profile)
	enabled := true
	if persisted, err := s.loadPersistedUsers(); err == nil {
		if u, ok := persisted[username]; ok {
			enabled = u.Enabled
		}
	}
	bundle, serial, err := s.pki.IssueBundle(username, profile)
	if err != nil {
		log.Printf("service ReissueBundle pki failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return nil, "", err
	}
	if err := s.backend.ReissueUser(ctx, username, serial); err != nil {
		log.Printf("service ReissueBundle sync-vpp failed username=%q serial=%s ms=%d error=%v", username, shortSerial(serial), sinceMs(start), err)
		return nil, "", fmt.Errorf("bundle reissued but vpp sync failed for %q: %w", username, err)
	}
	if err := s.setUserProfile(username, profile); err != nil {
		return nil, "", err
	}
	if err := s.persistUserRecord(username, serial, enabled, profile); err != nil {
		return nil, "", err
	}
	log.Printf("service ReissueBundle ok username=%q serial=%s ms=%d", username, shortSerial(serial), sinceMs(start))
	return bundle, serial, nil
}

func (s *Service) ReissueUser(ctx context.Context, username, certSerial string) error {
	start := time.Now()
	if username == "" || certSerial == "" {
		err := errors.New("username and cert serial are required")
		log.Printf("service ReissueUser error=%v", err)
		return err
	}
	log.Printf("service ReissueUser start username=%q serial=%s", username, shortSerial(certSerial))
	err := s.backend.ReissueUser(ctx, username, certSerial)
	if err != nil {
		log.Printf("service ReissueUser failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return fmt.Errorf("reissue user %q in vpp: %w", username, err)
	}
	profile := s.userProfile(username)
	if err := s.persistUserRecord(username, certSerial, true, profile); err != nil {
		return err
	}
	log.Printf("service ReissueUser ok username=%q ms=%d", username, sinceMs(start))
	return nil
}

func (s *Service) DeleteUser(ctx context.Context, username string) error {
	start := time.Now()
	if username == "" {
		err := errors.New("username is required")
		log.Printf("service DeleteUser error=%v", err)
		return err
	}
	log.Printf("service DeleteUser start username=%q", username)
	err := s.backend.DeleteUser(ctx, username)
	if err != nil {
		log.Printf("service DeleteUser failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return fmt.Errorf("delete user %q from vpp: %w", username, err)
	}
	_ = s.deleteUserProfile(username)
	_ = s.deletePersistedUser(username)
	log.Printf("service DeleteUser ok username=%q ms=%d", username, sinceMs(start))
	return nil
}

func (s *Service) Users(ctx context.Context) ([]model.User, error) {
	start := time.Now()
	users, err := s.backend.ListUsers(ctx)
	if err != nil {
		log.Printf("service Users failed ms=%d error=%v", sinceMs(start), err)
		return nil, err
	}
	meta, _ := s.loadUserMeta()
	persisted, _ := s.loadPersistedUsers()
	seen := map[string]bool{}
	for i := range users {
		seen[users[i].Username] = true
		if pu, ok := persisted[users[i].Username]; ok {
			if strings.TrimSpace(users[i].CertSerial) == "" {
				users[i].CertSerial = pu.CertSerial
			}
			users[i].Enabled = pu.Enabled
		}
		if m, ok := meta[users[i].Username]; ok && strings.TrimSpace(m.Profile) != "" {
			users[i].Profile = m.Profile
		} else if pu, ok := persisted[users[i].Username]; ok && strings.TrimSpace(pu.Profile) != "" {
			users[i].Profile = pu.Profile
		} else if strings.TrimSpace(users[i].Profile) == "" {
			users[i].Profile = "default"
		}
	}
	for username, pu := range persisted {
		if seen[username] {
			continue
		}
		profile := strings.TrimSpace(pu.Profile)
		if profile == "" {
			profile = "default"
		}
		users = append(users, model.User{
			Username: username,
			CertSerial: pu.CertSerial,
			Enabled: pu.Enabled,
			Profile: profile,
			UpdatedAt: pu.UpdatedAt,
		})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	log.Printf("service Users ok ms=%d count=%d", sinceMs(start), len(users))
	return users, nil
}

func (s *Service) Sessions(ctx context.Context) ([]model.Session, error) {
	start := time.Now()
	if err := s.ensureVPP(ctx); err != nil {
		log.Printf("service Sessions ensureVPP warning ms=%d error=%v", sinceMs(start), err)
	}
	sessions, err := s.backend.ListSessions(ctx)
	if err != nil {
		log.Printf("service Sessions failed ms=%d error=%v", sinceMs(start), err)
		return nil, err
	}
	log.Printf("service Sessions ok ms=%d count=%d", sinceMs(start), len(sessions))
	return sessions, nil
}

func (s *Service) DisconnectSession(ctx context.Context, username string) error {
	start := time.Now()
	log.Printf("service DisconnectSession start username=%q", username)
	err := s.backend.DisconnectSession(ctx, username)
	if err != nil {
		log.Printf("service DisconnectSession failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return err
	}
	log.Printf("service DisconnectSession ok username=%q ms=%d", username, sinceMs(start))
	return nil
}

func (s *Service) RequestApps(ctx context.Context, username string) (model.Command, error) {
	if username == "" {
		return model.Command{}, errors.New("username is required")
	}
	cmd := model.Command{
		ID:        fmt.Sprintf("apps-%d", time.Now().UTC().UnixNano()),
		Type:      "apps_snapshot",
		CreatedAt: time.Now().UTC(),
		Payload: map[string]any{
			"reason": "manual_request",
		},
	}
	if err := s.backend.SetCommand(ctx, username, cmd); err != nil {
		return model.Command{}, err
	}
	return cmd, nil
}

func (s *Service) AppsView(ctx context.Context, username string) (model.AppsView, error) {
	view := model.AppsView{Username: username}
	cmd, err := s.backend.GetCommand(ctx, username)
	if err != nil {
		return view, err
	}
	if strings.TrimSpace(cmd.Type) != "" || strings.TrimSpace(cmd.ID) != "" {
		view.Pending = true
		view.Command = &cmd
	}
	report, err := s.backend.GetApps(ctx, username)
	if err != nil {
		return view, err
	}
	if strings.TrimSpace(report.Username) != "" || len(report.Apps) > 0 || !report.GeneratedAt.IsZero() {
		view.Report = &report
	}
	return view, nil
}

func (s *Service) ClientHeartbeat(ctx context.Context, cert *x509.Certificate, hb model.ClientHeartbeat) error {
	if cert == nil {
		return errors.New("mTLS peer cert is required")
	}
	if err := s.ensureVPP(ctx); err != nil {
		return err
	}
	hb.MTLSVerified = true
	hb.CertSerial = certSerialHex(cert)
	if hb.Source == "" {
		hb.Source = "mtls-agent"
	}
	return s.backend.ClientHeartbeat(ctx, hb)
}

func (s *Service) ClientApps(ctx context.Context, cert *x509.Certificate, username, commandID, generatedAtRaw string, apps []model.AppInfo) error {
	if cert == nil {
		return errors.New("mTLS peer cert is required")
	}
	if err := s.ensureVPP(ctx); err != nil {
		return err
	}
	generatedAt := time.Now().UTC()
	if strings.TrimSpace(generatedAtRaw) != "" {
		if parsed, err := time.Parse(time.RFC3339, generatedAtRaw); err == nil {
			generatedAt = parsed.UTC()
		}
	}
	return s.backend.SetClientApps(ctx, username, strings.TrimSpace(commandID), generatedAt, apps)
}

func (s *Service) ClientCommand(ctx context.Context, cert *x509.Certificate, username string) (model.Command, error) {
	if cert == nil {
		return model.Command{}, errors.New("mTLS peer cert is required")
	}
	if err := s.ensureVPP(ctx); err != nil {
		return model.Command{}, err
	}
	return s.backend.GetCommand(ctx, username)
}

func (s *Service) Profiles(ctx context.Context) ([]model.VPNProfile, error) {
	return s.loadProfiles()
}

func (s *Service) UpsertProfile(ctx context.Context, profile model.VPNProfile) error {
	if strings.TrimSpace(profile.Name) == "" {
		return errors.New("profile name is required")
	}
	profile = s.normalizeProfile(profile)
	profile.UpdatedAt = time.Now().UTC()
	profiles, err := s.loadProfiles()
	if err != nil {
		return err
	}
	found := false
	for i := range profiles {
		if strings.EqualFold(strings.TrimSpace(profiles[i].Name), strings.TrimSpace(profile.Name)) {
			profiles[i] = profile
			found = true
			break
		}
	}
	if !found {
		profiles = append(profiles, profile)
	}
	if err := s.saveProfiles(profiles); err != nil {
		return err
	}
	return s.SyncVPNProfiles(ctx)
}

func (s *Service) DeleteProfile(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("profile name is required")
	}
	if strings.EqualFold(name, "default") {
		return errors.New("default profile cannot be deleted")
	}
	profiles, err := s.loadProfiles()
	if err != nil {
		return err
	}
	out := make([]model.VPNProfile, 0, len(profiles))
	for _, p := range profiles {
		if !strings.EqualFold(strings.TrimSpace(p.Name), name) {
			out = append(out, p)
		}
	}
	if err := s.saveProfiles(out); err != nil {
		return err
	}
	/* no plugin delete API yet; remaining runtime profile entries are harmless until restart */
	return nil
}

func (s *Service) UserCertInfo(ctx context.Context, username string) (map[string]any, error) {
	if strings.TrimSpace(username) == "" {
		return nil, errors.New("username is required")
	}
	info, err := s.pki.GetClientCertInfo(strings.TrimSpace(username))
	if err != nil {
		return nil, err
	}
	users, err := s.backend.ListUsers(ctx)
	profile := s.userProfile(username)
	if err == nil {
		for _, u := range users {
			if strings.TrimSpace(u.Username) == strings.TrimSpace(username) {
				if strings.TrimSpace(u.Profile) != "" {
					profile = u.Profile
				}
				return map[string]any{
					"username": info.Username,
					"serial": func() string {
						if info.Serial != "" {
							return info.Serial
						}
						return u.CertSerial
					}(),
					"subject_cn":         info.SubjectCN,
					"issuer_cn":          info.IssuerCN,
					"not_before":         info.NotBefore,
					"not_after":          info.NotAfter,
					"key_algorithm":      info.KeyAlgorithm,
					"key_bits":           info.KeyBits,
					"ext_key_usage":      info.ExtKeyUsage,
					"bundle_server_url":  info.BundleServerURL,
					"bundle_server_name": info.BundleServerName,
					"available":          info.Available,
					"note":               info.Note,
					"enabled":            u.Enabled,
					"generation":         u.Generation,
					"profile":            profile,
				}, nil
			}
		}
	}
	return map[string]any{
		"username":           info.Username,
		"serial":             info.Serial,
		"subject_cn":         info.SubjectCN,
		"issuer_cn":          info.IssuerCN,
		"not_before":         info.NotBefore,
		"not_after":          info.NotAfter,
		"key_algorithm":      info.KeyAlgorithm,
		"key_bits":           info.KeyBits,
		"ext_key_usage":      info.ExtKeyUsage,
		"bundle_server_url":  info.BundleServerURL,
		"bundle_server_name": info.BundleServerName,
		"available":          info.Available,
		"note":               info.Note,
		"profile":            profile,
	}, nil
}

func (s *Service) Health(ctx context.Context) map[string]any {
	settings, _ := s.CurrentSettings()
	profiles, _ := s.loadProfiles()
	return map[string]any{
		"ok":                 true,
		"vpp_required":       s.requireVPP,
		"vpp_available":      s.vppAvailable(),
		"vpp_socket":         s.vppSocket,
		"server_name":        settings.ServerName,
		"client_public_url":  settings.ClientPublicURL,
		"extra_sans":         settings.ExtraSANs,
		"applied_sans":       settings.AppliedSANs,
		"plugin_listen_addr": settings.PluginListenAddr,
		"plugin_listen_port": settings.PluginListenPort,
		"profiles_count":     len(profiles),
	}
}
