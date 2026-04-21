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

	"tlsctrl-agent/internal/model"
	"tlsctrl-agent/internal/pki"
	"tlsctrl-agent/internal/userstore"
	"tlsctrl-agent/internal/vppclient"
)

type forceDisconnectAller interface {
	ForceDisconnectAll(ctx context.Context) error
}

type Service struct {
	backend    vppclient.Client
	pki        *pki.Manager
	store      userstore.Store
	vppSocket  string
	requireVPP bool
}

func New(backend vppclient.Client, pkiManager *pki.Manager, st userstore.Store, vppSocket string, requireVPP bool) *Service {
	return &Service{backend: backend, pki: pkiManager, store: st,
		vppSocket: strings.TrimSpace(vppSocket), requireVPP: requireVPP}
}

func sinceMs(start time.Time) int64 { return time.Since(start).Milliseconds() }

func certSerialHex(cert *x509.Certificate) string {
	if cert == nil || cert.SerialNumber == nil {
		return ""
	}
	return strings.ToLower(cert.SerialNumber.Text(16))
}

func shortSerial(serial string) string {
	serial = strings.TrimSpace(serial)
	if len(serial) <= 12 {
		return serial
	}
	return serial[:12] + "..."
}

func ensureDir(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return os.MkdirAll(filepath.Dir(path), 0o755)
}

func (s *Service) profileExists(ctx context.Context, name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return true
	}
	_, err := s.store.GetProfile(ctx, name)
	return err == nil
}

func (s *Service) userProfile(ctx context.Context, username string) string {
	u, err := s.store.GetUser(ctx, strings.ToLower(strings.TrimSpace(username)))
	if err != nil || strings.TrimSpace(u.Profile) == "" {
		return "default"
	}
	return u.Profile
}

func (s *Service) ensureDefaultProfile(ctx context.Context) {
	profiles, err := s.store.ListProfiles(ctx)
	if err != nil || len(profiles) > 0 {
		return
	}
	_ = s.store.UpsertProfile(ctx, model.VPNProfile{
		Name: "default", PoolName: "corp", PoolSubnet: "10.90.0.0/24",
		PoolGateway: "10.90.0.1", LeaseSeconds: 3600, FullTunnel: true,
		DNSServers: "1.1.1.1,8.8.8.8", MTU: 1400, MSSClamp: 1360, UpdatedAt: time.Now().UTC(),
	})
}

func (s *Service) SyncPersistedUsers(ctx context.Context) error {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, u := range users {
		profile := strings.TrimSpace(u.Profile)
		if profile == "" {
			profile = "default"
		}
		if !s.profileExists(ctx, profile) {
			continue
		}
		if err := s.backend.UpsertUser(ctx, model.User{
			Username: u.Username, CertSerial: u.CertSerial, Enabled: u.Enabled, Profile: profile,
		}); err != nil {
			return fmt.Errorf("sync persisted user %q: %w", u.Username, err)
		}
	}
	return nil
}

func (s *Service) EnsurePKI() error {
	start := time.Now()
	if s.pki == nil {
		return errors.New("pki manager is not configured")
	}
	if err := s.pki.Ensure(); err != nil {
		log.Printf("service EnsurePKI failed ms=%d error=%v", sinceMs(start), err)
		return err
	}
	s.ensureDefaultProfile(context.Background())
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
		return pki.RuntimeSettings{}, errors.New("pki manager is not configured")
	}
	log.Printf("service UpdateSettings start client-url=%q server-name=%q plugin=%s:%d extra-sans=%d",
		clientPublicURL, serverName, pluginListenAddr, pluginListenPort, len(extraSANs))
	st, err := s.pki.UpdateSettings(clientPublicURL, serverName, extraSANs, pluginListenAddr, pluginListenPort)
	if err != nil {
		return pki.RuntimeSettings{}, err
	}
	if err := s.SyncPluginRuntime(ctx); err != nil {
		log.Printf("service UpdateSettings sync-plugin failed ms=%d error=%v", sinceMs(start), err)
		return pki.RuntimeSettings{}, err
	}
	if err := s.SyncVPNProfiles(ctx); err != nil {
		log.Printf("service UpdateSettings sync-vpn failed ms=%d error=%v", sinceMs(start), err)
		return pki.RuntimeSettings{}, err
	}
	log.Printf("service UpdateSettings ok ms=%d", sinceMs(start))
	return st, nil
}

func (s *Service) SyncPluginRuntime(ctx context.Context) error {
	start := time.Now()
	if s.pki == nil || s.backend == nil {
		return errors.New("plugin runtime sync is not configured")
	}
	mat, err := s.pki.PluginMaterial()
	if err != nil {
		return err
	}
	log.Printf("service SyncPluginRuntime start addr=%s port=%d", mat.ListenAddr, mat.ListenPort)
	if err := s.backend.SetListenerConfig(ctx, mat.ListenAddr, mat.ListenPort, mat.ServerCertPEM, mat.ServerKeyPEM, mat.CACertPEM); err != nil {
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
	profiles, err := s.store.ListProfiles(ctx)
	if err != nil {
		return err
	}
	for _, raw := range profiles {
		p := s.normalizeProfile(raw)
		if err := s.backend.SetVPNPool(ctx, p.PoolName, p.PoolSubnet, p.PoolGateway, p.LeaseSeconds); err != nil {
			return err
		}
		if err := s.backend.SetVPNProfile(ctx, p.Name, p.PoolName, p.FullTunnel,
			p.DNSServers, p.IncludeRoutes, p.ExcludeRoutes, p.MTU, p.MSSClamp); err != nil {
			return err
		}
	}
	log.Printf("service SyncVPNProfiles ok ms=%d count=%d", sinceMs(start), len(profiles))
	return nil
}

func (s *Service) Profiles(ctx context.Context) ([]model.VPNProfile, error) {
	return s.store.ListProfiles(ctx)
}

func (s *Service) UpsertProfile(ctx context.Context, profile model.VPNProfile) error {
	if strings.TrimSpace(profile.Name) == "" {
		return errors.New("profile name is required")
	}
	profile = s.normalizeProfile(profile)
	profile.UpdatedAt = time.Now().UTC()
	if err := s.store.UpsertProfile(ctx, profile); err != nil {
		return err
	}
	if err := s.SyncVPNProfiles(ctx); err != nil {
		log.Printf("service UpsertProfile sync warning name=%q error=%v", profile.Name, err)
	}
	return nil
}

func (s *Service) DeleteProfile(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("profile name is required")
	}
	if strings.EqualFold(name, "default") {
		return errors.New("default profile cannot be deleted")
	}
	return s.store.DeleteProfile(ctx, name)
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
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return errors.New("username is required")
	}
	if strings.TrimSpace(profile) == "" {
		profile = "default"
	}
	if !s.profileExists(ctx, profile) {
		return fmt.Errorf("profile %q not found", profile)
	}
	log.Printf("service UpsertUser start username=%q enabled=%v profile=%q serial=%s",
		username, enabled, profile, shortSerial(certSerial))
	if err := s.backend.UpsertUser(ctx, model.User{
		Username: username, CertSerial: certSerial, Enabled: enabled, Profile: profile,
	}); err != nil {
		log.Printf("service UpsertUser vpp failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return fmt.Errorf("upsert user %q to vpp: %w", username, err)
	}
	existing, _ := s.store.GetUser(ctx, username)
	if err := s.store.UpsertUser(ctx, userstore.StoredUser{
		Username: username, CertSerial: certSerial, Enabled: enabled, Profile: profile,
		Email: existing.Email, Require2FA: existing.Require2FA, Last2FAAt: existing.Last2FAAt,
		RadiusSource: existing.RadiusSource,
	}); err != nil {
		return fmt.Errorf("persist user %q: %w", username, err)
	}
	log.Printf("service UpsertUser ok username=%q ms=%d", username, sinceMs(start))
	return nil
}

func (s *Service) DeleteUser(ctx context.Context, username string) error {
	start := time.Now()
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return errors.New("username is required")
	}
	log.Printf("service DeleteUser start username=%q", username)
	if err := s.backend.DeleteUser(ctx, username); err != nil {
		log.Printf("service DeleteUser vpp failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return fmt.Errorf("delete user %q from vpp: %w", username, err)
	}
	_ = s.store.DeleteUser(ctx, username)
	_ = s.store.DeletePlacement(ctx, username)
	log.Printf("service DeleteUser ok username=%q ms=%d", username, sinceMs(start))
	return nil
}

func (s *Service) Users(ctx context.Context) ([]model.User, error) {
	start := time.Now()
	vppUsers, err := s.backend.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	storedUsers, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	storedMap := make(map[string]userstore.StoredUser, len(storedUsers))
	for _, su := range storedUsers {
		storedMap[su.Username] = su
	}
	seen := make(map[string]bool)
	out := make([]model.User, 0, len(storedUsers))
	for _, vu := range vppUsers {
		username := strings.ToLower(strings.TrimSpace(vu.Username))
		seen[username] = true
		u := vu
		if su, ok := storedMap[username]; ok {
			if strings.TrimSpace(u.CertSerial) == "" {
				u.CertSerial = su.CertSerial
			}
			u.Enabled = su.Enabled
			if strings.TrimSpace(su.Profile) != "" {
				u.Profile = su.Profile
			}
			u.Email = su.Email
			u.Require2FA = su.Require2FA
			u.Last2FAAt = su.Last2FAAt
			u.CreatedAt = su.CreatedAt
			u.UpdatedAt = su.UpdatedAt
		}
		if strings.TrimSpace(u.Profile) == "" {
			u.Profile = "default"
		}
		u.TwoFAStatus = normalizeTwoFAStatus(u.Require2FA, !u.Last2FAAt.IsZero())
		out = append(out, u)
	}
	for _, su := range storedUsers {
		if seen[su.Username] {
			continue
		}
		u := su.ToModel()
		if strings.TrimSpace(u.Profile) == "" {
			u.Profile = "default"
		}
		u.TwoFAStatus = normalizeTwoFAStatus(u.Require2FA, !u.Last2FAAt.IsZero())
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	log.Printf("service Users ok ms=%d count=%d", sinceMs(start), len(out))
	return out, nil
}

// ─── RADIUS import ─────────────────────────────────────────────────────────

type RadiusUserImport struct {
	Username string `json:"username"`
	Profile  string `json:"profile"`
	Enabled  bool   `json:"enabled"`
	Source   string `json:"source"`
}

type RadiusImportResult struct {
	Created int      `json:"created"`
	Updated int      `json:"updated"`
	Skipped int      `json:"skipped"`
	Errors  []string `json:"errors,omitempty"`
}

// ImportRadiusUsers bulk-upserts users from radius-agent.
// Never issues certificates — cert issuance is an explicit admin action.
func (s *Service) ImportRadiusUsers(ctx context.Context, items []RadiusUserImport) RadiusImportResult {
	var result RadiusImportResult
	for _, item := range items {
		username := strings.ToLower(strings.TrimSpace(item.Username))
		if username == "" {
			result.Skipped++
			continue
		}
		profile := strings.TrimSpace(item.Profile)
		if profile == "" {
			profile = "default"
		}
		if !s.profileExists(ctx, profile) {
			result.Errors = append(result.Errors,
				fmt.Sprintf("user %s: profile %q not found", username, profile))
			result.Skipped++
			continue
		}
		source := strings.TrimSpace(item.Source)
		existing, err := s.store.GetUser(ctx, username)
		if err != nil {
			// New user: create pending record (no cert)
			if uerr := s.store.UpsertUser(ctx, userstore.StoredUser{
				Username: username, Enabled: item.Enabled, Profile: profile, RadiusSource: source,
			}); uerr != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("user %s: %v", username, uerr))
				continue
			}
			result.Created++
			continue
		}
		// Existing user — skip if nothing changed
		changed := existing.Profile != profile ||
			existing.Enabled != item.Enabled ||
			(source != "" && existing.RadiusSource != source)
		if !changed {
			result.Skipped++
			continue
		}
		su := existing
		su.Profile = profile
		su.Enabled = item.Enabled
		if source != "" {
			su.RadiusSource = source
		}
		if uerr := s.store.UpsertUser(ctx, su); uerr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("user %s: %v", username, uerr))
			continue
		}
		// Push to VPP only if the user has a cert already
		if strings.TrimSpace(existing.CertSerial) != "" {
			if berr := s.backend.UpsertUser(ctx, model.User{
				Username: username, CertSerial: existing.CertSerial,
				Enabled: item.Enabled, Profile: profile,
			}); berr != nil {
				log.Printf("service ImportRadiusUsers vpp upsert username=%s err=%v (non-fatal)", username, berr)
			}
		}
		result.Updated++
	}
	log.Printf("service ImportRadiusUsers done created=%d updated=%d skipped=%d errors=%d",
		result.Created, result.Updated, result.Skipped, len(result.Errors))
	return result
}

// ─── Bundle issuance ────────────────────────────────────────────────────────

func (s *Service) IssueBundle(ctx context.Context, username string, enabled bool, profile string) ([]byte, string, error) {
	start := time.Now()
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, "", errors.New("username is required")
	}
	if strings.TrimSpace(profile) == "" {
		profile = s.userProfile(ctx, username)
	}
	if strings.TrimSpace(profile) == "" {
		profile = "default"
	}
	if !s.profileExists(ctx, profile) {
		return nil, "", fmt.Errorf("profile %q not found", profile)
	}
	log.Printf("service IssueBundle start username=%q enabled=%v profile=%q", username, enabled, profile)
	bundle, serial, shard, err := s.issueBundleWithAutoPlacement(ctx, username, profile)
	if err != nil {
		log.Printf("service IssueBundle pki failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return nil, "", err
	}
	if err := s.backend.UpsertUser(ctx, model.User{
		Username: username, CertSerial: serial, Enabled: enabled, Profile: profile,
	}); err != nil {
		log.Printf("service IssueBundle vpp failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return nil, "", fmt.Errorf("bundle issued but vpp sync failed for %q: %w", username, err)
	}
	existing, _ := s.store.GetUser(ctx, username)
	if err := s.store.UpsertUser(ctx, userstore.StoredUser{
		Username: username, CertSerial: serial, Enabled: enabled, Profile: profile,
		Email: existing.Email, Require2FA: existing.Require2FA, Last2FAAt: existing.Last2FAAt,
		RadiusSource: existing.RadiusSource,
	}); err != nil {
		return nil, "", fmt.Errorf("persist user %q: %w", username, err)
	}
	log.Printf("service IssueBundle ok username=%q serial=%s shard=%s ms=%d",
		username, shortSerial(serial), shard.Name, sinceMs(start))
	return bundle, serial, nil
}

func (s *Service) ReissueBundle(ctx context.Context, username string, profile string) ([]byte, string, error) {
	start := time.Now()
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, "", errors.New("username is required")
	}
	if strings.TrimSpace(profile) == "" {
		profile = s.userProfile(ctx, username)
	}
	if strings.TrimSpace(profile) == "" {
		profile = "default"
	}
	if !s.profileExists(ctx, profile) {
		return nil, "", fmt.Errorf("profile %q not found", profile)
	}
	log.Printf("service ReissueBundle start username=%q profile=%q", username, profile)
	existing, _ := s.store.GetUser(ctx, username)
	bundle, serial, shard, err := s.issueBundleWithAutoPlacement(ctx, username, profile)
	if err != nil {
		log.Printf("service ReissueBundle pki failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return nil, "", err
	}
	if err := s.backend.ReissueUser(ctx, username, serial); err != nil {
		log.Printf("service ReissueBundle vpp failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return nil, "", fmt.Errorf("bundle reissued but vpp sync failed for %q: %w", username, err)
	}
	if err := s.store.UpsertUser(ctx, userstore.StoredUser{
		Username: username, CertSerial: serial, Enabled: existing.Enabled, Profile: profile,
		Email: existing.Email, Require2FA: existing.Require2FA, Last2FAAt: existing.Last2FAAt,
		RadiusSource: existing.RadiusSource,
	}); err != nil {
		return nil, "", fmt.Errorf("persist user %q: %w", username, err)
	}
	log.Printf("service ReissueBundle ok username=%q serial=%s shard=%s ms=%d",
		username, shortSerial(serial), shard.Name, sinceMs(start))
	return bundle, serial, nil
}

func (s *Service) ReissueUser(ctx context.Context, username, certSerial string) error {
	start := time.Now()
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" || certSerial == "" {
		return errors.New("username and cert serial are required")
	}
	log.Printf("service ReissueUser start username=%q serial=%s", username, shortSerial(certSerial))
	if err := s.backend.ReissueUser(ctx, username, certSerial); err != nil {
		log.Printf("service ReissueUser vpp failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return fmt.Errorf("reissue user %q in vpp: %w", username, err)
	}
	existing, _ := s.store.GetUser(ctx, username)
	if err := s.store.UpsertUser(ctx, userstore.StoredUser{
		Username: username, CertSerial: certSerial, Enabled: true, Profile: existing.Profile,
		Email: existing.Email, Require2FA: existing.Require2FA, Last2FAAt: existing.Last2FAAt,
		RadiusSource: existing.RadiusSource,
	}); err != nil {
		return fmt.Errorf("persist user %q: %w", username, err)
	}
	log.Printf("service ReissueUser ok username=%q ms=%d", username, sinceMs(start))
	return nil
}

// ─── Sessions ────────────────────────────────────────────────────────────────

func (s *Service) Sessions(ctx context.Context) ([]model.Session, error) {
	start := time.Now()
	if err := s.ensureVPP(ctx); err != nil {
		log.Printf("service Sessions ensureVPP warning ms=%d error=%v", sinceMs(start), err)
	}
	sessions, err := s.backend.ListSessions(ctx)
	if err != nil {
		return nil, err
	}
	for i := range sessions {
		username := strings.ToLower(strings.TrimSpace(sessions[i].Username))
		su, serr := s.store.GetUser(ctx, username)
		if serr == nil {
			sessions[i].Email = su.Email
			sessions[i].Require2FA = su.Require2FA
			passed := false
			if !su.Last2FAAt.IsZero() {
				passed = sessions[i].ConnectedAt.IsZero() ||
					!su.Last2FAAt.Before(sessions[i].ConnectedAt.Add(-30*time.Second))
				sessions[i].TwoFAAt = su.Last2FAAt
			}
			sessions[i].TwoFAPassed = passed
			sessions[i].TwoFAStatus = normalizeTwoFAStatus(su.Require2FA, passed)
		}
	}
	latestViolations, err := s.latestPolicyViolationsByUser()
	if err != nil {
		log.Printf("service Sessions violations warning ms=%d error=%v", sinceMs(start), err)
	} else if len(latestViolations) > 0 {
		idx := map[string]int{}
		for i, sess := range sessions {
			idx[strings.TrimSpace(sess.Username)] = i
		}
		for username, v := range latestViolations {
			if i, ok := idx[username]; ok {
				sessions[i].PolicyBlocked = true
				sessions[i].PolicyBlockedAt = v.OccurredAt
				sessions[i].PolicyName = v.PolicyName
				sessions[i].PolicyMessage = v.Message
				sessions[i].PolicyMatchedApps = append([]string(nil), v.MatchedApps...)
				if sessions[i].LastSeen.IsZero() || (!v.OccurredAt.IsZero() && v.OccurredAt.After(sessions[i].LastSeen)) {
					sessions[i].LastSeen = v.OccurredAt
				}
				if !sessions[i].Connected && !v.OccurredAt.IsZero() &&
					(sessions[i].ConnectedAt.IsZero() || v.OccurredAt.After(sessions[i].ConnectedAt) || v.OccurredAt.After(sessions[i].LastSeen)) {
					sessions[i].Source = "policy_deny"
					sessions[i].IP = ""
					sessions[i].MAC = ""
					sessions[i].SystemUser = ""
					sessions[i].OSName = ""
					sessions[i].OSVersion = ""
					sessions[i].SystemUptime = ""
					sessions[i].Interfaces = nil
					sessions[i].AppsCount = len(v.MatchedApps)
					sessions[i].AppsUpdatedAt = v.OccurredAt
				}
				continue
			}
			su, _ := s.store.GetUser(ctx, username)
			passed := !su.Last2FAAt.IsZero()
			sessions = append(sessions, model.Session{
				Username: username, Connected: false, LastSeen: v.OccurredAt,
				AppsCount: len(v.MatchedApps), Source: "policy_deny",
				Email: su.Email, Require2FA: su.Require2FA,
				TwoFAPassed: passed, TwoFAStatus: normalizeTwoFAStatus(su.Require2FA, passed),
				TwoFAAt: su.Last2FAAt, PolicyBlocked: true,
				PolicyBlockedAt: v.OccurredAt, PolicyName: v.PolicyName,
				PolicyMessage: v.Message, PolicyMatchedApps: append([]string(nil), v.MatchedApps...),
			})
		}
	}
	log.Printf("service Sessions ok ms=%d count=%d", sinceMs(start), len(sessions))
	return sessions, nil
}

func (s *Service) DisconnectSession(ctx context.Context, username string) error {
	start := time.Now()
	log.Printf("service DisconnectSession start username=%q", username)
	if err := s.backend.DisconnectSession(ctx, username); err != nil {
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
		ID: fmt.Sprintf("apps-%d", time.Now().UTC().UnixNano()), Type: "apps_snapshot",
		CreatedAt: time.Now().UTC(), Payload: map[string]any{"reason": "manual_request"},
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
	latestViolations, verr := s.latestPolicyViolationsByUser()
	if verr == nil {
		if v, ok := latestViolations[strings.TrimSpace(username)]; ok {
			copyV := v
			view.LastPolicyViolation = &copyV
			if err != nil {
				report = model.AppsSnapshot{Username: username}
				err = nil
			}
			report = mergeViolationApps(report, &copyV)
		}
	}
	if err != nil {
		return view, err
	}
	if strings.TrimSpace(report.Username) == "" {
		report.Username = username
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

func (s *Service) UserCertInfo(ctx context.Context, username string) (map[string]any, error) {
	if strings.TrimSpace(username) == "" {
		return nil, errors.New("username is required")
	}
	info, err := s.pki.GetClientCertInfo(strings.TrimSpace(username))
	if err != nil {
		return nil, err
	}
	profile := s.userProfile(ctx, username)
	vppUsers, _ := s.backend.ListUsers(ctx)
	placement := func() any {
		if p, ok := s.placementForUser(ctx, username); ok {
			return p
		}
		return nil
	}
	for _, u := range vppUsers {
		if strings.EqualFold(strings.TrimSpace(u.Username), strings.TrimSpace(username)) {
			if strings.TrimSpace(u.Profile) != "" {
				profile = u.Profile
			}
			serial := info.Serial
			if serial == "" {
				serial = u.CertSerial
			}
			return map[string]any{
				"username": info.Username, "serial": serial,
				"subject_cn": info.SubjectCN, "issuer_cn": info.IssuerCN,
				"not_before": info.NotBefore, "not_after": info.NotAfter,
				"key_algorithm": info.KeyAlgorithm, "key_bits": info.KeyBits,
				"ext_key_usage": info.ExtKeyUsage,
				"bundle_server_url": info.BundleServerURL, "bundle_server_name": info.BundleServerName,
				"available": info.Available, "note": info.Note,
				"enabled": u.Enabled, "generation": u.Generation, "profile": profile,
				"placement": placement(),
			}, nil
		}
	}
	return map[string]any{
		"username": info.Username, "serial": info.Serial,
		"subject_cn": info.SubjectCN, "issuer_cn": info.IssuerCN,
		"not_before": info.NotBefore, "not_after": info.NotAfter,
		"key_algorithm": info.KeyAlgorithm, "key_bits": info.KeyBits,
		"ext_key_usage": info.ExtKeyUsage,
		"bundle_server_url": info.BundleServerURL, "bundle_server_name": info.BundleServerName,
		"available": info.Available, "note": info.Note,
		"profile": profile, "placement": placement(),
	}, nil
}

func (s *Service) Health(ctx context.Context) map[string]any {
	settings, _ := s.CurrentSettings()
	profiles, _ := s.store.ListProfiles(ctx)
	out := map[string]any{
		"ok": true, "vpp_required": s.requireVPP, "vpp_available": s.vppAvailable(),
		"vpp_socket": s.vppSocket, "server_name": settings.ServerName,
		"client_public_url": settings.ClientPublicURL, "extra_sans": settings.ExtraSANs,
		"applied_sans": settings.AppliedSANs, "plugin_listen_addr": settings.PluginListenAddr,
		"plugin_listen_port": settings.PluginListenPort, "profiles_count": len(profiles),
	}
	out["shards"] = s.shardSummary(ctx)
	return out
}

// ─── App policies (JSON files — not in RADIUS sync path) ─────────────────────

func (s *Service) appPoliciesPath() string {
	if s.pki == nil || strings.TrimSpace(s.pki.DataDir) == "" {
		return filepath.Join(".", "agent-data", "app_policies.json")
	}
	return filepath.Join(s.pki.DataDir, "app_policies.json")
}

func (s *Service) appPolicyViolationsPath() string {
	if s.pki == nil || strings.TrimSpace(s.pki.DataDir) == "" {
		return filepath.Join(".", "agent-data", "app_policy_violations.json")
	}
	return filepath.Join(s.pki.DataDir, "app_policy_violations.json")
}

func (s *Service) loadAppPolicies() ([]model.AppPolicy, error) {
	path := s.appPoliciesPath()
	if err := ensureDir(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return []model.AppPolicy{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return []model.AppPolicy{}, nil
	}
	var out []model.AppPolicy
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []model.AppPolicy{}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

func (s *Service) saveAppPolicies(policies []model.AppPolicy) error {
	path := s.appPoliciesPath()
	if err := ensureDir(path); err != nil {
		return err
	}
	b, err := json.MarshalIndent(policies, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func dedupeStringsFold(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		k := strings.ToLower(v)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, v)
	}
	return out
}

func (s *Service) normalizeAppPolicy(in model.AppPolicy) model.AppPolicy {
	in.ID = strings.TrimSpace(in.ID)
	in.Name = strings.TrimSpace(in.Name)
	in.Mode = strings.TrimSpace(strings.ToLower(in.Mode))
	if in.Mode == "" {
		in.Mode = "deny_on_match"
	}
	if strings.TrimSpace(in.Message) == "" {
		in.Message = "У вас обнаружено запрещенное приложение"
	}
	patterns := make([]model.AppPolicyPattern, 0, len(in.Patterns))
	for _, pat := range in.Patterns {
		pat.Type = strings.TrimSpace(strings.ToLower(pat.Type))
		if pat.Type == "" {
			pat.Type = "contains"
		}
		pat.Value = strings.TrimSpace(pat.Value)
		if pat.Value == "" {
			continue
		}
		patterns = append(patterns, pat)
	}
	in.Patterns = patterns
	if !in.CheckOnClient && !in.CheckOnServer {
		in.CheckOnClient = true
	}
	in.Scope.Profiles = dedupeStringsFold(in.Scope.Profiles)
	in.Scope.Users = dedupeStringsFold(in.Scope.Users)
	in.UpdatedAt = time.Now().UTC()
	return in
}

func (s *Service) AppPolicies(ctx context.Context) ([]model.AppPolicy, error) { return s.loadAppPolicies() }

func (s *Service) UpsertAppPolicy(ctx context.Context, policy model.AppPolicy) error {
	if strings.TrimSpace(policy.ID) == "" {
		return errors.New("policy id is required")
	}
	if strings.TrimSpace(policy.Name) == "" {
		policy.Name = policy.ID
	}
	policy = s.normalizeAppPolicy(policy)
	policies, err := s.loadAppPolicies()
	if err != nil {
		return err
	}
	found := false
	for i := range policies {
		if strings.EqualFold(strings.TrimSpace(policies[i].ID), policy.ID) {
			policies[i] = policy
			found = true
			break
		}
	}
	if !found {
		policies = append(policies, policy)
	}
	return s.saveAppPolicies(policies)
}

func (s *Service) DeleteAppPolicy(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("policy id is required")
	}
	policies, err := s.loadAppPolicies()
	if err != nil {
		return err
	}
	out := make([]model.AppPolicy, 0, len(policies))
	for _, p := range policies {
		if !strings.EqualFold(strings.TrimSpace(p.ID), id) {
			out = append(out, p)
		}
	}
	return s.saveAppPolicies(out)
}

func (s *Service) ResolveAppPolicy(ctx context.Context, username, profile string) (model.AppPolicyResolved, error) {
	policies, err := s.loadAppPolicies()
	if err != nil {
		return model.AppPolicyResolved{}, err
	}
	username = strings.TrimSpace(username)
	profile = strings.TrimSpace(profile)
	if profile == "" && username != "" {
		profile = s.userProfile(ctx, username)
	}
	resolved := model.AppPolicyResolved{
		PolicyVersion: fmt.Sprintf("%d", time.Now().UTC().Unix()),
		Username: username, Profile: profile, Policies: []model.AppPolicy{},
	}
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		match := p.Scope.AllUsers || (len(p.Scope.Profiles) == 0 && len(p.Scope.Users) == 0)
		if !match && username != "" {
			for _, u := range p.Scope.Users {
				if strings.EqualFold(strings.TrimSpace(u), username) {
					match = true
					break
				}
			}
		}
		if !match && profile != "" {
			for _, pr := range p.Scope.Profiles {
				if strings.EqualFold(strings.TrimSpace(pr), profile) {
					match = true
					break
				}
			}
		}
		if match {
			resolved.Policies = append(resolved.Policies, p)
		}
	}
	return resolved, nil
}

func (s *Service) loadAppPolicyViolations() ([]model.AppPolicyViolation, error) {
	raw, err := os.ReadFile(s.appPolicyViolationsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var items []model.AppPolicyViolation
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func trimStringList(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		v := strings.TrimSpace(item)
		if v == "" {
			continue
		}
		key := strings.ToLower(v)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	return out
}

func (s *Service) latestPolicyViolationsByUser() (map[string]model.AppPolicyViolation, error) {
	items, err := s.loadAppPolicyViolations()
	if err != nil {
		return nil, err
	}
	out := map[string]model.AppPolicyViolation{}
	for _, item := range items {
		username := strings.TrimSpace(item.Username)
		if username == "" {
			continue
		}
		cur, ok := out[username]
		if !ok || item.OccurredAt.After(cur.OccurredAt) {
			out[username] = item
		}
	}
	return out, nil
}

func mergeViolationApps(report model.AppsSnapshot, v *model.AppPolicyViolation) model.AppsSnapshot {
	if v == nil || len(v.MatchedApps) == 0 {
		return report
	}
	seen := map[string]struct{}{}
	for _, app := range report.Apps {
		for _, key := range []string{app.Name, app.Exe} {
			key = strings.ToLower(strings.TrimSpace(key))
			if key != "" {
				seen[key] = struct{}{}
			}
		}
	}
	for _, app := range v.MatchedApps {
		name := strings.TrimSpace(app)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		report.Apps = append(report.Apps, model.AppInfo{Name: name, Category: "Заблокировано политикой"})
	}
	if report.GeneratedAt.IsZero() || (!v.OccurredAt.IsZero() && v.OccurredAt.After(report.GeneratedAt)) {
		report.GeneratedAt = v.OccurredAt
	}
	return report
}

func (s *Service) RecordAppPolicyViolation(ctx context.Context, v model.AppPolicyViolation) error {
	path := s.appPolicyViolationsPath()
	if err := ensureDir(path); err != nil {
		return err
	}
	v.Username = strings.TrimSpace(v.Username)
	v.Profile = strings.TrimSpace(v.Profile)
	v.PolicyID = strings.TrimSpace(v.PolicyID)
	v.PolicyName = strings.TrimSpace(v.PolicyName)
	v.Message = strings.TrimSpace(v.Message)
	v.Action = strings.TrimSpace(v.Action)
	v.Source = strings.TrimSpace(v.Source)
	v.MatchedApps = trimStringList(v.MatchedApps)
	if v.OccurredAt.IsZero() {
		v.OccurredAt = time.Now().UTC()
	}
	var items []model.AppPolicyViolation
	raw, err := os.ReadFile(path)
	if err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &items)
	}
	items = append(items, v)
	if len(items) > 2000 {
		items = items[len(items)-2000:]
	}
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// PluginRuntime returns live VPN tunnel data from the VPP plugin.
// Never returns an error — on failure returns empty runtime so the UI still loads.
func (s *Service) PluginRuntime(ctx context.Context) model.PluginRuntime {
	tunnels, _ := s.backend.ListVPNTunnels(ctx)
	if tunnels == nil {
		tunnels = []model.VPNTunnel{}
	}
	running := 0
	for _, t := range tunnels {
		if t.Running {
			running++
		}
	}
	return model.PluginRuntime{
		Tunnels: tunnels,
		Summary: map[string]any{
			"total_tunnels":   len(tunnels),
			"running_tunnels": running,
		},
	}
}

// ─── Direct RADIUS auth settings (for 2FA via RADIUS protocol) ───────────────

// RadiusAuthSettings stores connection params for direct RADIUS authentication.
// These are saved as a JSON file alongside other agent data.
type RadiusAuthSettings struct {
	Enabled        bool   `json:"enabled"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Secret         string `json:"secret"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	Retries        int    `json:"retries"`
	NASIdentifier  string `json:"nas_identifier"`
}

func (s *Service) radiusSettingsPath() string {
	if s.pki == nil || strings.TrimSpace(s.pki.DataDir) == "" {
		return filepath.Join(".", "agent-data", "radius_settings.json")
	}
	return filepath.Join(s.pki.DataDir, "radius_settings.json")
}

func (s *Service) LoadRadiusSettings() (RadiusAuthSettings, error) {
	path := s.radiusSettingsPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return RadiusAuthSettings{Port: 1812, TimeoutSeconds: 5, Retries: 1, NASIdentifier: "tlsctrl-agent"}, nil
		}
		return RadiusAuthSettings{}, err
	}
	var st RadiusAuthSettings
	if err := json.Unmarshal(raw, &st); err != nil {
		return RadiusAuthSettings{}, err
	}
	return st, nil
}

func (s *Service) SaveRadiusSettings(st RadiusAuthSettings) error {
	path := s.radiusSettingsPath()
	if err := ensureDir(path); err != nil {
		return err
	}
	// Normalize defaults
	if st.Port <= 0 {
		st.Port = 1812
	}
	if st.TimeoutSeconds <= 0 {
		st.TimeoutSeconds = 5
	}
	if st.Retries <= 0 {
		st.Retries = 1
	}
	if strings.TrimSpace(st.NASIdentifier) == "" {
		st.NASIdentifier = "tlsctrl-agent"
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
