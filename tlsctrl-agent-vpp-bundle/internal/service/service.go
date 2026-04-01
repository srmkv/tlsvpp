package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
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
	return &Service{backend: backend, pki: pkiManager, vppSocket: strings.TrimSpace(vppSocket), requireVPP: requireVPP}
}

func shortSerial(serial string) string {
	serial = strings.TrimSpace(serial)
	if len(serial) <= 12 {
		return serial
	}
	return serial[:12] + "..."
}

func sinceMs(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}

func certSerialHex(cert *x509.Certificate) string {
	if cert == nil || cert.SerialNumber == nil {
		return ""
	}
	return strings.ToLower(cert.SerialNumber.Text(16))
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

func (s *Service) UpsertUser(ctx context.Context, username, certSerial string, enabled bool) error {
	start := time.Now()
	if username == "" {
		err := errors.New("username is required")
		log.Printf("service UpsertUser error=%v", err)
		return err
	}
	log.Printf("service UpsertUser start username=%q enabled=%v serial=%s", username, enabled, shortSerial(certSerial))
	err := s.backend.UpsertUser(ctx, model.User{
		Username:   username,
		CertSerial: certSerial,
		Enabled:    enabled,
	})
	if err != nil {
		log.Printf("service UpsertUser failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return fmt.Errorf("upsert user %q to vpp: %w", username, err)
	}
	log.Printf("service UpsertUser ok username=%q ms=%d", username, sinceMs(start))
	return nil
}

func (s *Service) IssueBundle(ctx context.Context, username string, enabled bool) ([]byte, string, error) {
	start := time.Now()
	if username == "" {
		err := errors.New("username is required")
		log.Printf("service IssueBundle error=%v", err)
		return nil, "", err
	}
	log.Printf("service IssueBundle start username=%q enabled=%v", username, enabled)
	bundle, serial, err := s.pki.IssueBundle(username)
	if err != nil {
		log.Printf("service IssueBundle pki failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return nil, "", err
	}
	log.Printf("service IssueBundle pki ok username=%q serial=%s bundle-bytes=%d ms=%d", username, shortSerial(serial), len(bundle), sinceMs(start))
	if err := s.backend.UpsertUser(ctx, model.User{
		Username:   username,
		CertSerial: serial,
		Enabled:    enabled,
	}); err != nil {
		log.Printf("service IssueBundle sync-vpp failed username=%q serial=%s ms=%d error=%v", username, shortSerial(serial), sinceMs(start), err)
		return nil, "", fmt.Errorf("bundle issued but vpp user sync failed for %q: %w", username, err)
	}
	log.Printf("service IssueBundle ok username=%q serial=%s ms=%d", username, shortSerial(serial), sinceMs(start))
	return bundle, serial, nil
}

func (s *Service) ReissueBundle(ctx context.Context, username string) ([]byte, string, error) {
	start := time.Now()
	if username == "" {
		err := errors.New("username is required")
		log.Printf("service ReissueBundle error=%v", err)
		return nil, "", err
	}
	log.Printf("service ReissueBundle start username=%q", username)
	bundle, serial, err := s.pki.IssueBundle(username)
	if err != nil {
		log.Printf("service ReissueBundle pki failed username=%q ms=%d error=%v", username, sinceMs(start), err)
		return nil, "", err
	}
	if err := s.backend.ReissueUser(ctx, username, serial); err != nil {
		log.Printf("service ReissueBundle sync-vpp failed username=%q serial=%s ms=%d error=%v", username, shortSerial(serial), sinceMs(start), err)
		return nil, "", fmt.Errorf("bundle reissued but vpp sync failed for %q: %w", username, err)
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

func (s *Service) UserCertInfo(ctx context.Context, username string) (map[string]any, error) {
	if strings.TrimSpace(username) == "" {
		return nil, errors.New("username is required")
	}
	info, err := s.pki.GetClientCertInfo(strings.TrimSpace(username))
	if err != nil {
		return nil, err
	}
	users, err := s.backend.ListUsers(ctx)
	if err == nil {
		for _, u := range users {
			if strings.TrimSpace(u.Username) == strings.TrimSpace(username) {
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
	}, nil
}

func (s *Service) Health(ctx context.Context) map[string]any {
	settings, _ := s.CurrentSettings()
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
	}
}
