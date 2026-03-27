package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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

func certSerialHex(cert *x509.Certificate) string {
	if cert == nil || cert.SerialNumber == nil {
		return ""
	}
	return strings.ToLower(cert.SerialNumber.Text(16))
}

func (s *Service) EnsurePKI() error {
	if s.pki == nil {
		return errors.New("pki manager is not configured")
	}
	return s.pki.Ensure()
}

func (s *Service) ServerTLSConfig() (*tls.Config, error) {
	if s.pki == nil {
		return nil, errors.New("pki manager is not configured")
	}
	return s.pki.ServerTLSConfig()
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
	if username == "" {
		return errors.New("username is required")
	}
	return s.backend.UpsertUser(ctx, model.User{
		Username:   username,
		CertSerial: certSerial,
		Enabled:    enabled,
	})
}

func (s *Service) IssueBundle(ctx context.Context, username string, enabled bool) ([]byte, string, error) {
	if username == "" {
		return nil, "", errors.New("username is required")
	}
	bundle, serial, err := s.pki.IssueBundle(username)
	if err != nil {
		return nil, "", err
	}
	if err := s.backend.UpsertUser(ctx, model.User{
		Username:   username,
		CertSerial: serial,
		Enabled:    enabled,
	}); err != nil {
		return nil, "", err
	}
	return bundle, serial, nil
}

func (s *Service) ReissueBundle(ctx context.Context, username string) ([]byte, string, error) {
	if username == "" {
		return nil, "", errors.New("username is required")
	}
	bundle, serial, err := s.pki.IssueBundle(username)
	if err != nil {
		return nil, "", err
	}
	if err := s.backend.ReissueUser(ctx, username, serial); err != nil {
		return nil, "", err
	}
	return bundle, serial, nil
}

func (s *Service) ReissueUser(ctx context.Context, username, certSerial string) error {
	if username == "" || certSerial == "" {
		return errors.New("username and cert serial are required")
	}
	return s.backend.ReissueUser(ctx, username, certSerial)
}

func (s *Service) DeleteUser(ctx context.Context, username string) error {
	if username == "" {
		return errors.New("username is required")
	}
	return s.backend.DeleteUser(ctx, username)
}

func (s *Service) Users(ctx context.Context) ([]model.User, error) {
	return s.backend.ListUsers(ctx)
}

func (s *Service) Sessions(ctx context.Context) ([]model.Session, error) {
	if err := s.ensureVPP(ctx); err != nil {
		// still return sessions, but they are already forcibly disconnected
	}
	return s.backend.ListSessions(ctx)
}

func (s *Service) DisconnectSession(ctx context.Context, username string) error {
	return s.backend.DisconnectSession(ctx, username)
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

func (s *Service) ClientApps(ctx context.Context, cert *x509.Certificate, username string, apps []model.AppInfo) error {
	if cert == nil {
		return errors.New("mTLS peer cert is required")
	}
	if err := s.ensureVPP(ctx); err != nil {
		return err
	}
	return s.backend.SetClientApps(ctx, username, apps)
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

func (s *Service) Health(ctx context.Context) map[string]any {
	return map[string]any{
		"ok":            true,
		"vpp_required":  s.requireVPP,
		"vpp_available": s.vppAvailable(),
		"vpp_socket":    s.vppSocket,
	}
}
