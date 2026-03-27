package httpapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/srmkv/tlsctrl-agent/internal/config"
	"github.com/srmkv/tlsctrl-agent/internal/model"
	"github.com/srmkv/tlsctrl-agent/internal/service"
)

type Server struct {
	cfg config.Config
	svc *service.Service
}

func New(cfg config.Config, svc *service.Service) *Server {
	return &Server{cfg: cfg, svc: svc}
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func peerCert(r *http.Request) *x509.Certificate {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

func (s *Server) Run(ctx context.Context) error {
	if err := s.svc.EnsurePKI(); err != nil {
		return err
	}

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/healthz", s.handleHealth)
	adminMux.HandleFunc("/api/admin/users", s.handleAdminUsers)
	adminMux.HandleFunc("/api/admin/users/reissue", s.handleAdminReissue)
	adminMux.HandleFunc("/api/admin/users/delete", s.handleAdminDelete)
	adminMux.HandleFunc("/api/admin/sessions", s.handleAdminSessions)
	adminMux.HandleFunc("/api/admin/sessions/disconnect", s.handleAdminDisconnect)
	adminMux.HandleFunc("/api/admin/bundle", s.handleAdminBundle)
	adminMux.HandleFunc("/api/admin/reissue-bundle", s.handleAdminReissueBundle)
	adminSrv := &http.Server{
		Addr:              s.cfg.AdminListenAddr,
		Handler:           withCORS(adminMux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	clientMux := http.NewServeMux()
	clientMux.HandleFunc("/healthz", s.handleHealth)
	clientMux.HandleFunc("/api/client/heartbeat", s.handleClientHeartbeat)
	clientMux.HandleFunc("/api/client/apps", s.handleClientApps)
	clientMux.HandleFunc("/api/client/command", s.handleClientCommand)
	clientSrv := &http.Server{
		Addr:              s.cfg.ClientListenAddr,
		Handler:           clientMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	tlsCfg, err := s.svc.ServerTLSConfig()
	if err != nil {
		return err
	}
	clientSrv.TLSConfig = tlsCfg

	errCh := make(chan error, 2)
	go func() {
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	go func() {
		if err := clientSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = adminSrv.Shutdown(shutdownCtx)
		_ = clientSrv.Shutdown(shutdownCtx)
	}()

	return <-errCh
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Health(r.Context()))
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users, err := s.svc.Users(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": users})
	case http.MethodPost:
		var req struct {
			Username   string `json:"username"`
			CertSerial string `json:"cert_serial"`
			Enabled    bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.svc.UpsertUser(r.Context(), strings.TrimSpace(req.Username), strings.TrimSpace(req.CertSerial), req.Enabled); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminReissue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username   string `json:"username"`
		CertSerial string `json:"cert_serial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.svc.ReissueUser(r.Context(), strings.TrimSpace(req.Username), strings.TrimSpace(req.CertSerial)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct{ Username string `json:"username"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.svc.DeleteUser(r.Context(), strings.TrimSpace(req.Username)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sessions, err := s.svc.Sessions(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (s *Server) handleAdminDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct{ Username string `json:"username"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.svc.DisconnectSession(r.Context(), strings.TrimSpace(req.Username)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAdminBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}
	bundle, serial, err := s.svc.IssueBundle(r.Context(), username, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-Cert-Serial", serial)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="bundle-`+username+`.zip"`)
	_, _ = w.Write(bundle)
}

func (s *Server) handleAdminReissueBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}
	bundle, serial, err := s.svc.ReissueBundle(r.Context(), username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-Cert-Serial", serial)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="bundle-`+username+`.zip"`)
	_, _ = w.Write(bundle)
}

func (s *Server) handleClientHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var hb model.ClientHeartbeat
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.svc.ClientHeartbeat(r.Context(), peerCert(r), hb); err != nil {
		status := http.StatusUnauthorized
		if strings.Contains(strings.ToLower(err.Error()), "vpp api unavailable") {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, err.Error(), status)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "connected"})
}

func (s *Server) handleClientApps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string          `json:"username"`
		Apps     []model.AppInfo `json:"apps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.svc.ClientApps(r.Context(), peerCert(r), req.Username, req.Apps); err != nil {
		status := http.StatusUnauthorized
		if strings.Contains(strings.ToLower(err.Error()), "vpp api unavailable") {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, err.Error(), status)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleClientCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.URL.Query().Get("username")
	cmd, err := s.svc.ClientCommand(r.Context(), peerCert(r), username)
	if err != nil {
		status := http.StatusUnauthorized
		if strings.Contains(strings.ToLower(err.Error()), "vpp api unavailable") {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, err.Error(), status)
		return
	}
	writeJSON(w, http.StatusOK, cmd)
}
