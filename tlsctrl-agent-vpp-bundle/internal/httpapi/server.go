package httpapi

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/srmkv/tlsctrl-agent/internal/config"
	"github.com/srmkv/tlsctrl-agent/internal/model"
	"github.com/srmkv/tlsctrl-agent/internal/service"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func writeError(w http.ResponseWriter, op string, status int, err error) {
	if err != nil {
		log.Printf("http %s status=%d error=%v", op, status, err)
		http.Error(w, err.Error(), status)
		return
	}
	http.Error(w, http.StatusText(status), status)
}

func remoteAddrOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

type Server struct {
	cfg config.Config
	svc *service.Service
}

func New(cfg config.Config, svc *service.Service) *Server { return &Server{cfg: cfg, svc: svc} }

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

func withAccessLog(enabled bool, next http.Handler) http.Handler {
	if !enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		log.Printf("http access method=%s path=%s query=%q remote=%s status=%d ms=%d ua=%q", r.Method, r.URL.Path, r.URL.RawQuery, remoteAddrOnly(r.RemoteAddr), status, time.Since(start).Milliseconds(), r.UserAgent())
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) Run(ctx context.Context) error {
	log.Printf("http Run start admin-listen=%s backend=%s access-log=%v", s.cfg.AdminListenAddr, s.cfg.Backend, s.cfg.HTTPAccessLog)
	if err := s.svc.EnsurePKI(); err != nil {
		log.Printf("http Run EnsurePKI failed error=%v", err)
		return err
	}
	if err := s.svc.SyncPluginRuntime(context.Background()); err != nil {
		log.Printf("http Run SyncPluginRuntime failed error=%v", err)
		return err
	}
	log.Printf("http Run init complete")

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/api/admin/settings", s.handleAdminSettings)
	mux.HandleFunc("/api/admin/users", s.handleAdminUsers)
	mux.HandleFunc("/api/admin/users/reissue", s.handleAdminReissue)
	mux.HandleFunc("/api/admin/users/delete", s.handleAdminDelete)
	mux.HandleFunc("/api/admin/users/request-apps", s.handleAdminRequestApps)
	mux.HandleFunc("/api/admin/users/apps", s.handleAdminUserApps)
	mux.HandleFunc("/api/admin/users/cert", s.handleAdminUserCert)
	mux.HandleFunc("/api/admin/sessions", s.handleAdminSessions)
	mux.HandleFunc("/api/admin/sessions/disconnect", s.handleAdminDisconnect)
	mux.HandleFunc("/api/admin/bundle", s.handleAdminBundle)
	mux.HandleFunc("/api/admin/reissue-bundle", s.handleAdminReissueBundle)

	httpSrv := &http.Server{
		Addr:              s.cfg.AdminListenAddr,
		Handler:           withAccessLog(s.cfg.HTTPAccessLog, withCORS(mux)),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()
	return httpSrv.ListenAndServe()
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Health(r.Context()))
}

func (s *Server) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		st, err := s.svc.CurrentSettings()
		if err != nil {
			writeError(w, "admin_settings_get", 500, err)
			return
		}
		writeJSON(w, 200, st)
	case http.MethodPost:
		var req struct {
			ClientPublicURL  string   `json:"client_public_url"`
			ServerName       string   `json:"server_name"`
			ExtraSANs        []string `json:"extra_sans"`
			PluginListenAddr string   `json:"plugin_listen_addr"`
			PluginListenPort int      `json:"plugin_listen_port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "admin_users_post_decode", 400, err)
			return
		}
		st, err := s.svc.UpdateSettings(r.Context(), strings.TrimSpace(req.ClientPublicURL), strings.TrimSpace(req.ServerName), req.ExtraSANs, strings.TrimSpace(req.PluginListenAddr), req.PluginListenPort)
		if err != nil {
			writeError(w, "admin_settings_post", 400, err)
			return
		}
		writeJSON(w, 200, st)
	default:
		http.Error(w, "method not allowed", 405)
	}
}
func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users, err := s.svc.Users(r.Context())
		if err != nil {
			writeError(w, "admin_users_get", 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{"users": users})
	case http.MethodPost:
		var req struct {
			Username   string `json:"username"`
			CertSerial string `json:"cert_serial"`
			Enabled    bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "admin_settings_post_decode", 400, err)
			return
		}
		if err := s.svc.UpsertUser(r.Context(), strings.TrimSpace(req.Username), strings.TrimSpace(req.CertSerial), req.Enabled); err != nil {
			writeError(w, "admin_users_post", 400, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", 405)
	}
}
func (s *Server) handleAdminReissue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username   string `json:"username"`
		CertSerial string `json:"cert_serial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "admin_reissue_decode", 400, err)
		return
	}
	if err := s.svc.ReissueUser(r.Context(), strings.TrimSpace(req.Username), strings.TrimSpace(req.CertSerial)); err != nil {
		writeError(w, "admin_reissue", 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "admin_delete_decode", 400, err)
		return
	}
	if err := s.svc.DeleteUser(r.Context(), strings.TrimSpace(req.Username)); err != nil {
		writeError(w, "admin_delete", 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) handleAdminRequestApps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "admin_request_apps_decode", 400, err)
		return
	}
	cmd, err := s.svc.RequestApps(r.Context(), strings.TrimSpace(req.Username))
	if err != nil {
		writeError(w, "admin_request_apps", 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "command": cmd})
}
func (s *Server) handleAdminUserCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}
	view, err := s.svc.UserCertInfo(r.Context(), username)
	if err != nil {
		writeError(w, "admin_user_cert", http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleAdminUserApps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		http.Error(w, "username is required", 400)
		return
	}
	view, err := s.svc.AppsView(r.Context(), username)
	if err != nil {
		writeError(w, "admin_user_apps", 500, err)
		return
	}
	writeJSON(w, 200, view)
}
func (s *Server) handleAdminSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	sessions, err := s.svc.Sessions(r.Context())
	if err != nil {
		writeError(w, "admin_sessions", 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"sessions": sessions})
}
func (s *Server) handleAdminDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "admin_disconnect_decode", 400, err)
		return
	}
	if err := s.svc.DisconnectSession(r.Context(), strings.TrimSpace(req.Username)); err != nil {
		writeError(w, "admin_disconnect", 400, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) handleAdminBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		http.Error(w, "username is required", 400)
		return
	}
	bundle, serial, err := s.svc.IssueBundle(r.Context(), username, true)
	if err != nil {
		writeError(w, "admin_bundle", 500, err)
		return
	}
	w.Header().Set("X-Cert-Serial", serial)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="bundle-`+username+`.zip"`)
	_, _ = w.Write(bundle)
}
func (s *Server) handleAdminReissueBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		http.Error(w, "username is required", 400)
		return
	}
	bundle, serial, err := s.svc.ReissueBundle(r.Context(), username)
	if err != nil {
		writeError(w, "admin_reissue_bundle", 500, err)
		return
	}
	w.Header().Set("X-Cert-Serial", serial)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="bundle-`+username+`.zip"`)
	_, _ = w.Write(bundle)
}

// Note: there is intentionally no /api/client/* on the agent anymore.
// Client traffic must terminate in the VPP plugin. The agent is admin/PKI only.
var _ = model.Command{}
