package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"radius-agent/internal/health"
	"radius-agent/internal/model"
	"radius-agent/internal/resolver"
	"radius-agent/internal/store"
	"radius-agent/internal/syncer"
)

type Server struct {
	store    store.Store
	engine   *syncer.Engine
	resolver *resolver.Service
	mux      *http.ServeMux
}

func New(st store.Store, eng *syncer.Engine, rs *resolver.Service) *Server {
	s := &Server{store: st, engine: eng, resolver: rs, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/api/admin/radius/sources", s.handleSources)
	s.mux.HandleFunc("/api/admin/radius/sources/", s.handleSourceSubroutes)
	s.mux.HandleFunc("/api/admin/radius/mappings/groups", s.handleGroupMappings)
	s.mux.HandleFunc("/api/admin/radius/mappings/attrs", s.handleAttrMappings)
	s.mux.HandleFunc("/api/admin/radius/resolve", s.handleResolve)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, health.Status{OK: true})
}

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sources, intervals, err := s.store.ListSources(r.Context())
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": sources, "intervals": intervals})
	case http.MethodPost:
		var in model.SourceInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, err, http.StatusBadRequest)
			return
		}
		src := model.Source{ID: in.ID, Name: in.Name, Type: model.SourceType(in.Type), Enabled: in.Enabled, DSN: in.DSN, Description: in.Description}
		if src.ID == "" || src.Name == "" || src.DSN == "" {
			writeError(w, errors.New("id,name,dsn required"), http.StatusBadRequest)
			return
		}
		if in.SyncEverySec <= 0 {
			in.SyncEverySec = 60
		}
		if err := s.store.UpsertSource(r.Context(), src, in.SyncEverySec); err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSourceSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/radius/sources/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		writeError(w, errors.New("invalid path"), http.StatusBadRequest)
		return
	}
	sourceID, action := parts[0], parts[1]
	switch action {
	case "sync":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		snap, err := s.engine.SyncSource(r.Context(), sourceID)
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, snap)
	case "users":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		snap, err := s.store.GetLatestSnapshot(r.Context(), sourceID)
		if err != nil {
			writeError(w, err, http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": snap.Users})
	case "groups":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		snap, err := s.store.GetLatestSnapshot(r.Context(), sourceID)
		if err != nil {
			writeError(w, err, http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": snap.Groups})
	case "snapshot":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		snap, err := s.store.GetLatestSnapshot(r.Context(), sourceID)
		if err != nil {
			writeError(w, err, http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, snap)
	default:
		writeError(w, errors.New("unknown action"), http.StatusBadRequest)
	}
}

func (s *Server) handleGroupMappings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListGroupMappings(r.Context())
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var items []model.GroupMapping
		if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
			writeError(w, err, http.StatusBadRequest)
			return
		}
		if err := s.store.SaveGroupMappings(r.Context(), items); err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAttrMappings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListAttrMappings(r.Context())
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		var items []model.AttrMapping
		if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
			writeError(w, err, http.StatusBadRequest)
			return
		}
		if err := s.store.SaveAttrMappings(r.Context(), items); err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	sourceID := r.URL.Query().Get("source_id")
	username := r.URL.Query().Get("username")
	if sourceID == "" || username == "" {
		writeError(w, errors.New("source_id and username required"), http.StatusBadRequest)
		return
	}
	out, err := s.resolver.ResolveUser(r.Context(), sourceID, username)
	if err != nil {
		writeError(w, err, http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("radius-agent: encode response: %v", err)
	}
}

func writeError(w http.ResponseWriter, err error, code int) {
	writeJSON(w, code, map[string]any{"ok": false, "error": err.Error()})
}

func Shutdown(ctx context.Context, srv *http.Server) error { return srv.Shutdown(ctx) }
