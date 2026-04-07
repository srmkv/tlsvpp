package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/srmkv/tlsctrl-agent/internal/model"
)

func (s *Server) handleAdminAppPolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.svc.AppPolicies(r.Context())
		if err != nil {
			writeError(w, "admin_app_policies_get", http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"policies": items})
	case http.MethodPost:
		var req model.AppPolicy
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "admin_app_policies_post_decode", http.StatusBadRequest, err)
			return
		}
		if err := s.svc.UpsertAppPolicy(r.Context(), req); err != nil {
			writeError(w, "admin_app_policies_post", http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminDeleteAppPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "admin_app_policies_delete_decode", http.StatusBadRequest, err)
		return
	}
	if err := s.svc.DeleteAppPolicy(r.Context(), req.ID); err != nil {
		writeError(w, "admin_app_policies_delete", http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handlePluginResolveAppPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Profile  string `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "plugin_app_policy_resolve_decode", http.StatusBadRequest, err)
		return
	}
	res, err := s.svc.ResolveAppPolicy(r.Context(), strings.TrimSpace(req.Username), strings.TrimSpace(req.Profile))
	if err != nil {
		writeError(w, "plugin_app_policy_resolve", http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handlePluginAppPolicyViolation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req model.AppPolicyViolation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "plugin_app_policy_violation_decode", http.StatusBadRequest, err)
		return
	}
	if err := s.svc.RecordAppPolicyViolation(r.Context(), req); err != nil {
		writeError(w, "plugin_app_policy_violation", http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handlePluginEvaluateAppPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req model.AppPolicyEvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "plugin_app_policy_evaluate_decode", http.StatusBadRequest, err)
		return
	}
	res, err := s.svc.EvaluateAppPolicy(r.Context(), req)
	if err != nil {
		writeError(w, "plugin_app_policy_evaluate", http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}
