package httpapi

import (
    "encoding/json"
    "net/http"
    "strings"

    "tlsctrl-agent/internal/service"
)

func (s *Server) handleAdminSMTPSettings(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        st, err := s.svc.LoadSMTPSettings()
        if err != nil {
            writeError(w, "admin_smtp_get", http.StatusInternalServerError, err)
            return
        }
        writeJSON(w, http.StatusOK, st)
    case http.MethodPost:
        var req service.SMTPSettings
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            writeError(w, "admin_smtp_post_decode", http.StatusBadRequest, err)
            return
        }
        st, err := s.svc.SaveSMTPSettings(req)
        if err != nil {
            writeError(w, "admin_smtp_post", http.StatusBadRequest, err)
            return
        }
        writeJSON(w, http.StatusOK, st)
    default:
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
    }
}

func (s *Server) handleAdminSMTPTest(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    var req service.SMTPTestRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, "admin_smtp_test_decode", http.StatusBadRequest, err)
        return
    }
    req.To = strings.TrimSpace(req.To)
    if req.To == "" {
        writeError(w, "admin_smtp_test", http.StatusBadRequest, http.ErrMissingFile)
        return
    }
    if err := s.svc.SendSMTPTest(r.Context(), req); err != nil {
        writeError(w, "admin_smtp_test", http.StatusBadRequest, err)
        return
    }
    writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handlePlugin2FAStart(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    var req struct {
        Username string `json:"username"`
        Profile  string `json:"profile"`
        ClientIP string `json:"client_ip"`
        IP       string `json:"ip"`
        RemoteIP string `json:"remote_ip"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, "plugin_2fa_start_decode", http.StatusBadRequest, err)
        return
    }
    clientIP := firstNonEmptyHTTP(req.ClientIP, req.IP, req.RemoteIP)
    reply, err := s.svc.TwoFAStart(r.Context(), strings.TrimSpace(req.Username), strings.TrimSpace(req.Profile), strings.TrimSpace(clientIP))
    if err != nil {
        writeError(w, "plugin_2fa_start", http.StatusBadRequest, err)
        return
    }
    writeJSON(w, http.StatusOK, reply)
}

func (s *Server) handlePlugin2FAVerify(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    var req struct {
        Username    string `json:"username"`
        Profile     string `json:"profile"`
        ClientIP    string `json:"client_ip"`
        IP          string `json:"ip"`
        RemoteIP    string `json:"remote_ip"`
        ChallengeID string `json:"challenge_id"`
        Code        string `json:"code"`
        OTP         string `json:"otp"`
        BindNonce   string `json:"bind_nonce"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, "plugin_2fa_verify_decode", http.StatusBadRequest, err)
        return
    }
    clientIP := firstNonEmptyHTTP(req.ClientIP, req.IP, req.RemoteIP)
    code := firstNonEmptyHTTP(req.Code, req.OTP)
    reply, err := s.svc.TwoFAVerify(r.Context(), strings.TrimSpace(req.Username), strings.TrimSpace(req.Profile), strings.TrimSpace(clientIP), strings.TrimSpace(req.ChallengeID), strings.TrimSpace(code), strings.TrimSpace(req.BindNonce))
    if err != nil {
        writeError(w, "plugin_2fa_verify", http.StatusBadRequest, err)
        return
    }
    writeJSON(w, http.StatusOK, reply)
}

func (s *Server) handlePlugin2FAResend(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    var req struct {
        ChallengeID string `json:"challenge_id"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, "plugin_2fa_resend_decode", http.StatusBadRequest, err)
        return
    }
    reply, err := s.svc.TwoFAResend(r.Context(), strings.TrimSpace(req.ChallengeID))
    if err != nil {
        writeError(w, "plugin_2fa_resend", http.StatusBadRequest, err)
        return
    }
    writeJSON(w, http.StatusOK, reply)
}

func firstNonEmptyHTTP(values ...string) string {
    for _, v := range values {
        v = strings.TrimSpace(v)
        if v != "" {
            return v
        }
    }
    return ""
}
