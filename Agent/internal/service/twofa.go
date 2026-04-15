package service

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type SMTPSettings struct {
	Enabled         bool   `json:"enabled"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Security        string `json:"security"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	FromEmail       string `json:"from_email"`
	FromName        string `json:"from_name"`
	ReplyTo         string `json:"reply_to"`
	SubjectTemplate string `json:"subject_template"`
	BodyTemplate    string `json:"body_template"`
	CodeTTLSeconds  int    `json:"code_ttl_seconds"`
	CodeLength      int    `json:"code_length"`
	MaxAttempts     int    `json:"max_attempts"`
}

type SMTPTestRequest struct {
	Settings SMTPSettings `json:"settings"`
	To       string       `json:"to"`
}

type TwoFAStartReply struct {
	OK          bool   `json:"ok"`
	Status      string `json:"status,omitempty"`
	Required    bool   `json:"required,omitempty"`
	ChallengeID string `json:"challenge_id,omitempty"`
	Method      string `json:"method,omitempty"`
	MaskedEmail string `json:"masked_email,omitempty"`
	TTLSeconds  int    `json:"ttl_seconds,omitempty"`
	BindNonce   string `json:"bind_nonce,omitempty"`
}

type TwoFAChallengeRecord struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Profile     string    `json:"profile,omitempty"`
	ClientIP    string    `json:"client_ip,omitempty"`
	Email       string    `json:"email"`
	Masked      string    `json:"masked_email"`
	Code        string    `json:"code"`
	BindNonce   string    `json:"bind_nonce"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Attempts    int       `json:"attempts"`
	MaxAttempts int       `json:"max_attempts"`
}

type TwoFAVerifyResult struct {
	OK         bool      `json:"ok"`
	Passed     bool      `json:"passed"`
	Require2FA bool      `json:"require_2fa"`
	Username   string    `json:"username,omitempty"`
	Profile    string    `json:"profile,omitempty"`
	PassedAt   time.Time `json:"passed_at,omitempty"`
}

func (s SMTPSettings) normalized() SMTPSettings {
	s.Host = strings.TrimSpace(s.Host)
	s.Security = strings.ToLower(strings.TrimSpace(s.Security))
	if s.Security == "" {
		s.Security = "starttls"
	}
	if s.Port == 0 {
		s.Port = 587
		if s.Security == "ssl" || s.Security == "tls" {
			s.Port = 465
		}
	}
	if s.CodeTTLSeconds <= 0 {
		s.CodeTTLSeconds = 300
	}
	if s.CodeLength <= 0 {
		s.CodeLength = 6
	}
	if s.CodeLength > 10 {
		s.CodeLength = 10
	}
	if s.MaxAttempts <= 0 {
		s.MaxAttempts = 5
	}
	s.FromEmail = strings.TrimSpace(s.FromEmail)
	s.FromName = strings.TrimSpace(s.FromName)
	s.ReplyTo = strings.TrimSpace(s.ReplyTo)
	s.Username = strings.TrimSpace(s.Username)
	if strings.TrimSpace(s.SubjectTemplate) == "" {
		s.SubjectTemplate = "Код подтверждения входа"
	}
	if strings.TrimSpace(s.BodyTemplate) == "" {
		s.BodyTemplate = "Ваш код входа: {{CODE}}\nПользователь: {{USERNAME}}\nКод действует {{TTL}} сек."
	}
	return s
}

func (s SMTPSettings) validate() error {
	s = s.normalized()
	if !s.Enabled {
		return nil
	}
	if s.Host == "" {
		return errors.New("smtp host is required")
	}
	if s.Port <= 0 {
		return errors.New("smtp port is required")
	}
	if s.FromEmail == "" {
		return errors.New("smtp from_email is required")
	}
	if _, err := mail.ParseAddress(s.FromEmail); err != nil {
		return fmt.Errorf("invalid from_email: %w", err)
	}
	return nil
}

func (s *Service) smtpSettingsPath() string {
	if s.pki == nil || strings.TrimSpace(s.pki.DataDir) == "" {
		return filepath.Join(".", "agent-data", "smtp-settings.json")
	}
	return filepath.Join(s.pki.DataDir, "smtp-settings.json")
}

func (s *Service) twoFAChallengesPath() string {
	if s.pki == nil || strings.TrimSpace(s.pki.DataDir) == "" {
		return filepath.Join(".", "agent-data", "twofa-challenges.json")
	}
	return filepath.Join(s.pki.DataDir, "twofa-challenges.json")
}

func (s *Service) LoadSMTPSettings() (SMTPSettings, error) {
	path := s.smtpSettingsPath()
	if err := ensureDir(path); err != nil {
		return SMTPSettings{}, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return SMTPSettings{}.normalized(), nil
	}
	if err != nil {
		return SMTPSettings{}, err
	}
	if len(raw) == 0 {
		return SMTPSettings{}.normalized(), nil
	}
	var st SMTPSettings
	if err := json.Unmarshal(raw, &st); err != nil {
		return SMTPSettings{}, err
	}
	return st.normalized(), nil
}

func (s *Service) SaveSMTPSettings(st SMTPSettings) (SMTPSettings, error) {
	st = st.normalized()
	if err := st.validate(); err != nil {
		return SMTPSettings{}, err
	}
	path := s.smtpSettingsPath()
	if err := ensureDir(path); err != nil {
		return SMTPSettings{}, err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return SMTPSettings{}, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return SMTPSettings{}, err
	}
	return st, nil
}

func (s *Service) loadChallenges() (map[string]TwoFAChallengeRecord, error) {
	path := s.twoFAChallengesPath()
	if err := ensureDir(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]TwoFAChallengeRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return map[string]TwoFAChallengeRecord{}, nil
	}
	var out map[string]TwoFAChallengeRecord
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]TwoFAChallengeRecord{}
	}
	now := time.Now().UTC()
	for id, rec := range out {
		if !rec.ExpiresAt.IsZero() && now.After(rec.ExpiresAt) {
			delete(out, id)
		}
	}
	return out, nil
}

func (s *Service) saveChallenges(in map[string]TwoFAChallengeRecord) error {
	path := s.twoFAChallengesPath()
	if err := ensureDir(path); err != nil {
		return err
	}
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func randomNumericCode(n int) (string, error) {
	if n <= 0 {
		n = 6
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		x, err := crand.Int(crand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		b.WriteByte(byte('0' + x.Int64()))
	}
	return b.String(), nil
}

func randomToken(n int) (string, error) {
	if n <= 0 {
		n = 24
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var b strings.Builder
	for i := 0; i < n; i++ {
		x, err := crand.Int(crand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[x.Int64()])
	}
	return b.String(), nil
}

func maskEmail(v string) string {
	v = strings.TrimSpace(v)
	parts := strings.Split(v, "@")
	if len(parts) != 2 {
		return "***"
	}
	name, domain := parts[0], parts[1]
	if len(name) <= 2 {
		name = name[:1] + "***"
	} else {
		name = name[:1] + strings.Repeat("*", len(name)-2) + name[len(name)-1:]
	}
	dp := strings.Split(domain, ".")
	if len(dp) > 0 && len(dp[0]) > 2 {
		dp[0] = dp[0][:1] + strings.Repeat("*", len(dp[0])-2) + dp[0][len(dp[0])-1:]
	}
	return name + "@" + strings.Join(dp, ".")
}

func renderSMTPTemplate(tpl, username, code string, ttlSeconds int) string {
	repl := strings.NewReplacer(
		"{{USERNAME}}", username,
		"{{CODE}}", code,
		"{{TTL}}", strconv.Itoa(ttlSeconds),
	)
	return repl.Replace(tpl)
}

func smtpHeaderAddress(name, addr string) string {
	addr = strings.TrimSpace(addr)
	name = strings.TrimSpace(name)
	if addr == "" {
		return ""
	}
	if name == "" {
		return addr
	}
	return (&mail.Address{Name: name, Address: addr}).String()
}

func sendSMTPMessage(st SMTPSettings, to, subject, body string) error {
	st = st.normalized()
	if err := st.validate(); err != nil {
		return err
	}
	to = strings.TrimSpace(to)
	if to == "" {
		return errors.New("recipient is required")
	}
	if _, err := mail.ParseAddress(to); err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}
	addr := net.JoinHostPort(st.Host, strconv.Itoa(st.Port))
	fromHeader := smtpHeaderAddress(st.FromName, st.FromEmail)
	msg := strings.Join([]string{
		"From: " + fromHeader,
		"To: " + to,
		func() string {
			if st.ReplyTo != "" {
				return "Reply-To: " + st.ReplyTo
			}
			return ""
		}(),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")
	host := st.Host
	var auth smtp.Auth
	if st.Username != "" {
		auth = smtp.PlainAuth("", st.Username, st.Password, host)
	}
	switch st.Security {
	case "ssl", "tls":
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err != nil {
			return err
		}
		defer conn.Close()
		c, err := smtp.NewClient(conn, host)
		if err != nil {
			return err
		}
		defer c.Quit()
		if auth != nil {
			if err := c.Auth(auth); err != nil {
				return err
			}
		}
		if err := c.Mail(st.FromEmail); err != nil {
			return err
		}
		if err := c.Rcpt(to); err != nil {
			return err
		}
		wc, err := c.Data()
		if err != nil {
			return err
		}
		if _, err := wc.Write([]byte(msg)); err != nil {
			_ = wc.Close()
			return err
		}
		return wc.Close()
	default:
		c, err := smtp.Dial(addr)
		if err != nil {
			return err
		}
		defer c.Quit()
		if st.Security == "starttls" {
			if ok, _ := c.Extension("STARTTLS"); ok {
				if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
					return err
				}
			}
		}
		if auth != nil {
			if ok, _ := c.Extension("AUTH"); ok {
				if err := c.Auth(auth); err != nil {
					return err
				}
			}
		}
		if err := c.Mail(st.FromEmail); err != nil {
			return err
		}
		if err := c.Rcpt(to); err != nil {
			return err
		}
		wc, err := c.Data()
		if err != nil {
			return err
		}
		if _, err := wc.Write([]byte(msg)); err != nil {
			_ = wc.Close()
			return err
		}
		return wc.Close()
	}
}

func (s *Service) SendSMTPTest(ctx context.Context, req SMTPTestRequest) error {
	_ = ctx
	st := req.Settings.normalized()
	if !st.Enabled {
		return errors.New("smtp is disabled")
	}
	subject := "Проверка SMTP TLS VPN"
	body := "Тестовое письмо отправлено из TLS VPN Agent."
	return sendSMTPMessage(st, req.To, subject, body)
}

func (s *Service) UpdateUser2FAConfig(username, email string, require2FA bool) error {
	username = normalizeUserMetaKey(username)
	if username == "" {
		return errors.New("username is required")
	}
	meta, err := s.loadUserMeta()
	if err != nil {
		return err
	}
	m := getUserMeta(meta, username)
	m.Profile = strings.TrimSpace(firstNonEmpty2FA(m.Profile, s.userProfile(username), "default"))
	m.Email = strings.TrimSpace(email)
	m.Require2FA = require2FA
	setUserMeta(meta, username, m)
	return s.saveUserMeta(meta)
}

func firstNonEmpty2FA(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

func normalizeTwoFAStatus(require2FA, passed bool) string {
	if !require2FA {
		return "not_required"
	}
	if passed {
		return "passed"
	}
	return "not_passed"
}

func (s *Service) markUser2FAPassed(username string, at time.Time) error {
	username = normalizeUserMetaKey(username)
	meta, err := s.loadUserMeta()
	if err != nil {
		return err
	}
	m := getUserMeta(meta, username)
	m.Last2FAAt = at.UTC()
	setUserMeta(meta, username, m)
	return s.saveUserMeta(meta)
}

func (s *Service) TwoFAStart(ctx context.Context, username, profile, clientIP string) (TwoFAStartReply, error) {
	_ = ctx
	origUsername := strings.TrimSpace(username)
	username = normalizeUserMetaKey(username)
	profile = strings.TrimSpace(profile)
	clientIP = strings.TrimSpace(clientIP)
	if username == "" {
		return TwoFAStartReply{}, errors.New("username is required")
	}
	meta, err := s.loadUserMeta()
	if err != nil {
		return TwoFAStartReply{}, err
	}
	m := getUserMeta(meta, username)
	if !m.Require2FA {
		log.Printf("service TwoFAStart bypass username=%q normalized=%q require2FA=%v email=%q", origUsername, username, m.Require2FA, strings.TrimSpace(m.Email))
		return TwoFAStartReply{OK: true, Status: "ok", Required: false}, nil
	}
	if strings.TrimSpace(m.Email) == "" {
		return TwoFAStartReply{}, errors.New("email for 2FA is not configured")
	}
	st, err := s.LoadSMTPSettings()
	if err != nil {
		return TwoFAStartReply{}, err
	}
	if !st.Enabled {
		return TwoFAStartReply{}, errors.New("smtp is disabled")
	}
	code, err := randomNumericCode(st.CodeLength)
	if err != nil {
		return TwoFAStartReply{}, err
	}
	challengeID, err := randomToken(32)
	if err != nil {
		return TwoFAStartReply{}, err
	}
	bindNonce, err := randomToken(24)
	if err != nil {
		return TwoFAStartReply{}, err
	}
	body := renderSMTPTemplate(st.BodyTemplate, origUsername, code, st.CodeTTLSeconds)
	subject := renderSMTPTemplate(st.SubjectTemplate, origUsername, code, st.CodeTTLSeconds)
	if err := sendSMTPMessage(st, m.Email, subject, body); err != nil {
		return TwoFAStartReply{}, err
	}
	all, err := s.loadChallenges()
	if err != nil {
		return TwoFAStartReply{}, err
	}
	now := time.Now().UTC()
	all[challengeID] = TwoFAChallengeRecord{
		ID:          challengeID,
		Username:    origUsername,
		Profile:     strings.TrimSpace(firstNonEmpty2FA(profile, m.Profile, "default")),
		ClientIP:    clientIP,
		Email:       m.Email,
		Masked:      maskEmail(m.Email),
		Code:        code,
		BindNonce:   bindNonce,
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Duration(st.CodeTTLSeconds) * time.Second),
		Attempts:    0,
		MaxAttempts: st.MaxAttempts,
	}
	if err := s.saveChallenges(all); err != nil {
		return TwoFAStartReply{}, err
	}
	return TwoFAStartReply{OK: true, Status: "2fa_required", Required: true, ChallengeID: challengeID, Method: "email", MaskedEmail: maskEmail(m.Email), TTLSeconds: st.CodeTTLSeconds, BindNonce: bindNonce}, nil
}

func (s *Service) TwoFAResend(ctx context.Context, challengeID string) (TwoFAStartReply, error) {
	_ = ctx
	challengeID = strings.TrimSpace(challengeID)
	if challengeID == "" {
		return TwoFAStartReply{}, errors.New("challenge_id is required")
	}
	all, err := s.loadChallenges()
	if err != nil {
		return TwoFAStartReply{}, err
	}
	rec, ok := all[challengeID]
	if !ok {
		return TwoFAStartReply{}, errors.New("challenge not found")
	}
	st, err := s.LoadSMTPSettings()
	if err != nil {
		return TwoFAStartReply{}, err
	}
	if !st.Enabled {
		return TwoFAStartReply{}, errors.New("smtp is disabled")
	}
	code, err := randomNumericCode(st.CodeLength)
	if err != nil {
		return TwoFAStartReply{}, err
	}
	now := time.Now().UTC()
	rec.Code = code
	rec.CreatedAt = now
	rec.ExpiresAt = now.Add(time.Duration(st.CodeTTLSeconds) * time.Second)
	rec.Attempts = 0
	rec.MaxAttempts = st.MaxAttempts
	all[challengeID] = rec
	if err := s.saveChallenges(all); err != nil {
		return TwoFAStartReply{}, err
	}
	body := renderSMTPTemplate(st.BodyTemplate, rec.Username, code, st.CodeTTLSeconds)
	subject := renderSMTPTemplate(st.SubjectTemplate, rec.Username, code, st.CodeTTLSeconds)
	if err := sendSMTPMessage(st, rec.Email, subject, body); err != nil {
		return TwoFAStartReply{}, err
	}
	return TwoFAStartReply{OK: true, Status: "2fa_required", Required: true, ChallengeID: rec.ID, Method: "email", MaskedEmail: rec.Masked, TTLSeconds: st.CodeTTLSeconds, BindNonce: rec.BindNonce}, nil
}

func (s *Service) TwoFAVerify(ctx context.Context, username, profile, clientIP, challengeID, code, bindNonce string) (TwoFAVerifyResult, error) {
	_ = ctx
	origUsername := strings.TrimSpace(username)
	username = normalizeUserMetaKey(username)
	challengeID = strings.TrimSpace(challengeID)
	profile = strings.TrimSpace(profile)
	clientIP = strings.TrimSpace(clientIP)
	code = strings.TrimSpace(code)
	bindNonce = strings.TrimSpace(bindNonce)
	if challengeID == "" || username == "" || code == "" {
		return TwoFAVerifyResult{}, errors.New("username, challenge_id and code are required")
	}
	all, err := s.loadChallenges()
	if err != nil {
		return TwoFAVerifyResult{}, err
	}
	rec, ok := all[challengeID]
	if !ok {
		return TwoFAVerifyResult{}, errors.New("challenge not found")
	}
	if normalizeUserMetaKey(rec.Username) != username {
		return TwoFAVerifyResult{}, errors.New("challenge does not belong to this user")
	}
	if profile != "" && rec.Profile != "" && !strings.EqualFold(rec.Profile, profile) {
		return TwoFAVerifyResult{}, errors.New("challenge profile mismatch")
	}
	if bindNonce != "" && rec.BindNonce != "" && bindNonce != rec.BindNonce {
		return TwoFAVerifyResult{}, errors.New("challenge bind nonce mismatch")
	}
	if clientIP != "" && rec.ClientIP != "" && rec.ClientIP != clientIP {
		return TwoFAVerifyResult{}, errors.New("challenge client ip mismatch")
	}
	now := time.Now().UTC()
	if !rec.ExpiresAt.IsZero() && now.After(rec.ExpiresAt) {
		delete(all, challengeID)
		_ = s.saveChallenges(all)
		return TwoFAVerifyResult{}, errors.New("challenge expired")
	}
	if rec.Code != code {
		rec.Attempts++
		if rec.MaxAttempts > 0 && rec.Attempts >= rec.MaxAttempts {
			delete(all, challengeID)
		} else {
			all[challengeID] = rec
		}
		_ = s.saveChallenges(all)
		return TwoFAVerifyResult{}, errors.New("invalid code")
	}
	delete(all, challengeID)
	if err := s.saveChallenges(all); err != nil {
		return TwoFAVerifyResult{}, err
	}
	if err := s.markUser2FAPassed(rec.Username, now); err != nil {
		return TwoFAVerifyResult{}, err
	}
	return TwoFAVerifyResult{OK: true, Passed: true, Require2FA: true, Username: firstNonEmpty2FA(origUsername, rec.Username, username), Profile: firstNonEmpty2FA(profile, rec.Profile), PassedAt: now}, nil
}
