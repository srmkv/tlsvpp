package pki

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type RuntimeSettings struct {
	ServerName       string   `json:"server_name"`
	ClientPublicURL  string   `json:"client_public_url"`
	ExtraSANs        []string `json:"extra_sans"`
	AppliedSANs      []string `json:"applied_sans,omitempty"`
	PluginListenAddr string   `json:"plugin_listen_addr"`
	PluginListenPort int      `json:"plugin_listen_port"`
}

type ClientCertInfo struct {
	Username         string   `json:"username"`
	Serial           string   `json:"serial"`
	SubjectCN        string   `json:"subject_cn"`
	IssuerCN         string   `json:"issuer_cn"`
	NotBefore        string   `json:"not_before"`
	NotAfter         string   `json:"not_after"`
	KeyAlgorithm     string   `json:"key_algorithm"`
	KeyBits          int      `json:"key_bits"`
	ExtKeyUsage      []string `json:"ext_key_usage,omitempty"`
	BundleServerURL  string   `json:"bundle_server_url,omitempty"`
	BundleServerName string   `json:"bundle_server_name,omitempty"`
	Available        bool     `json:"available"`
	Note             string   `json:"note,omitempty"`
}

type PluginRuntimeMaterial struct {
	ListenAddr    string
	ListenPort    int
	ServerCertPEM string
	ServerKeyPEM  string
	CACertPEM     string
}

type Manager struct {
	mu sync.Mutex

	DataDir          string
	ServerName       string
	ClientURL        string
	RequireMTLS      bool
	ExtraSANs        []string
	PluginListenAddr string
	PluginListenPort int
	certMetaDir      string
	settingsPath     string
	caCertPath       string
	caKeyPath        string
	serverCertPath   string
	serverKeyPath    string

	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	caPEM  []byte
}

func NewManager(dataDir, serverName, clientURL string, requireMTLS bool, extraSANs []string, pluginListenAddr string, pluginListenPort int) *Manager {
	return &Manager{
		DataDir:          dataDir,
		ServerName:       strings.TrimSpace(serverName),
		ClientURL:        strings.TrimSpace(clientURL),
		RequireMTLS:      requireMTLS,
		ExtraSANs:        append([]string(nil), extraSANs...),
		PluginListenAddr: strings.TrimSpace(pluginListenAddr),
		PluginListenPort: pluginListenPort,
		certMetaDir:      filepath.Join(dataDir, "client-certs"),
		settingsPath:     filepath.Join(dataDir, "settings.json"),
		caCertPath:       filepath.Join(dataDir, "ca.pem"),
		caKeyPath:        filepath.Join(dataDir, "ca.key"),
		serverCertPath:   filepath.Join(dataDir, "server.pem"),
		serverKeyPath:    filepath.Join(dataDir, "server.key"),
	}
}

func (m *Manager) Ensure() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(m.DataDir, 0o700); err != nil {
		return fmt.Errorf("mkdir data dir: %w", err)
	}
	if err := os.MkdirAll(m.certMetaDir, 0o700); err != nil {
		return fmt.Errorf("mkdir cert meta dir: %w", err)
	}
	if err := m.loadSettingsLocked(); err != nil {
		return err
	}
	if !fileExists(m.caCertPath) || !fileExists(m.caKeyPath) {
		if err := generateCA(m.caCertPath, m.caKeyPath); err != nil {
			return err
		}
	}
	if err := m.loadPKILocked(); err != nil {
		return err
	}
	if !fileExists(m.serverCertPath) || !fileExists(m.serverKeyPath) {
		if err := m.regenerateServerCertLocked(); err != nil {
			return err
		}
	}
	return m.saveSettingsLocked()
}

func (m *Manager) ServerTLSConfig() (*tls.Config, error) {
	if err := m.Ensure(); err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(m.serverCertPath, m.serverKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if m.RequireMTLS {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(m.caPEM) {
			return nil, fmt.Errorf("append ca pem failed")
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pool
	}
	return cfg, nil
}

func (m *Manager) CurrentSettings() (RuntimeSettings, error) {
	if err := m.Ensure(); err != nil {
		return RuntimeSettings{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	applied, _ := buildAppliedSANs(m.ServerName, m.ClientURL, m.ExtraSANs)
	return RuntimeSettings{
		ServerName:       m.ServerName,
		ClientPublicURL:  m.ClientURL,
		ExtraSANs:        append([]string(nil), m.ExtraSANs...),
		AppliedSANs:      applied,
		PluginListenAddr: m.PluginListenAddr,
		PluginListenPort: m.PluginListenPort,
	}, nil
}

func (m *Manager) UpdateSettings(clientPublicURL, serverName string, extraSANs []string, pluginListenAddr string, pluginListenPort int) (RuntimeSettings, error) {
	clientPublicURL = strings.TrimSpace(clientPublicURL)
	serverName = strings.TrimSpace(serverName)
	cleanExtras := cleanList(extraSANs)

	if clientPublicURL == "" {
		return RuntimeSettings{}, fmt.Errorf("client_public_url is required")
	}
	u, err := url.Parse(clientPublicURL)
	if err != nil {
		return RuntimeSettings{}, fmt.Errorf("parse client_public_url: %w", err)
	}
	if u.Scheme != "https" {
		return RuntimeSettings{}, fmt.Errorf("client_public_url must start with https://")
	}
	if serverName == "" {
		serverName = u.Hostname()
	}
	if serverName == "" {
		return RuntimeSettings{}, fmt.Errorf("server_name is empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.ClientURL = strings.TrimRight(clientPublicURL, "/")
	m.ServerName = serverName
	m.ExtraSANs = cleanExtras
	if strings.TrimSpace(pluginListenAddr) == "" {
		m.PluginListenAddr = "0.0.0.0"
	} else {
		m.PluginListenAddr = strings.TrimSpace(pluginListenAddr)
	}
	if pluginListenPort <= 0 {
		pluginListenPort = 9443
	}
	m.PluginListenPort = pluginListenPort

	if err := os.MkdirAll(m.DataDir, 0o700); err != nil {
		return RuntimeSettings{}, fmt.Errorf("mkdir data dir: %w", err)
	}
	if err := m.loadPKILocked(); err != nil {
		return RuntimeSettings{}, err
	}
	if err := m.regenerateServerCertLocked(); err != nil {
		return RuntimeSettings{}, err
	}
	if err := m.saveSettingsLocked(); err != nil {
		return RuntimeSettings{}, err
	}
	applied, _ := buildAppliedSANs(m.ServerName, m.ClientURL, m.ExtraSANs)
	return RuntimeSettings{
		ServerName:       m.ServerName,
		ClientPublicURL:  m.ClientURL,
		ExtraSANs:        append([]string(nil), m.ExtraSANs...),
		AppliedSANs:      applied,
		PluginListenAddr: m.PluginListenAddr,
		PluginListenPort: m.PluginListenPort,
	}, nil
}

func (m *Manager) IssueBundle(username, profile string) ([]byte, string, error) {
	if err := m.Ensure(); err != nil {
		return nil, "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	clientCertPEM, clientKeyPEM, clientCert, err := generateClientCertPEM(username, m.caCert, m.caKey)
	if err != nil {
		return nil, "", err
	}
	meta := struct {
		Username      string `json:"username"`
		Profile       string `json:"profile,omitempty"`
		ServerURL     string `json:"server_url"`
		ServerName    string `json:"server_name"`
		IssuedAt      string `json:"issued_at"`
		BundleVersion int    `json:"bundle_version"`
	}{
		Username:      username,
		Profile:       strings.TrimSpace(profile),
		ServerURL:     m.ClientURL,
		ServerName:    m.ServerName,
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
		BundleVersion: 1,
	}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("marshal metadata: %w", err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := writeZipEntry(zw, "ca.pem", m.caPEM); err != nil {
		return nil, "", err
	}
	if err := writeZipEntry(zw, "client.crt", clientCertPEM); err != nil {
		return nil, "", err
	}
	if err := writeZipEntry(zw, "client.key", clientKeyPEM); err != nil {
		return nil, "", err
	}
	if err := writeZipEntry(zw, "metadata.json", metaJSON); err != nil {
		return nil, "", err
	}
	if err := zw.Close(); err != nil {
		return nil, "", fmt.Errorf("close zip: %w", err)
	}
	if err := m.saveClientCertInfoLocked(username, clientCert); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), strings.ToLower(clientCert.SerialNumber.Text(16)), nil
}

func ekuNames(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	out := make([]string, 0, len(cert.ExtKeyUsage))
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "ClientAuth")
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "ServerAuth")
		default:
			out = append(out, fmt.Sprintf("EKU(%d)", int(eku)))
		}
	}
	return out
}

func keyBits(cert *x509.Certificate) int {
	if cert == nil || cert.PublicKey == nil {
		return 0
	}
	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pk.N.BitLen()
	default:
		return 0
	}
}

func (m *Manager) certInfoPath(username string) string {
	return filepath.Join(m.certMetaDir, cleanFilename(username)+".json")
}

func cleanFilename(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	v = strings.ReplaceAll(v, "/", "_")
	v = strings.ReplaceAll(v, "\\", "_")
	v = strings.ReplaceAll(v, " ", "_")
	return v
}

func (m *Manager) saveClientCertInfoLocked(username string, cert *x509.Certificate) error {
	if cert == nil {
		return nil
	}
	info := ClientCertInfo{
		Username:         username,
		Serial:           strings.ToLower(cert.SerialNumber.Text(16)),
		SubjectCN:        cert.Subject.CommonName,
		IssuerCN:         cert.Issuer.CommonName,
		NotBefore:        cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:         cert.NotAfter.UTC().Format(time.RFC3339),
		KeyAlgorithm:     "RSA",
		KeyBits:          keyBits(cert),
		ExtKeyUsage:      ekuNames(cert),
		BundleServerURL:  m.ClientURL,
		BundleServerName: m.ServerName,
		Available:        true,
	}
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal client cert info: %w", err)
	}
	return os.WriteFile(m.certInfoPath(username), data, 0o600)
}

func (m *Manager) GetClientCertInfo(username string) (ClientCertInfo, error) {
	if err := m.Ensure(); err != nil {
		return ClientCertInfo{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	path := m.certInfoPath(username)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ClientCertInfo{
				Username:  username,
				Available: false,
				Note:      "Сертификат ещё не сохранён в metadata agent. Скачайте или перевыпустите bundle для этого пользователя.",
			}, nil
		}
		return ClientCertInfo{}, fmt.Errorf("read client cert info: %w", err)
	}
	var info ClientCertInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return ClientCertInfo{}, fmt.Errorf("decode client cert info: %w", err)
	}
	if info.Username == "" {
		info.Username = username
	}
	return info, nil
}

func (m *Manager) PluginMaterial() (PluginRuntimeMaterial, error) {
	if err := m.Ensure(); err != nil {
		return PluginRuntimeMaterial{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	serverCertPEM, err := os.ReadFile(m.serverCertPath)
	if err != nil {
		return PluginRuntimeMaterial{}, fmt.Errorf("read server cert pem: %w", err)
	}
	serverKeyPEM, err := os.ReadFile(m.serverKeyPath)
	if err != nil {
		return PluginRuntimeMaterial{}, fmt.Errorf("read server key pem: %w", err)
	}
	caPEM, err := os.ReadFile(m.caCertPath)
	if err != nil {
		return PluginRuntimeMaterial{}, fmt.Errorf("read ca pem: %w", err)
	}
	listenAddr := m.PluginListenAddr
	if strings.TrimSpace(listenAddr) == "" {
		listenAddr = "0.0.0.0"
	}
	listenPort := m.PluginListenPort
	if listenPort <= 0 {
		listenPort = 9443
	}
	return PluginRuntimeMaterial{
		ListenAddr:    listenAddr,
		ListenPort:    listenPort,
		ServerCertPEM: string(serverCertPEM),
		ServerKeyPEM:  string(serverKeyPEM),
		CACertPEM:     string(caPEM),
	}, nil
}

func (m *Manager) loadSettingsLocked() error {
	data, err := os.ReadFile(m.settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read settings: %w", err)
	}
	var st RuntimeSettings
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("decode settings: %w", err)
	}
	if strings.TrimSpace(st.ServerName) != "" {
		m.ServerName = strings.TrimSpace(st.ServerName)
	}
	if strings.TrimSpace(st.ClientPublicURL) != "" {
		m.ClientURL = strings.TrimRight(strings.TrimSpace(st.ClientPublicURL), "/")
	}
	if len(st.ExtraSANs) > 0 {
		m.ExtraSANs = cleanList(st.ExtraSANs)
	}
	if strings.TrimSpace(st.PluginListenAddr) != "" {
		m.PluginListenAddr = strings.TrimSpace(st.PluginListenAddr)
	}
	if st.PluginListenPort > 0 {
		m.PluginListenPort = st.PluginListenPort
	}
	if m.PluginListenAddr == "" {
		m.PluginListenAddr = "0.0.0.0"
	}
	if m.PluginListenPort <= 0 {
		m.PluginListenPort = 9443
	}
	return nil
}

func (m *Manager) saveSettingsLocked() error {
	applied, _ := buildAppliedSANs(m.ServerName, m.ClientURL, m.ExtraSANs)
	st := RuntimeSettings{
		ServerName:       m.ServerName,
		ClientPublicURL:  m.ClientURL,
		ExtraSANs:        append([]string(nil), m.ExtraSANs...),
		AppliedSANs:      applied,
		PluginListenAddr: m.PluginListenAddr,
		PluginListenPort: m.PluginListenPort,
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	return os.WriteFile(m.settingsPath, data, 0o600)
}

func (m *Manager) loadPKILocked() error {
	if !fileExists(m.caCertPath) || !fileExists(m.caKeyPath) {
		if err := generateCA(m.caCertPath, m.caKeyPath); err != nil {
			return err
		}
	}
	caPEM, err := os.ReadFile(m.caCertPath)
	if err != nil {
		return fmt.Errorf("read ca cert: %w", err)
	}
	caKeyPEM, err := os.ReadFile(m.caKeyPath)
	if err != nil {
		return fmt.Errorf("read ca key: %w", err)
	}
	caCert, err := parseCertPEM(caPEM)
	if err != nil {
		return err
	}
	caKey, err := parseRSAPrivateKeyPEM(caKeyPEM)
	if err != nil {
		return err
	}
	m.caPEM = caPEM
	m.caCert = caCert
	m.caKey = caKey
	return nil
}

func (m *Manager) regenerateServerCertLocked() error {
	_ = os.Remove(m.serverCertPath)
	_ = os.Remove(m.serverKeyPath)
	dnsSANs, ipSANs, _, err := buildServerSANs(m.ServerName, m.ClientURL, m.ExtraSANs)
	if err != nil {
		return err
	}
	return generateServerCert(m.serverCertPath, m.serverKeyPath, m.ServerName, dnsSANs, ipSANs, m.caCert, m.caKey)
}

func buildAppliedSANs(serverName, clientURL string, extraSANs []string) ([]string, string) {
	dnsSANs, ipSANs, commonName, _ := buildServerSANs(serverName, clientURL, extraSANs)
	vals := make([]string, 0, len(dnsSANs)+len(ipSANs)+1)
	if commonName != "" {
		vals = append(vals, "CN="+commonName)
	}
	for _, dns := range dnsSANs {
		vals = append(vals, "DNS:"+dns)
	}
	for _, ip := range ipSANs {
		vals = append(vals, "IP:"+ip.String())
	}
	return vals, commonName
}

func buildServerSANs(serverName, clientURL string, extraSANs []string) ([]string, []net.IP, string, error) {
	dnsSet := map[string]struct{}{"localhost": {}}
	ipSet := map[string]net.IP{
		"127.0.0.1": net.ParseIP("127.0.0.1"),
		"::1":       net.ParseIP("::1"),
	}

	addSAN := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if ip := net.ParseIP(v); ip != nil {
			ipSet[ip.String()] = ip
			return
		}
		dnsSet[v] = struct{}{}
	}

	commonName := strings.TrimSpace(serverName)
	if commonName == "" {
		if u, err := url.Parse(strings.TrimSpace(clientURL)); err == nil {
			commonName = u.Hostname()
		}
	}
	addSAN(commonName)

	if u, err := url.Parse(strings.TrimSpace(clientURL)); err == nil {
		addSAN(u.Hostname())
	}

	for _, san := range cleanList(extraSANs) {
		addSAN(san)
	}

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addSAN(strings.TrimSpace(iface.Name))
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.IP != nil {
					ip := v.IP
					if ip4 := ip.To4(); ip4 != nil {
						ip = ip4
					}
					ipSet[ip.String()] = ip
				}
			case *net.IPAddr:
				if v.IP != nil {
					ip := v.IP
					if ip4 := ip.To4(); ip4 != nil {
						ip = ip4
					}
					ipSet[ip.String()] = ip
				}
			}
		}
	}

	dnsSANs := make([]string, 0, len(dnsSet))
	for v := range dnsSet {
		if strings.TrimSpace(v) != "" {
			dnsSANs = append(dnsSANs, v)
		}
	}
	sort.Strings(dnsSANs)

	ipKeys := make([]string, 0, len(ipSet))
	for k := range ipSet {
		ipKeys = append(ipKeys, k)
	}
	sort.Strings(ipKeys)
	ipSANs := make([]net.IP, 0, len(ipKeys))
	for _, k := range ipKeys {
		if ipSet[k] != nil {
			ipSANs = append(ipSANs, ipSet[k])
		}
	}
	if commonName == "" {
		if len(dnsSANs) > 0 {
			commonName = dnsSANs[0]
		} else if len(ipSANs) > 0 {
			commonName = ipSANs[0].String()
		}
	}
	if commonName == "" {
		return nil, nil, "", fmt.Errorf("server_name is empty")
	}
	return dnsSANs, ipSANs, commonName, nil
}

func cleanList(items []string) []string {
	set := map[string]struct{}{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			set[item] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func writeZipEntry(zw *zip.Writer, name string, data []byte) error {
	f, err := zw.Create(name)
	if err != nil {
		return fmt.Errorf("create zip entry %s: %w", name, err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write zip entry %s: %w", name, err)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func generateCA(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "tlsctrl-agent-ca",
			Organization: []string{"TLSCTRL"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create ca cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write ca cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write ca key: %w", err)
	}
	return nil
}

func generateServerCert(certPath, keyPath, commonName string, dnsSANs []string, ipSANs []net.IP, caCert *x509.Certificate, caKey *rsa.PrivateKey) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"TLSCTRL Agent"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().AddDate(3, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsSANs,
		IPAddresses: ipSANs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create server cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write server cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write server key: %w", err)
	}
	return nil
}

func generateClientCertPEM(username string, caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, []byte, *x509.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate client key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   username,
			Organization: []string{"TLSCTRL Client"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().AddDate(2, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create client cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse client cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM, cert, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("random serial: %w", err)
	}
	return serial, nil
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("pem decode failed")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseRSAPrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("pem decode failed")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse rsa key: %w", err)
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not rsa")
	}
	return key, nil
}
