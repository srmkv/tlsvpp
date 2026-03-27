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
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Manager struct {
	DataDir     string
	ServerName  string
	ClientURL   string
	RequireMTLS bool

	caCertPath     string
	caKeyPath      string
	serverCertPath string
	serverKeyPath  string

	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	caPEM  []byte
}

func NewManager(dataDir, serverName, clientURL string, requireMTLS bool) *Manager {
	return &Manager{
		DataDir:        dataDir,
		ServerName:     serverName,
		ClientURL:      clientURL,
		RequireMTLS:    requireMTLS,
		caCertPath:     filepath.Join(dataDir, "ca.pem"),
		caKeyPath:      filepath.Join(dataDir, "ca.key"),
		serverCertPath: filepath.Join(dataDir, "server.pem"),
		serverKeyPath:  filepath.Join(dataDir, "server.key"),
	}
}

func (m *Manager) Ensure() error {
	if err := os.MkdirAll(m.DataDir, 0o700); err != nil {
		return fmt.Errorf("mkdir data dir: %w", err)
	}
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

	if !fileExists(m.serverCertPath) || !fileExists(m.serverKeyPath) {
		if err := generateServerCert(m.serverCertPath, m.serverKeyPath, m.ServerName, caCert, caKey); err != nil {
			return err
		}
	}
	return nil
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

func (m *Manager) IssueBundle(username string) ([]byte, string, error) {
	if err := m.Ensure(); err != nil {
		return nil, "", err
	}
	clientCertPEM, clientKeyPEM, clientCert, err := generateClientCertPEM(username, m.caCert, m.caKey)
	if err != nil {
		return nil, "", err
	}
	meta := struct {
		Username   string `json:"username"`
		ServerURL  string `json:"server_url"`
		ServerName string `json:"server_name"`
	}{
		Username:   username,
		ServerURL:  m.ClientURL,
		ServerName: m.ServerName,
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
	return buf.Bytes(), strings.ToLower(clientCert.SerialNumber.Text(16)), nil
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

func generateServerCert(certPath, keyPath, serverName string, caCert *x509.Certificate, caKey *rsa.PrivateKey) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	dnsNames := []string{"localhost"}
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if ip := net.ParseIP(serverName); ip != nil {
		ipAddresses = append(ipAddresses, ip)
	} else if strings.TrimSpace(serverName) != "" && serverName != "localhost" {
		dnsNames = append(dnsNames, serverName)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   serverName,
			Organization: []string{"TLSCTRL Agent"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().AddDate(3, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
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
