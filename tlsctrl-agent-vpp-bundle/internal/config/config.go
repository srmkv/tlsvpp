package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	AdminListenAddr   string
	ClientListenAddr  string
	Backend           string
	VPPAPISocket      string
	RequireVPP        bool
	DataDir           string
	ServerName        string
	PublicHost        string
	ClientPublicURL   string
	RequireClientCert bool
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func Load() Config {
	return Config{
		AdminListenAddr:   envOr("TLSCTRL_ADMIN_LISTEN_ADDR", ":9080"),
		ClientListenAddr:  envOr("TLSCTRL_CLIENT_LISTEN_ADDR", ":9443"),
		Backend:           envOr("TLSCTRL_BACKEND", "memory"),
		VPPAPISocket:      envOr("TLSCTRL_VPP_API_SOCKET", "/run/vpp/api.sock"),
		RequireVPP:        envBool("TLSCTRL_REQUIRE_VPP", true),
		DataDir:           envOr("TLSCTRL_DATA_DIR", "./agent-data"),
		ServerName:        envOr("TLSCTRL_SERVER_NAME", "localhost"),
		PublicHost:        envOr("TLSCTRL_PUBLIC_HOST", "127.0.0.1"),
		ClientPublicURL:   strings.TrimSpace(os.Getenv("TLSCTRL_CLIENT_PUBLIC_URL")),
		RequireClientCert: envBool("TLSCTRL_REQUIRE_CLIENT_CERT", true),
	}
}

func (c Config) DefaultClientURL() string {
	if strings.TrimSpace(c.ClientPublicURL) != "" {
		return strings.TrimRight(c.ClientPublicURL, "/")
	}
	addr := strings.TrimSpace(c.ClientListenAddr)
	host := strings.TrimSpace(c.PublicHost)
	if host == "" {
		host = "127.0.0.1"
	}
	if strings.HasPrefix(addr, ":") {
		return fmt.Sprintf("https://%s%s", host, addr)
	}
	if strings.HasPrefix(addr, "0.0.0.0:") {
		parts := strings.SplitN(addr, ":", 2)
		return fmt.Sprintf("https://%s:%s", host, parts[1])
	}
	if strings.Contains(addr, "://") {
		return strings.TrimRight(addr, "/")
	}
	return "https://" + addr
}
