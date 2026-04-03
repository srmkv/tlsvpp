package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	AdminListenAddr   string
	Backend           string
	VPPAPISocket      string
	RequireVPP        bool
	DataDir           string
	ServerName        string
	PublicHost        string
	ClientPublicURL   string
	RequireClientCert bool
	PluginListenAddr  string
	PluginListenPort  int
	VerboseLogging    bool
	HTTPAccessLog     bool
	GovPPTimeout      time.Duration
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
func envInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	var out int
	_, err := fmt.Sscanf(v, "%d", &out)
	if err != nil || out <= 0 {
		return fallback
	}
	return out
}

func Load() Config {
	return Config{
		AdminListenAddr:   envOr("TLSCTRL_ADMIN_LISTEN_ADDR", ":9080"),
		Backend:           envOr("TLSCTRL_BACKEND", "memory"),
		VPPAPISocket:      envOr("TLSCTRL_VPP_API_SOCKET", "/run/vpp/api.sock"),
		RequireVPP:        envBool("TLSCTRL_REQUIRE_VPP", true),
		DataDir:           envOr("TLSCTRL_DATA_DIR", "./agent-data"),
		ServerName:        envOr("TLSCTRL_SERVER_NAME", "localhost"),
		PublicHost:        envOr("TLSCTRL_PUBLIC_HOST", "127.0.0.1"),
		ClientPublicURL:   strings.TrimSpace(os.Getenv("TLSCTRL_CLIENT_PUBLIC_URL")),
		RequireClientCert: envBool("TLSCTRL_REQUIRE_CLIENT_CERT", true),
		PluginListenAddr:  envOr("TLSCTRL_PLUGIN_LISTEN_ADDR", "0.0.0.0"),
		PluginListenPort:  envInt("TLSCTRL_PLUGIN_LISTEN_PORT", 9443),
		VerboseLogging:    envBool("TLSCTRL_VERBOSE_LOGGING", true),
		HTTPAccessLog:     envBool("TLSCTRL_HTTP_ACCESS_LOG", true),
		GovPPTimeout:      time.Duration(envInt("TLSCTRL_GOVPP_TIMEOUT_SECONDS", 5)) * time.Second,
	}
}

func (c Config) DefaultClientURL() string {
	if strings.TrimSpace(c.ClientPublicURL) != "" {
		return strings.TrimRight(c.ClientPublicURL, "/")
	}
	return "https://" + c.PublicHost + ":9443"
}
