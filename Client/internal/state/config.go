package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	ServerURL      string `json:"server_url"`
	ServerName     string `json:"server_name"`
	ClientsPath    string `json:"clients_path"`
	CommandsPath   string `json:"commands_path"`
	AppsReportPath string `json:"apps_report_path"`
	PollSeconds    int    `json:"poll_seconds"`
	Username       string `json:"username"`
	Profile        string `json:"profile"`
	CACertFile     string `json:"ca_cert_file"`
	ClientCertFile string `json:"client_cert_file"`
	ClientKeyFile  string `json:"client_key_file"`
}

func configDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("user config dir: %w", err)
	}
	path := filepath.Join(base, "tlsclientnative")
	if err := os.MkdirAll(path, 0o700); err != nil {
		return "", fmt.Errorf("mkdir config dir: %w", err)
	}
	return path, nil
}

func configPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func defaultConfig() (Config, error) {
	dir, err := configDir()
	if err != nil {
		return Config{}, err
	}
	return Config{
		ServerURL:      "https://127.0.0.1:9443",
		ServerName:     "",
		ClientsPath:    "/api/client/vpn-bind",
		CommandsPath:   "/api/client/command",
		AppsReportPath: "/api/client/apps",
		PollSeconds:    5,
		Username:       "",
		Profile:        "default",
		CACertFile:     filepath.Join(dir, "ca.pem"),
		ClientCertFile: filepath.Join(dir, "client.crt"),
		ClientKeyFile:  filepath.Join(dir, "client.key"),
	}, nil
}

func Load() (Config, error) {
	cfg, err := defaultConfig()
	if err != nil {
		return Config{}, err
	}
	path, err := configPath()
	if err != nil {
		return Config{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshal config: %w", err)
	}
	if cfg.ClientsPath == "" || cfg.ClientsPath == "/api/v1/clients" || cfg.ClientsPath == "/api/client/heartbeat" {
		cfg.ClientsPath = "/api/client/vpn-bind"
	}
	if cfg.CommandsPath == "" || cfg.CommandsPath == "/api/v1/commands" {
		cfg.CommandsPath = "/api/client/command"
	}
	if cfg.AppsReportPath == "" || cfg.AppsReportPath == "/api/v1/apps/report" {
		cfg.AppsReportPath = "/api/client/apps"
	}
	if cfg.PollSeconds <= 0 {
		cfg.PollSeconds = 5
	}
	if cfg.Profile == "" {
		cfg.Profile = "default"
	}
	return cfg, nil
}

func Save(cfg Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
