package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	DataDir    string `yaml:"data_dir"`
	SQLite     struct {
		Path string `yaml:"path"`
	} `yaml:"sqlite"`
	Sync struct {
		DefaultIntervalSec int `yaml:"default_interval_sec"`
	} `yaml:"sync"`
	ControlPlane struct {
		APIBase string `yaml:"api_base"`
		Token   string `yaml:"token"`
	} `yaml:"controlplane"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":9190"
	}
	if cfg.SQLite.Path == "" {
		return nil, fmt.Errorf("sqlite.path required")
	}
	if cfg.Sync.DefaultIntervalSec <= 0 {
		cfg.Sync.DefaultIntervalSec = 60
	}
	return &cfg, nil
}

func (c *Config) SyncInterval() time.Duration {
	return time.Duration(c.Sync.DefaultIntervalSec) * time.Second
}
