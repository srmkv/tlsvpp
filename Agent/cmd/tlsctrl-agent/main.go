package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/srmkv/tlsctrl-agent/internal/config"
	"github.com/srmkv/tlsctrl-agent/internal/httpapi"
	"github.com/srmkv/tlsctrl-agent/internal/pki"
	"github.com/srmkv/tlsctrl-agent/internal/service"
	"github.com/srmkv/tlsctrl-agent/internal/vppclient"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	cfg := config.Load()

	var (
		backend vppclient.Client
		err     error
	)

	switch cfg.Backend {
	case "", "memory":
		backend = vppclient.NewMemoryClient()
	case "govpp":
		backend, err = newGovPPBackend(cfg)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unsupported backend %q", cfg.Backend)
	}

	pkiManager := pki.NewManager(cfg.DataDir, cfg.ServerName, cfg.DefaultClientURL(), cfg.RequireClientCert, nil, cfg.PluginListenAddr, cfg.PluginListenPort)
	svc := service.New(backend, pkiManager, cfg.VPPAPISocket, cfg.RequireVPP)
	srv := httpapi.New(cfg, svc)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("tlsctrl-agent admin=%s backend=%s require-vpp=%v vpp-api=%s client-url=%s plugin-listen=%s:%d data-dir=%s verbose=%v access-log=%v govpp-timeout=%s",
		cfg.AdminListenAddr, cfg.Backend, cfg.RequireVPP, cfg.VPPAPISocket, cfg.DefaultClientURL(), cfg.PluginListenAddr, cfg.PluginListenPort, cfg.DataDir, cfg.VerboseLogging, cfg.HTTPAccessLog, cfg.GovPPTimeout)
	if err := srv.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
