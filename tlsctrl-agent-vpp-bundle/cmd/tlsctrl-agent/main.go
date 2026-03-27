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
	cfg := config.Load()

	var backend vppclient.Client
	switch cfg.Backend {
	case "memory", "":
		backend = vppclient.NewMemoryClient()
	default:
		log.Fatalf("unsupported backend %q in default build", cfg.Backend)
	}

	pkiManager := pki.NewManager(cfg.DataDir, cfg.ServerName, cfg.DefaultClientURL(), cfg.RequireClientCert)
	svc := service.New(backend, pkiManager, cfg.VPPAPISocket, cfg.RequireVPP)
	srv := httpapi.New(cfg, svc)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("tlsctrl-agent admin=%s client-mtls=%s backend=%s require-vpp=%v vpp-socket=%s client-url=%s data-dir=%s",
		cfg.AdminListenAddr, cfg.ClientListenAddr, cfg.Backend, cfg.RequireVPP, cfg.VPPAPISocket, cfg.DefaultClientURL(), cfg.DataDir)
	if err := srv.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
