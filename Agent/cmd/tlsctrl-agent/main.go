package main

import (
	"context"
	"log"
	"os/signal"
	"path/filepath"
	"syscall"

	"tlsctrl-agent/internal/config"
	"tlsctrl-agent/internal/httpapi"
	"tlsctrl-agent/internal/pki"
	"tlsctrl-agent/internal/service"
	"tlsctrl-agent/internal/userstore"
	"tlsctrl-agent/internal/vppclient"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	cfg := config.Load()

	// ── Open the SQLite user/profile/shard store ──────────────────────────
	dbPath := filepath.Join(cfg.DataDir, "agent.db")
	st, err := userstore.Open(dbPath)
	if err != nil {
		log.Fatalf("userstore open %s: %v", dbPath, err)
	}
	defer func() { _ = st.Close() }()

	// ── VPP backend ───────────────────────────────────────────────────────
	var backend vppclient.Client
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

	// ── PKI manager ───────────────────────────────────────────────────────
	pkiManager := pki.NewManager(
		cfg.DataDir, cfg.ServerName, cfg.DefaultClientURL(),
		cfg.RequireClientCert, nil,
		cfg.PluginListenAddr, cfg.PluginListenPort,
	)

	// ── Service / HTTP server ─────────────────────────────────────────────
	svc := service.New(backend, pkiManager, st, cfg.VPPAPISocket, cfg.RequireVPP)
	srv := httpapi.New(cfg, svc)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("tlsctrl-agent admin=%s backend=%s require-vpp=%v vpp-api=%s client-url=%s plugin-listen=%s:%d data-dir=%s db=%s",
		cfg.AdminListenAddr, cfg.Backend, cfg.RequireVPP, cfg.VPPAPISocket,
		cfg.DefaultClientURL(), cfg.PluginListenAddr, cfg.PluginListenPort,
		cfg.DataDir, dbPath)

	if err := srv.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
