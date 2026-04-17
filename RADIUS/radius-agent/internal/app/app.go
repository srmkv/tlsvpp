package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"radius-agent/internal/config"
	"radius-agent/internal/httpapi"
	"radius-agent/internal/resolver"
	frsql "radius-agent/internal/source/freeradius_sql"
	sqlitestore "radius-agent/internal/store/sqlite"
	"radius-agent/internal/syncer"
)

type App struct {
	cfg    *config.Config
	server *http.Server
	stop   context.CancelFunc
}

func New(cfg *config.Config) (*App, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, err
	}
	store, err := sqlitestore.New(filepath.Clean(cfg.SQLite.Path))
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}
	adapter := frsql.New()
	engine := syncer.New(store, adapter)
	resolverSvc := resolver.New(store)
	httpServer := httpapi.New(store, engine, resolverSvc)
	ctx, cancel := context.WithCancel(context.Background())
	go syncer.NewScheduler(store, engine).Run(ctx, cfg.SyncInterval())
	return &App{
		cfg:    cfg,
		server: &http.Server{Addr: cfg.ListenAddr, Handler: httpServer.Handler()},
		stop:   cancel,
	}, nil
}

func (a *App) Run() error {
	errCh := make(chan error, 1)
	go func() {
		log.Printf("radius-agent listening on %s", a.cfg.ListenAddr)
		errCh <- a.server.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		log.Printf("radius-agent stopping by signal %s", sig)
		a.stop()
		return a.server.Shutdown(context.Background())
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
