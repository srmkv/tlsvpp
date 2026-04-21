package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"radius-agent/internal/config"
	"radius-agent/internal/httpapi"
	"radius-agent/internal/integration/controlplane"
	"radius-agent/internal/model"
	"radius-agent/internal/resolver"
	frsql "radius-agent/internal/source/freeradius_sql"
	frfiles "radius-agent/internal/source/freeradius_files"
	"radius-agent/internal/source"
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

	// Multi-adapter: routes each source to the right backend by Type.
	adapter := source.NewMultiAdapter(map[model.SourceType]source.Adapter{
		model.SourceFreeRadiusSQL:   frsql.New(),
		model.SourceFreeRadiusFiles: frfiles.New(),
	})

	// Control-plane client — no-op when api_base is empty.
	cp := controlplane.New(cfg.ControlPlane.APIBase, cfg.ControlPlane.Token)
	if cp.Enabled() {
		log.Printf("radius-agent: control-plane push enabled → %s", cfg.ControlPlane.APIBase)
	} else {
		log.Printf("radius-agent: control-plane push disabled (set controlplane.api_base to enable)")
	}

	engine := syncer.New(store, adapter, cp)
	resolverSvc := resolver.New(store)
	httpServer := httpapi.New(store, engine, resolverSvc)

	ctx, cancel := context.WithCancel(context.Background())

	// Log configured sources on startup.
	go func() {
		sources, _, err := store.ListSources(ctx)
		if err != nil {
			return
		}
		if len(sources) == 0 {
			log.Printf("radius-agent: нет настроенных источников. Добавьте через POST /api/admin/radius/sources или Web UI.")
			return
		}
		for _, src := range sources {
			status := "включён"
			if !src.Enabled {
				status = "выключен"
			}
			log.Printf("radius-agent: source=%s type=%s status=%s", src.ID, src.Type, status)

			// For SSH file sources, check key availability and print actionable hints.
			if src.Type == model.SourceFreeRadiusFiles && strings.HasPrefix(strings.TrimSpace(src.DSN), "ssh://") {
				sshHint(src.DSN)
			}
		}
	}()

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

// sshHint prints actionable log lines for SSH file sources.
// It never suggests running the DSN string as a command.
func sshHint(dsn string) {
	// Parse user@host from the DSN (strip ssh:// prefix and everything after the first /)
	rest := strings.TrimPrefix(dsn, "ssh://")
	// Strip query string
	if idx := strings.Index(rest, "?"); idx >= 0 {
		rest = rest[:idx]
	}
	// Strip path (everything from the first / after host)
	// URL format: user@host:port/path  or  user@host/path
	userHost := rest
	if idx := strings.Index(rest, "/"); idx >= 0 {
		userHost = rest[:idx]
	}

	// Determine the key being used
	hasExplicitKey := strings.Contains(dsn, "key=")
	home, _ := os.UserHomeDir()
	foundKey := ""
	if !hasExplicitKey {
		for _, candidate := range []string{
			filepath.Join(home, ".ssh", "id_ed25519"),
			filepath.Join(home, ".ssh", "id_rsa"),
			filepath.Join(home, ".ssh", "id_ecdsa"),
		} {
			if _, err := os.Stat(candidate); err == nil {
				foundKey = candidate
				break
			}
		}
	}

	if hasExplicitKey {
		log.Printf("radius-agent:   SSH ключ: из параметра ?key= в DSN")
	} else if foundKey != "" {
		log.Printf("radius-agent:   SSH ключ: %s (найден автоматически)", foundKey)
		log.Printf("radius-agent:   Если соединение не работает, выполните:")
		log.Printf("radius-agent:     ssh-copy-id -i %s.pub %s", foundKey, userHost)
	} else {
		log.Printf("radius-agent:   ⚠  SSH-ключ не найден. Выполните по порядку:")
		log.Printf("radius-agent:     1) ssh-keygen -t ed25519")
		log.Printf("radius-agent:     2) ssh-copy-id %s", userHost)
		log.Printf("radius-agent:   Или укажите ключ в DSN: ...?key=/home/ngfw/.ssh/id_ed25519")
	}
}
