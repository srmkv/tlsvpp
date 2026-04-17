package freeradius_sql

import (
	"context"
	"database/sql"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
	"radius-agent/internal/model"
)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Ping(ctx context.Context, src model.Source) error {
	driver := detectDriver(src.DSN)
	db, err := sql.Open(driver, src.DSN)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.PingContext(ctx)
}

func (a *Adapter) LoadSnapshot(ctx context.Context, src model.Source) (*model.Snapshot, error) {
	driver := detectDriver(src.DSN)
	db, err := sql.Open(driver, src.DSN)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return loadSnapshot(ctx, db, src)
}

func detectDriver(dsn string) string {
	v := strings.ToLower(strings.TrimSpace(dsn))
	switch {
	case strings.HasPrefix(v, "postgres://"), strings.HasPrefix(v, "postgresql://"):
		return "postgres"
	case strings.Contains(v, "@tcp("), strings.Contains(v, "@unix("), strings.HasPrefix(v, "mysql://"):
		return "mysql"
	default:
		return "sqlite"
	}
}
