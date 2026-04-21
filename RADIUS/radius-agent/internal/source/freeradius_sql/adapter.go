package freeradius_sql

import (
	"context"
	"database/sql"
	"fmt"
	"os"
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
	if driver == "sqlite" {
		if err := checkSQLitePath(src.DSN); err != nil {
			return err
		}
	}
	db, err := sql.Open(driver, src.DSN)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.PingContext(ctx)
}

func (a *Adapter) LoadSnapshot(ctx context.Context, src model.Source) (*model.Snapshot, error) {
	driver := detectDriver(src.DSN)

	// For SQLite, check path existence before trying to open so the error
	// message is clear instead of the confusing "out of memory (14)" from
	// modernc.org/sqlite when CANTOPEN (code 14) is returned.
	if driver == "sqlite" {
		if err := checkSQLitePath(src.DSN); err != nil {
			return nil, err
		}
	}

	db, err := sql.Open(driver, src.DSN)
	if err != nil {
		return nil, fmt.Errorf("open %s db: %w", driver, err)
	}
	defer db.Close()

	// Ping once to give a clear error before running queries
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("connect to %s db: %w", driver, friendlyDriverError(driver, err))
	}

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

// checkSQLitePath validates that the DSN path for a SQLite source actually
// exists as a file. This replaces the confusing "out of memory (14)" error
// (which is SQLite error code 14 = CANTOPEN) with a clear message.
func checkSQLitePath(dsn string) error {
	// Strip query string parameters (e.g. "?_journal_mode=WAL")
	path := dsn
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}
	path = strings.TrimSpace(path)

	// In-memory DBs are always valid
	if path == ":memory:" || strings.HasPrefix(path, "file::memory:") {
		return nil
	}

	// Strip "file:" URI prefix if present
	if strings.HasPrefix(path, "file:") {
		path = strings.TrimPrefix(path, "file:")
		// Strip query from URI form too
		if idx := strings.Index(path, "?"); idx >= 0 {
			path = path[:idx]
		}
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf(
			"SQLite: файл базы данных не найден: %q\n"+
				"Проверьте DSN в настройках источника. Для FreeRADIUS SQLite обычно путь выглядит как\n"+
				"/var/lib/radiusd/sqlite/radius.db или аналогичный.",
			path,
		)
	}
	return nil
}

// friendlyDriverError wraps low-level driver errors with readable messages.
func friendlyDriverError(driver string, err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch driver {
	case "sqlite":
		if strings.Contains(msg, "out of memory (14)") || strings.Contains(msg, "unable to open") {
			return fmt.Errorf("SQLite CANTOPEN (код 14): невозможно открыть файл базы данных")
		}
	case "mysql":
		if strings.Contains(msg, "connection refused") {
			return fmt.Errorf("MySQL: соединение отклонено — убедитесь, что MySQL запущен и DSN корректен")
		}
		if strings.Contains(msg, "Access denied") {
			return fmt.Errorf("MySQL: доступ запрещён — проверьте логин/пароль в DSN")
		}
	case "postgres":
		if strings.Contains(msg, "connection refused") {
			return fmt.Errorf("PostgreSQL: соединение отклонено — убедитесь, что PostgreSQL запущен и DSN корректен")
		}
		if strings.Contains(msg, "password authentication failed") {
			return fmt.Errorf("PostgreSQL: ошибка аутентификации — проверьте логин/пароль в DSN")
		}
	}
	return err
}
