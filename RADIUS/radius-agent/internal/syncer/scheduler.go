package syncer

import (
	"context"
	"log"
	"radius-agent/internal/store"
	"time"
)

// Scheduler periodically triggers SyncSource for every enabled source,
// respecting per-source sync intervals stored in the database.
// It deduplicates log output so a persistent error is logged only when
// it first occurs or when it changes, not on every tick.
type Scheduler struct {
	store      store.Store
	engine     *Engine
	lastErr    map[string]string // sourceID → last error string
	lastSync   map[string]time.Time
}

func NewScheduler(st store.Store, eng *Engine) *Scheduler {
	return &Scheduler{
		store:    st,
		engine:   eng,
		lastErr:  map[string]string{},
		lastSync: map[string]time.Time{},
	}
}

// Run starts the scheduler loop. Checks every 10 seconds whether any
// source is due. Uses per-source sync_every_sec from the DB.
// A given source error is logged only when it first appears or changes.
func (s *Scheduler) Run(ctx context.Context, defaultInterval time.Duration) {
	if defaultInterval <= 0 {
		defaultInterval = 60 * time.Second
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			sources, intervals, err := s.store.ListSources(ctx)
			if err != nil {
				log.Printf("radius-agent scheduler: list sources: %v", err)
				continue
			}
			for _, src := range sources {
				if !src.Enabled {
					continue
				}
				iv := defaultInterval
				if sec, ok := intervals[src.ID]; ok && sec > 0 {
					iv = time.Duration(sec) * time.Second
				}

				ls, seen := s.lastSync[src.ID]
				if seen && now.Sub(ls) < iv {
					continue
				}

				if _, err := s.engine.SyncSource(ctx, src.ID); err != nil {
					friendly := friendlyError(err)
					prev := s.lastErr[src.ID]
					if prev != friendly {
						log.Printf("radius-agent scheduler: source=%s: %s", src.ID, friendly)
						s.lastErr[src.ID] = friendly
					}
					// Do NOT update lastSync on error so we retry next tick,
					// but cap retry rate at the source interval.
					s.lastSync[src.ID] = now
				} else {
					if s.lastErr[src.ID] != "" {
						log.Printf("radius-agent scheduler: source=%s: sync recovered", src.ID)
						s.lastErr[src.ID] = ""
					}
					s.lastSync[src.ID] = now
				}
			}
		}
	}
}

// friendlyError converts low-level driver errors to human-readable messages.
func friendlyError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()

	// Unknown source type from MultiAdapter
	if contains(msg, "неизвестный тип источника") {
		return msg
	}
	// SQLite CANTOPEN — modernc.org/sqlite formats it as "out of memory (14)"
	if contains(msg, "out of memory (14)") || contains(msg, "unable to open database file") {
		return "SQLite: не удалось открыть файл базы данных. Проверьте, что путь DSN существует и доступен"
	}
	// MySQL connection refused
	if contains(msg, "connection refused") && contains(msg, "3306") {
		return "MySQL: соединение отклонено (порт 3306). Проверьте, что MySQL/MariaDB запущен и DSN корректен"
	}
	// PostgreSQL connection refused
	if contains(msg, "connection refused") && contains(msg, "5432") {
		return "PostgreSQL: соединение отклонено (порт 5432). Проверьте, что PostgreSQL запущен и DSN корректен"
	}
	// Generic connection refused
	if contains(msg, "connection refused") {
		return "Соединение с СУБД отклонено. Проверьте, что СУБД запущена и DSN корректен"
	}
	// SSH errors — already formatted by the adapter's buildSSHError(); pass through.
	// Authentication errors
	if contains(msg, "Access denied") || contains(msg, "password authentication failed") {
		return "Ошибка аутентификации в СУБД. Проверьте логин/пароль в DSN"
	}
	// Unknown database
	if contains(msg, "Unknown database") || contains(msg, "does not exist") {
		return "База данных не найдена. Проверьте имя БД в DSN"
	}

	return msg
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) &&
		(s == sub || len(s) > 0 && indexInsensitive(s, sub) >= 0)
}

func indexInsensitive(s, sub string) int {
	ls, lsub := len(s), len(sub)
	if lsub == 0 {
		return 0
	}
	for i := 0; i <= ls-lsub; i++ {
		match := true
		for j := 0; j < lsub; j++ {
			cs, csub := s[i+j], sub[j]
			if cs >= 'A' && cs <= 'Z' {
				cs += 'a' - 'A'
			}
			if csub >= 'A' && csub <= 'Z' {
				csub += 'a' - 'A'
			}
			if cs != csub {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
