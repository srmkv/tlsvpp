package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"radius-agent/internal/model"
)

type Store struct{ db *sql.DB }

func New(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, migration001)
	return err
}

func (s *Store) UpsertSource(ctx context.Context, src model.Source, syncEverySec int) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO radius_sources(id,name,type,enabled,dsn,sync_every_sec,description,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,datetime('now'),datetime('now'))
ON CONFLICT(id) DO UPDATE SET
  name=excluded.name,
  type=excluded.type,
  enabled=excluded.enabled,
  dsn=excluded.dsn,
  sync_every_sec=excluded.sync_every_sec,
  description=excluded.description,
  updated_at=datetime('now')`,
		src.ID, src.Name, string(src.Type), boolToInt(src.Enabled), src.DSN, syncEverySec, src.Description)
	return err
}

func (s *Store) ListSources(ctx context.Context) ([]model.Source, map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,type,enabled,dsn,sync_every_sec,description FROM radius_sources ORDER BY name,id`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []model.Source
	intervals := map[string]int{}
	for rows.Next() {
		var src model.Source
		var enabled, syncEvery int
		var typ string
		if err := rows.Scan(&src.ID, &src.Name, &typ, &enabled, &src.DSN, &syncEvery, &src.Description); err != nil {
			return nil, nil, err
		}
		src.Type = model.SourceType(typ)
		src.Enabled = enabled == 1
		out = append(out, src)
		intervals[src.ID] = syncEvery
	}
	return out, intervals, rows.Err()
}

func (s *Store) GetSource(ctx context.Context, sourceID string) (*model.Source, int, error) {
	var src model.Source
	var enabled, syncEvery int
	var typ string
	err := s.db.QueryRowContext(ctx, `SELECT id,name,type,enabled,dsn,sync_every_sec,description FROM radius_sources WHERE id=?`, sourceID).
		Scan(&src.ID, &src.Name, &typ, &enabled, &src.DSN, &syncEvery, &src.Description)
	if err != nil {
		return nil, 0, err
	}
	src.Type = model.SourceType(typ)
	src.Enabled = enabled == 1
	return &src, syncEvery, nil
}

func (s *Store) SaveSnapshot(ctx context.Context, sourceID string, snap *model.Snapshot) error {
	payload, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	// INSERT OR IGNORE: the revision hash is derived from stable content, so
	// if the revision already exists the data is identical — no need to re-store.
	// This prevents unbounded table growth on unchanged RADIUS data.
	_, err = s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO radius_snapshots(source_id,revision,created_at,payload_json) VALUES(?,?,datetime('now'),?)`,
		sourceID, snap.Revision, string(payload))
	return err
}

func (s *Store) GetLatestSnapshot(ctx context.Context, sourceID string) (*model.Snapshot, error) {
	var payload string
	err := s.db.QueryRowContext(ctx, `SELECT payload_json FROM radius_snapshots WHERE source_id=? ORDER BY created_at DESC LIMIT 1`, sourceID).Scan(&payload)
	if err != nil {
		return nil, err
	}
	var snap model.Snapshot
	if err := json.Unmarshal([]byte(payload), &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

func (s *Store) SaveGroupMappings(ctx context.Context, items []model.GroupMapping) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM radius_group_mappings`); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := tx.ExecContext(ctx, `INSERT INTO radius_group_mappings(group_name,vpn_profile,policy_set,trust_level,enabled) VALUES(?,?,?,?,?)`, item.GroupName, item.VPNProfile, item.PolicySet, item.TrustLevel, boolToInt(item.Enabled)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListGroupMappings(ctx context.Context) ([]model.GroupMapping, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT group_name,vpn_profile,policy_set,trust_level,enabled FROM radius_group_mappings ORDER BY group_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.GroupMapping
	for rows.Next() {
		var item model.GroupMapping
		var enabled int
		if err := rows.Scan(&item.GroupName, &item.VPNProfile, &item.PolicySet, &item.TrustLevel, &enabled); err != nil {
			return nil, err
		}
		item.Enabled = enabled == 1
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) SaveAttrMappings(ctx context.Context, items []model.AttrMapping) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM radius_attr_mappings`); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := tx.ExecContext(ctx, `INSERT INTO radius_attr_mappings(attr_name,attr_value_like,session_option,target_value,enabled) VALUES(?,?,?,?,?)`, item.AttrName, item.AttrValueLike, item.SessionOption, item.TargetValue, boolToInt(item.Enabled)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListAttrMappings(ctx context.Context) ([]model.AttrMapping, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,attr_name,attr_value_like,session_option,target_value,enabled FROM radius_attr_mappings ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AttrMapping
	for rows.Next() {
		var item model.AttrMapping
		var enabled int
		if err := rows.Scan(&item.ID, &item.AttrName, &item.AttrValueLike, &item.SessionOption, &item.TargetValue, &enabled); err != nil {
			return nil, err
		}
		item.Enabled = enabled == 1
		out = append(out, item)
	}
	return out, rows.Err()
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

var _ interface{ Close() error } = (*Store)(nil)
