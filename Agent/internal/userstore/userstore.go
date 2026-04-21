// Package userstore provides a SQLite-backed store for Agent persistent state.
// It replaces the previous approach of multiple JSON files (users.json,
// users-meta.json, profiles.json, shards.json, shard_placements.json) which
// suffered from race conditions and no atomic multi-field updates.
package userstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"tlsctrl-agent/internal/model"
)

// Store is the interface for all persistent Agent state.
type Store interface {
	// Users
	UpsertUser(ctx context.Context, u StoredUser) error
	GetUser(ctx context.Context, username string) (StoredUser, error)
	ListUsers(ctx context.Context) ([]StoredUser, error)
	DeleteUser(ctx context.Context, username string) error

	// VPN Profiles
	UpsertProfile(ctx context.Context, p model.VPNProfile) error
	GetProfile(ctx context.Context, name string) (model.VPNProfile, error)
	ListProfiles(ctx context.Context) ([]model.VPNProfile, error)
	DeleteProfile(ctx context.Context, name string) error

	// Shards
	UpsertShard(ctx context.Context, s model.ShardNode) error
	ListShards(ctx context.Context) ([]model.ShardNode, error)
	DeleteShard(ctx context.Context, name string) error

	// Shard Placements
	SetPlacement(ctx context.Context, p model.ShardPlacement) error
	GetPlacement(ctx context.Context, username string) (model.ShardPlacement, error)
	ListPlacements(ctx context.Context) ([]model.ShardPlacement, error)
	DeletePlacement(ctx context.Context, username string) error

	Close() error
}

// StoredUser is the unified user record (merges the old persistedUser + userMeta).
type StoredUser struct {
	Username    string
	CertSerial  string
	Enabled     bool
	Profile     string
	Email       string
	Require2FA  bool
	Last2FAAt   time.Time
	RadiusSource string // set when imported from RADIUS, empty for manual users
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ToModel converts StoredUser to model.User for API responses.
func (u StoredUser) ToModel() model.User {
	status := "disabled"
	if u.Require2FA {
		if !u.Last2FAAt.IsZero() {
			status = "2fa_ok"
		} else {
			status = "2fa_pending"
		}
	} else if u.Enabled {
		status = "ok"
	}
	return model.User{
		Username:    u.Username,
		CertSerial:  u.CertSerial,
		Enabled:     u.Enabled,
		Profile:     u.Profile,
		Email:       u.Email,
		Require2FA:  u.Require2FA,
		Last2FAAt:   u.Last2FAAt,
		TwoFAStatus: status,
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
	}
}

// sqliteStore is the SQLite implementation of Store.
type sqliteStore struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
  username     TEXT    PRIMARY KEY,
  cert_serial  TEXT    NOT NULL DEFAULT '',
  enabled      INTEGER NOT NULL DEFAULT 1,
  profile      TEXT    NOT NULL DEFAULT 'default',
  email        TEXT    NOT NULL DEFAULT '',
  require_2fa  INTEGER NOT NULL DEFAULT 0,
  last_2fa_at  TEXT    NOT NULL DEFAULT '',
  radius_source TEXT   NOT NULL DEFAULT '',
  created_at   TEXT    NOT NULL,
  updated_at   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS vpn_profiles (
  name           TEXT    PRIMARY KEY,
  pool_name      TEXT    NOT NULL DEFAULT '',
  pool_subnet    TEXT    NOT NULL DEFAULT '',
  pool_gateway   TEXT    NOT NULL DEFAULT '',
  lease_seconds  INTEGER NOT NULL DEFAULT 0,
  full_tunnel    INTEGER NOT NULL DEFAULT 0,
  dns_servers    TEXT    NOT NULL DEFAULT '',
  include_routes TEXT    NOT NULL DEFAULT '',
  exclude_routes TEXT    NOT NULL DEFAULT '',
  mtu            INTEGER NOT NULL DEFAULT 1400,
  mss_clamp      INTEGER NOT NULL DEFAULT 0,
  note           TEXT    NOT NULL DEFAULT '',
  updated_at     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS shards (
  name              TEXT    PRIMARY KEY,
  client_public_url TEXT    NOT NULL DEFAULT '',
  server_name       TEXT    NOT NULL DEFAULT '',
  enabled           INTEGER NOT NULL DEFAULT 1,
  weight            INTEGER NOT NULL DEFAULT 1,
  capacity_hint     INTEGER NOT NULL DEFAULT 0,
  updated_at        TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS shard_placements (
  username          TEXT    PRIMARY KEY,
  shard_name        TEXT    NOT NULL,
  client_public_url TEXT    NOT NULL DEFAULT '',
  server_name       TEXT    NOT NULL DEFAULT '',
  assigned_at       TEXT    NOT NULL,
  updated_at        TEXT    NOT NULL
);
`

// Open opens (or creates) the SQLite store at path.
func Open(path string) (Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("userstore mkdir: %w", err)
	}
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("userstore open: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite WAL handles readers; single writer avoids lock contention
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("userstore migrate: %w", err)
	}
	return &sqliteStore{db: db}, nil
}

func (s *sqliteStore) Close() error { return s.db.Close() }

// --- Users ---

func (s *sqliteStore) UpsertUser(ctx context.Context, u StoredUser) error {
	u.Username = strings.ToLower(strings.TrimSpace(u.Username))
	if u.Username == "" {
		return errors.New("username is required")
	}
	if u.Profile == "" {
		u.Profile = "default"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	last2fa := ""
	if !u.Last2FAAt.IsZero() {
		last2fa = u.Last2FAAt.UTC().Format(time.RFC3339)
	}
	createdAt := now
	// Preserve original created_at if the row already exists
	var existing string
	row := s.db.QueryRowContext(ctx, `SELECT created_at FROM users WHERE username=?`, u.Username)
	if err := row.Scan(&existing); err == nil && existing != "" {
		createdAt = existing
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO users(username,cert_serial,enabled,profile,email,require_2fa,last_2fa_at,radius_source,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(username) DO UPDATE SET
  cert_serial   = excluded.cert_serial,
  enabled       = excluded.enabled,
  profile       = excluded.profile,
  email         = excluded.email,
  require_2fa   = excluded.require_2fa,
  last_2fa_at   = excluded.last_2fa_at,
  radius_source = excluded.radius_source,
  updated_at    = excluded.updated_at`,
		u.Username, u.CertSerial, boolInt(u.Enabled), u.Profile,
		u.Email, boolInt(u.Require2FA), last2fa, u.RadiusSource, createdAt, now)
	return err
}

func (s *sqliteStore) GetUser(ctx context.Context, username string) (StoredUser, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	row := s.db.QueryRowContext(ctx, `
SELECT username,cert_serial,enabled,profile,email,require_2fa,last_2fa_at,radius_source,created_at,updated_at
FROM users WHERE username=?`, username)
	return scanUser(row)
}

func (s *sqliteStore) ListUsers(ctx context.Context) ([]StoredUser, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT username,cert_serial,enabled,profile,email,require_2fa,last_2fa_at,radius_source,created_at,updated_at
FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredUser
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *sqliteStore) DeleteUser(ctx context.Context, username string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE username=?`, strings.ToLower(strings.TrimSpace(username)))
	return err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (StoredUser, error) {
	var u StoredUser
	var enabledInt, require2faInt int
	var last2faStr, createdStr, updatedStr string
	err := row.Scan(
		&u.Username, &u.CertSerial, &enabledInt, &u.Profile,
		&u.Email, &require2faInt, &last2faStr, &u.RadiusSource,
		&createdStr, &updatedStr,
	)
	if err != nil {
		return StoredUser{}, err
	}
	u.Enabled = enabledInt == 1
	u.Require2FA = require2faInt == 1
	if last2faStr != "" {
		if t, err := time.Parse(time.RFC3339, last2faStr); err == nil {
			u.Last2FAAt = t.UTC()
		}
	}
	if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
		u.CreatedAt = t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, updatedStr); err == nil {
		u.UpdatedAt = t.UTC()
	}
	return u, nil
}

// --- VPN Profiles ---

func (s *sqliteStore) UpsertProfile(ctx context.Context, p model.VPNProfile) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO vpn_profiles(name,pool_name,pool_subnet,pool_gateway,lease_seconds,full_tunnel,dns_servers,include_routes,exclude_routes,mtu,mss_clamp,note,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(name) DO UPDATE SET
  pool_name=excluded.pool_name, pool_subnet=excluded.pool_subnet, pool_gateway=excluded.pool_gateway,
  lease_seconds=excluded.lease_seconds, full_tunnel=excluded.full_tunnel,
  dns_servers=excluded.dns_servers, include_routes=excluded.include_routes, exclude_routes=excluded.exclude_routes,
  mtu=excluded.mtu, mss_clamp=excluded.mss_clamp, note=excluded.note, updated_at=excluded.updated_at`,
		p.Name, p.PoolName, p.PoolSubnet, p.PoolGateway, p.LeaseSeconds,
		boolInt(p.FullTunnel), p.DNSServers, p.IncludeRoutes, p.ExcludeRoutes,
		p.MTU, p.MSSClamp, p.Note, now)
	return err
}

func (s *sqliteStore) GetProfile(ctx context.Context, name string) (model.VPNProfile, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT name,pool_name,pool_subnet,pool_gateway,lease_seconds,full_tunnel,dns_servers,include_routes,exclude_routes,mtu,mss_clamp,note,updated_at
FROM vpn_profiles WHERE name=?`, name)
	return scanProfile(row)
}

func (s *sqliteStore) ListProfiles(ctx context.Context) ([]model.VPNProfile, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT name,pool_name,pool_subnet,pool_gateway,lease_seconds,full_tunnel,dns_servers,include_routes,exclude_routes,mtu,mss_clamp,note,updated_at
FROM vpn_profiles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.VPNProfile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *sqliteStore) DeleteProfile(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM vpn_profiles WHERE name=?`, name)
	return err
}

func scanProfile(row scanner) (model.VPNProfile, error) {
	var p model.VPNProfile
	var fullTunnelInt int
	var updatedStr string
	err := row.Scan(&p.Name, &p.PoolName, &p.PoolSubnet, &p.PoolGateway, &p.LeaseSeconds,
		&fullTunnelInt, &p.DNSServers, &p.IncludeRoutes, &p.ExcludeRoutes,
		&p.MTU, &p.MSSClamp, &p.Note, &updatedStr)
	if err != nil {
		return model.VPNProfile{}, err
	}
	p.FullTunnel = fullTunnelInt == 1
	if t, err := time.Parse(time.RFC3339, updatedStr); err == nil {
		p.UpdatedAt = t.UTC()
	}
	return p, nil
}

// --- Shards ---

func (s *sqliteStore) UpsertShard(ctx context.Context, sn model.ShardNode) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO shards(name,client_public_url,server_name,enabled,weight,capacity_hint,updated_at)
VALUES(?,?,?,?,?,?,?)
ON CONFLICT(name) DO UPDATE SET
  client_public_url=excluded.client_public_url, server_name=excluded.server_name,
  enabled=excluded.enabled, weight=excluded.weight, capacity_hint=excluded.capacity_hint, updated_at=excluded.updated_at`,
		sn.Name, sn.ClientPublicURL, sn.ServerName, boolInt(sn.Enabled), sn.Weight, sn.CapacityHint, now)
	return err
}

func (s *sqliteStore) ListShards(ctx context.Context) ([]model.ShardNode, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT name,client_public_url,server_name,enabled,weight,capacity_hint,updated_at
FROM shards ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ShardNode
	for rows.Next() {
		var sn model.ShardNode
		var enabledInt int
		var updatedStr string
		if err := rows.Scan(&sn.Name, &sn.ClientPublicURL, &sn.ServerName, &enabledInt, &sn.Weight, &sn.CapacityHint, &updatedStr); err != nil {
			return nil, err
		}
		sn.Enabled = enabledInt == 1
		if t, err := time.Parse(time.RFC3339, updatedStr); err == nil {
			sn.UpdatedAt = t.UTC()
		}
		out = append(out, sn)
	}
	return out, rows.Err()
}

func (s *sqliteStore) DeleteShard(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM shards WHERE name=?`, name)
	return err
}

// --- Shard Placements ---

func (s *sqliteStore) SetPlacement(ctx context.Context, p model.ShardPlacement) error {
	now := time.Now().UTC().Format(time.RFC3339)
	assignedAt := now
	if !p.AssignedAt.IsZero() {
		assignedAt = p.AssignedAt.UTC().Format(time.RFC3339)
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO shard_placements(username,shard_name,client_public_url,server_name,assigned_at,updated_at)
VALUES(?,?,?,?,?,?)
ON CONFLICT(username) DO UPDATE SET
  shard_name=excluded.shard_name, client_public_url=excluded.client_public_url,
  server_name=excluded.server_name, updated_at=excluded.updated_at`,
		strings.ToLower(strings.TrimSpace(p.Username)),
		p.ShardName, p.ClientPublicURL, p.ServerName, assignedAt, now)
	return err
}

func (s *sqliteStore) GetPlacement(ctx context.Context, username string) (model.ShardPlacement, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	row := s.db.QueryRowContext(ctx, `
SELECT username,shard_name,client_public_url,server_name,assigned_at,updated_at
FROM shard_placements WHERE username=?`, username)
	return scanPlacement(row)
}

func (s *sqliteStore) ListPlacements(ctx context.Context) ([]model.ShardPlacement, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT username,shard_name,client_public_url,server_name,assigned_at,updated_at
FROM shard_placements ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ShardPlacement
	for rows.Next() {
		p, err := scanPlacement(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *sqliteStore) DeletePlacement(ctx context.Context, username string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM shard_placements WHERE username=?`,
		strings.ToLower(strings.TrimSpace(username)))
	return err
}

func scanPlacement(row scanner) (model.ShardPlacement, error) {
	var p model.ShardPlacement
	var assignedStr, updatedStr string
	err := row.Scan(&p.Username, &p.ShardName, &p.ClientPublicURL, &p.ServerName, &assignedStr, &updatedStr)
	if err != nil {
		return model.ShardPlacement{}, err
	}
	if t, err := time.Parse(time.RFC3339, assignedStr); err == nil {
		p.AssignedAt = t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, updatedStr); err == nil {
		p.UpdatedAt = t.UTC()
	}
	return p, nil
}

// MigrateFromJSON imports users from old JSON-file format into the store.
// Call once on first startup if users.json or profiles.json exists.
func MigrateFromJSON(ctx context.Context, st Store, usersJSON, metaJSON, profilesJSON []byte) error {
	// This function is intentionally a no-op placeholder - migration logic
	// can be added if upgrading from the old JSON-file Agent.
	_ = usersJSON
	_ = metaJSON
	_ = profilesJSON
	return nil
}

// --- helpers ---

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// SortedUsernames returns usernames from the user list sorted alphabetically.
func SortedUsernames(users []StoredUser) []string {
	names := make([]string, len(users))
	for i, u := range users {
		names[i] = u.Username
	}
	sort.Strings(names)
	return names
}
