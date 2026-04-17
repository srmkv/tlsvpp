CREATE TABLE IF NOT EXISTS radius_sources (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  dsn TEXT NOT NULL,
  sync_every_sec INTEGER NOT NULL DEFAULT 60,
  description TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS radius_snapshots (
  source_id TEXT NOT NULL,
  revision TEXT NOT NULL,
  created_at TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  PRIMARY KEY (source_id, revision)
);

CREATE TABLE IF NOT EXISTS radius_group_mappings (
  group_name TEXT PRIMARY KEY,
  vpn_profile TEXT NOT NULL,
  policy_set TEXT NOT NULL,
  trust_level TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS radius_attr_mappings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attr_name TEXT NOT NULL,
  attr_value_like TEXT NOT NULL,
  session_option TEXT NOT NULL,
  target_value TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1
);
