CREATE TABLE IF NOT EXISTS allowed_users (
  id TEXT PRIMARY KEY,
  auth_type TEXT NOT NULL DEFAULT 'vatsim',
  name TEXT NOT NULL,
  added_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS plugins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '1.0.0',
  is_dev INTEGER NOT NULL DEFAULT 0,
  uploader_id TEXT NOT NULL,
  uploader_name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
