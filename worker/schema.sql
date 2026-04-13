CREATE TABLE IF NOT EXISTS allowed_users (
  vatsim_cid TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  added_at TEXT NOT NULL DEFAULT (datetime('now'))
);
