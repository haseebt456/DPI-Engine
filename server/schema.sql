-- Users: dashboard accounts.
CREATE TABLE IF NOT EXISTS users (
  id             SERIAL PRIMARY KEY,
  email          TEXT UNIQUE NOT NULL,
  password_hash  TEXT NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Devices: one row per installed agent. A device belongs to exactly one
-- user (owner_user_id), enforced by a real foreign key -- if a user is
-- ever deleted, ON DELETE CASCADE removes their devices automatically
-- rather than leaving orphaned rows for the application to clean up.
CREATE TABLE IF NOT EXISTS devices (
  id                     SERIAL PRIMARY KEY,
  owner_user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name                   TEXT NOT NULL,
  pairing_code           TEXT,
  pairing_code_expires   TIMESTAMPTZ,
  api_key_hash           TEXT,
  enrolled               BOOLEAN NOT NULL DEFAULT false,
  last_seen              TIMESTAMPTZ,
  status                 TEXT NOT NULL DEFAULT 'offline' CHECK (status IN ('online', 'offline')),
  created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_devices_pairing_code ON devices(pairing_code);
CREATE INDEX IF NOT EXISTS idx_devices_owner ON devices(owner_user_id);

-- Rules: NULL device_id means "applies to every device this user owns".
-- This single nullable foreign key is what the WHERE clause in
-- getRulesForDevice() below is built around.
CREATE TABLE IF NOT EXISTS rules (
  id             SERIAL PRIMARY KEY,
  owner_user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id      INTEGER REFERENCES devices(id) ON DELETE CASCADE,
  type           TEXT NOT NULL CHECK (type IN ('domain', 'app', 'ip')),
  value          TEXT NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rules_owner ON rules(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_rules_device ON rules(device_id);

-- Events: telemetry reported by agents. device_id cascades on delete so
-- removing a device cleans up its whole event history in one statement.
CREATE TABLE IF NOT EXISTS events (
  id          SERIAL PRIMARY KEY,
  device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  domain      TEXT NOT NULL,
  action      TEXT NOT NULL CHECK (action IN ('blocked', 'forwarded')),
  timestamp   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
