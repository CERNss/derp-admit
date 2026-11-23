CREATE TABLE IF NOT EXISTS roles (
  name TEXT PRIMARY KEY,
  description TEXT NOT NULL DEFAULT '',
  all_relays BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS relays (
  name TEXT PRIMARY KEY,
  description TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_state (
  id INT PRIMARY KEY CHECK (id = 1),
  version BIGINT NOT NULL DEFAULT 0,
  upgraded_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS admin_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT UNIQUE NOT NULL,
  tier TEXT NOT NULL CHECK (tier IN ('viewer', 'operator', 'admin')),
  key_hash TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_admin_keys_tier ON admin_keys(tier);
CREATE INDEX IF NOT EXISTS idx_admin_keys_expires_at ON admin_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_admin_keys_revoked_at ON admin_keys(revoked_at);

CREATE TABLE IF NOT EXISTS admin_audit_logs (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_key_id UUID,
  actor_name TEXT NOT NULL,
  actor_tier TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  target_type TEXT NOT NULL DEFAULT '',
  target_id TEXT NOT NULL DEFAULT '',
  outcome TEXT NOT NULL,
  http_status INT,
  client_ip TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_ts_id ON admin_audit_logs(ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_actor_key_ts_id ON admin_audit_logs(actor_key_id, ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_action_ts_id ON admin_audit_logs(action, ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_target_ts_id ON admin_audit_logs(target_type, target_id, ts DESC, id DESC);

ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS relay TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_logs_relay_ts_id ON audit_logs(relay, ts DESC, id DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_casbin_rule ON casbin_rule (ptype, v0, v1, v2, v3, v4, v5);
