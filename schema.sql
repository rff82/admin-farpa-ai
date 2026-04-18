-- schema.sql — admin-farpa-ai-db (Identity Provider)
-- farpa.ai · admin · v0.1 · 2026-04-18
-- OAuth 2.1 Best Practices + OIDC Core 1.0

-- ─────────────────────────────────────────────────────────────
-- USERS — identidades globais do ecossistema
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id              TEXT PRIMARY KEY,               -- uuid v4
  email           TEXT UNIQUE NOT NULL,
  email_verified  INTEGER NOT NULL DEFAULT 0,
  name            TEXT,
  picture_url     TEXT,
  provider        TEXT NOT NULL,                  -- 'google' | 'apple' | 'microsoft' | 'local'
  provider_sub    TEXT NOT NULL,                  -- subject único no IdP upstream
  mfa_enabled     INTEGER NOT NULL DEFAULT 0,
  mfa_secret      TEXT,                           -- TOTP base32, criptografado com SESSION_COOKIE_SECRET
  last_login_at   INTEGER,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE(provider, provider_sub)
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ─────────────────────────────────────────────────────────────
-- CLIENTS — um por produto (farpa.ai, labs, health, forte…)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS clients (
  client_id           TEXT PRIMARY KEY,           -- id público, ex: "farpa-forte"
  client_secret_hash  TEXT NOT NULL,              -- argon2id
  name                TEXT NOT NULL,              -- "farpa Forte"
  redirect_uris       TEXT NOT NULL,              -- JSON array
  scopes              TEXT NOT NULL,              -- JSON array: ["openid","profile","email"]
  grant_types         TEXT NOT NULL DEFAULT '["authorization_code","refresh_token"]',
  token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic',
  require_pkce        INTEGER NOT NULL DEFAULT 1,
  is_active           INTEGER NOT NULL DEFAULT 1,
  created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ─────────────────────────────────────────────────────────────
-- SESSIONS — cookie admin_sid (SameSite=None; Partitioned)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
  id           TEXT PRIMARY KEY,                  -- opaque random 32B hex
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_agent   TEXT,
  ip_hash      TEXT,                              -- sha256(ip+salt) — nunca IP puro
  expires_at   INTEGER NOT NULL,
  created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  revoked_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- ─────────────────────────────────────────────────────────────
-- AUTHORIZATION CODES — TTL curto, single-use, PKCE bound
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS authorization_codes (
  code                   TEXT PRIMARY KEY,
  client_id              TEXT NOT NULL REFERENCES clients(client_id),
  user_id                TEXT NOT NULL REFERENCES users(id),
  redirect_uri           TEXT NOT NULL,
  scopes                 TEXT NOT NULL,            -- JSON array
  code_challenge         TEXT NOT NULL,            -- RFC 7636
  code_challenge_method  TEXT NOT NULL DEFAULT 'S256',
  nonce                  TEXT,                     -- OIDC replay protection
  state                  TEXT,
  expires_at             INTEGER NOT NULL,         -- ≤ now + 60s
  used_at                INTEGER,
  created_at             INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON authorization_codes(expires_at);

-- ─────────────────────────────────────────────────────────────
-- REFRESH TOKENS — rotação obrigatória (reuse detection)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id             TEXT PRIMARY KEY,
  token_hash     TEXT UNIQUE NOT NULL,            -- sha256(token)
  client_id      TEXT NOT NULL REFERENCES clients(client_id),
  user_id        TEXT NOT NULL REFERENCES users(id),
  session_id     TEXT REFERENCES sessions(id),
  scopes         TEXT NOT NULL,
  family_id      TEXT NOT NULL,                   -- detecta reuse: um family = uma chain
  parent_id      TEXT,                            -- id do token que originou este (para rotação)
  expires_at     INTEGER NOT NULL,
  revoked_at     INTEGER,
  created_at     INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_rt_family ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_rt_user ON refresh_tokens(user_id);

-- ─────────────────────────────────────────────────────────────
-- AUDIT LOG — sem PII (nunca email/token), só IDs opacos
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  event       TEXT NOT NULL,                     -- 'login.ok', 'login.fail', 'token.issued', 'token.reuse_detected'…
  user_id     TEXT,
  client_id   TEXT,
  ip_hash     TEXT,
  ua_hash     TEXT,
  details     TEXT,                              -- JSON sem PII
  at          INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id, at);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event, at);
