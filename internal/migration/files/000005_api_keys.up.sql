-- 000005_api_keys.up.sql
-- Service-to-service API keys (digest for lookup + bcrypt hash for verify).
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    key_digest TEXT UNIQUE NOT NULL,
    key_hash TEXT NOT NULL,
    user_id TEXT,
    scopes TEXT,
    last_used_at TIMESTAMP,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
