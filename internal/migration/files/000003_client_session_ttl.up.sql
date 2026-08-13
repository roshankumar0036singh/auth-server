-- 000003_client_session_ttl.up.sql
-- Per-client session TTL overrides (0 = global default).
ALTER TABLE oauth_clients ADD COLUMN access_token_ttl_seconds INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oauth_clients ADD COLUMN refresh_token_ttl_seconds INTEGER NOT NULL DEFAULT 0;
