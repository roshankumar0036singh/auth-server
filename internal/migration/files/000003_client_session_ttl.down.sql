-- 000003_client_session_ttl.down.sql
ALTER TABLE oauth_clients DROP COLUMN refresh_token_ttl_seconds;
ALTER TABLE oauth_clients DROP COLUMN access_token_ttl_seconds;
