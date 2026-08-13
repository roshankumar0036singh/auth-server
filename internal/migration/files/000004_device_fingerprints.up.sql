-- 000004_device_fingerprints.up.sql
-- Device fingerprints for new-device alerts.
CREATE TABLE IF NOT EXISTS device_fingerprints (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    hash TEXT NOT NULL,
    user_agent_preview TEXT,
    ip_subnet TEXT,
    first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_device_fingerprints_user ON device_fingerprints (user_id);
