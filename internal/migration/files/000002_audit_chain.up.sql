-- 000002_audit_chain.up.sql
-- Adds the tamper-evident hash chain columns to audit_logs.
ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_logs ADD COLUMN hash TEXT;
