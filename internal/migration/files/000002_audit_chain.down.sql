-- 000002_audit_chain.down.sql
ALTER TABLE audit_logs DROP COLUMN hash;
ALTER TABLE audit_logs DROP COLUMN prev_hash;
