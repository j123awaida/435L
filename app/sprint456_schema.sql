-- Services 4–6 (Mohammad Nasrallah). Loaded after schema.sql and sprint123_schema.sql.
-- Initialization is idempotent and never modifies existing team records.

-- Service 4: threat intelligence indicators.
-- The unique constraint rejects duplicate type/value pairs in the database itself,
-- so concurrent inserts cannot both succeed.
CREATE TABLE IF NOT EXISTS threats (
 id INTEGER PRIMARY KEY,
 threat_type TEXT NOT NULL CHECK(threat_type IN ('IP Address','Domain','File Hash','Malware Signature','Other')),
 threat_value TEXT NOT NULL,
 description TEXT NOT NULL,
 severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')),
 source TEXT NOT NULL,
 created_at TEXT NOT NULL,
 UNIQUE(threat_type, threat_value)
);
CREATE INDEX IF NOT EXISTS threat_filters ON threats(threat_type, severity, source);

-- Service 5: idempotent audit log ingestion for Services 1–3 and 7–9.
-- A replayed Idempotency-Key resolves to the log row recorded the first time,
-- so a teammate's retry cannot append a second copy of the same event.
CREATE TABLE IF NOT EXISTS log_receipts (
 idempotency_key TEXT PRIMARY KEY,
 log_id INTEGER NOT NULL REFERENCES audit_logs(id),
 payload_hash TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_filters ON audit_logs(user_id, severity, related_service);

-- Audit records must survive ingestion bookkeeping: clearing a receipt must never
-- cascade into the immutable log it points at.
CREATE TRIGGER IF NOT EXISTS log_receipt_no_update BEFORE UPDATE ON log_receipts
 BEGIN SELECT RAISE(ABORT,'Log receipts are immutable'); END;

-- Administrator deletions stay accountable: the removed identifier, the administrator who
-- removed it and the time are retained even though the record itself is gone.
--
-- Known limitation: audit_logs.id is a plain INTEGER PRIMARY KEY in Joseph's shared
-- schema.sql, so SQLite may reassign the highest deleted identifier to the next inserted
-- log. Adding AUTOINCREMENT would require recreating a table that already holds team
-- records, so the tombstone below is what proves which identifiers were deleted.
-- A surrogate AUTOINCREMENT key records every deletion in its own right, so the sequence
-- of deletions stays complete even if SQLite later reassigns a deleted log identifier.
CREATE TABLE IF NOT EXISTS log_tombstones (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 log_id INTEGER NOT NULL,
 deleted_by INTEGER NOT NULL REFERENCES users(id),
 action TEXT NOT NULL,
 recorded_at TEXT NOT NULL,
 deleted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS log_tombstone_lookup ON log_tombstones(log_id);
CREATE TRIGGER IF NOT EXISTS log_tombstone_no_update BEFORE UPDATE ON log_tombstones
 BEGIN SELECT RAISE(ABORT,'Log deletion records are immutable'); END;
CREATE TRIGGER IF NOT EXISTS log_tombstone_no_delete BEFORE DELETE ON log_tombstones
 BEGIN SELECT RAISE(ABORT,'Log deletion records are immutable'); END;
