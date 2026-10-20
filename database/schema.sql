CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, full_name TEXT NOT NULL, username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','analyst','employee','auditor')),
 account_status TEXT NOT NULL DEFAULT 'Active' CHECK(account_status IN ('Active','Inactive','Suspended'))
);
CREATE TABLE IF NOT EXISTS assets (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, owner_id INTEGER NOT NULL REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
 id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL, cve_identifier TEXT NOT NULL,
 cvss_score REAL NOT NULL CHECK(cvss_score BETWEEN 0 AND 10),
 severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')),
 asset_id INTEGER NOT NULL REFERENCES assets(id), discovery_source TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open','Under Investigation','In Progress','Resolved','Closed')),
 created_at TEXT NOT NULL, resolution_date TEXT
);
CREATE TABLE IF NOT EXISTS notifications (
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL,
 message TEXT NOT NULL, notification_type TEXT NOT NULL CHECK(notification_type IN ('Incident Assignment','Security Alert','System Notification','Threat Alert','Vulnerability Alert')),
 severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')),
 status TEXT NOT NULL DEFAULT 'Unread' CHECK(status IN ('Unread','Read')), created_at TEXT NOT NULL, read_date TEXT
);
CREATE TABLE IF NOT EXISTS playbooks (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, incident_category TEXT NOT NULL,
 severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')),
 created_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actions (
 id INTEGER PRIMARY KEY, playbook_id INTEGER NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
 description TEXT NOT NULL, step_number INTEGER NOT NULL CHECK(step_number>0),
 status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending','In Progress','Completed')),
 assigned_user_id INTEGER REFERENCES users(id), completion_date TEXT, UNIQUE(playbook_id,step_number)
);
CREATE TABLE IF NOT EXISTS action_history (
 id INTEGER PRIMARY KEY, action_id INTEGER NOT NULL, playbook_id INTEGER NOT NULL,
 actor_id INTEGER NOT NULL REFERENCES users(id), old_status TEXT, new_status TEXT NOT NULL,
 assigned_user_id INTEGER REFERENCES users(id), recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), action TEXT NOT NULL,
 description TEXT NOT NULL, severity TEXT NOT NULL, related_service TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_logs BEGIN SELECT RAISE(ABORT,'Audit logs are immutable'); END;
CREATE TRIGGER IF NOT EXISTS history_no_update BEFORE UPDATE ON action_history BEGIN SELECT RAISE(ABORT,'Action history is immutable'); END;
CREATE TRIGGER IF NOT EXISTS history_no_delete BEFORE DELETE ON action_history BEGIN SELECT RAISE(ABORT,'Action history is immutable'); END;
CREATE INDEX IF NOT EXISTS vulnerability_filters ON vulnerabilities(asset_id,severity,status);
CREATE INDEX IF NOT EXISTS notification_filters ON notifications(user_id,status);

-- Transactional handoff from Service 7 to Service 8. No credentials are persisted.
CREATE TABLE IF NOT EXISTS notification_outbox (
 event_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending','Delivered')),
 attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_at TEXT NOT NULL, delivered_at TEXT
);
CREATE TABLE IF NOT EXISTS notification_receipts (
 event_id TEXT PRIMARY KEY, payload_hash TEXT NOT NULL, response_json TEXT NOT NULL
);


-- Extend Joseph's reference identities/assets without changing their existing contracts.
CREATE TABLE IF NOT EXISTS user_profiles (
 user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE, department TEXT NOT NULL,
 created_at TEXT NOT NULL, last_login_at TEXT
);
-- Tombstones preserve immutable audit/foreign-key history after account deletion.
CREATE TABLE IF NOT EXISTS deleted_users (
 user_id INTEGER PRIMARY KEY REFERENCES users(id), deleted_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS asset_profiles (
 asset_id INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
 asset_type TEXT NOT NULL CHECK(asset_type IN ('Server','Workstation','Database','Application','Network Device','Cloud Resource')),
 ip_address TEXT NOT NULL, operating_system TEXT, department TEXT NOT NULL, location TEXT NOT NULL,
 criticality TEXT NOT NULL CHECK(criticality IN ('Low','Medium','High','Critical')),
 status TEXT NOT NULL CHECK(status IN ('Active','Inactive','Under Maintenance')),
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS asset_history (
 id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL, actor_id INTEGER NOT NULL,
 action TEXT NOT NULL, snapshot_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS asset_history_no_update BEFORE UPDATE ON asset_history
 BEGIN SELECT RAISE(ABORT,'Asset history is immutable'); END;
CREATE TRIGGER IF NOT EXISTS asset_history_no_delete BEFORE DELETE ON asset_history
 BEGIN SELECT RAISE(ABORT,'Asset history is immutable'); END;
CREATE TABLE IF NOT EXISTS incidents (
 id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL, category TEXT NOT NULL,
 severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')),
 reporter_id INTEGER NOT NULL REFERENCES users(id), asset_id INTEGER NOT NULL REFERENCES assets(id),
 assigned_analyst_id INTEGER REFERENCES users(id),
 status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open','Under Investigation','Mitigated','Resolved','Closed')),
 created_at TEXT NOT NULL, resolution_date TEXT
);
CREATE TABLE IF NOT EXISTS investigation_notes (
 id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL REFERENCES incidents(id),
 analyst_id INTEGER NOT NULL REFERENCES users(id), content TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS incident_reporter ON incidents(reporter_id);
CREATE INDEX IF NOT EXISTS incident_analyst ON incidents(assigned_analyst_id);
CREATE INDEX IF NOT EXISTS incident_asset ON incidents(asset_id);


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
