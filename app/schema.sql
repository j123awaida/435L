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
