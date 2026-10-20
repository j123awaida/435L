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
