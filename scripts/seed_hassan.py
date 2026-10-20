"""Seed development accounts/assets without overwriting existing team records."""
import json
import secrets
from pathlib import Path
from app.auth import hash_password, now
from app.db import connect, initialize

def main():
    initialize()
    path = Path('data/demo-credentials.json')
    credentials = json.loads(path.read_text()) if path.exists() else {}
    changed = False
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        for role in ('admin', 'analyst', 'employee', 'auditor'):
            if not db.execute('SELECT 1 FROM users WHERE username=?', (role,)).fetchone():
                password = secrets.token_urlsafe(18)
                db.execute('INSERT INTO users(full_name,username,password_hash,role) VALUES(?,?,?,?)',
                           (f'Demo {role.title()}', role, hash_password(password), role))
                credentials[role] = password
                changed = True
        for row in db.execute("SELECT id,username FROM users WHERE username IN ('admin','analyst','employee','auditor')").fetchall():
            db.execute('INSERT OR IGNORE INTO user_profiles(user_id,email,department,created_at) VALUES(?,?,?,?)',
                       (row['id'], row['username'] + '@example.test', 'Security Lab', now()))
        admin_id = db.execute("SELECT id FROM users WHERE username='admin'").fetchone()[0]
        for name, kind, address in [('Lab server', 'Server', '192.0.2.1'), ('Lab workstation', 'Workstation', '192.0.2.2')]:
            row = db.execute('SELECT id FROM assets WHERE name=? ORDER BY id LIMIT 1', (name,)).fetchone()
            if row is None:
                next_id = db.execute('SELECT COALESCE(MAX(id),0)+1 FROM (SELECT id FROM assets UNION ALL SELECT asset_id AS id FROM asset_history)').fetchone()[0]
                db.execute('INSERT INTO assets(id,name,owner_id) VALUES(?,?,?)', (next_id, name, admin_id))
                asset_id = next_id
            else:
                asset_id = row['id']
            db.execute('''INSERT OR IGNORE INTO asset_profiles(asset_id,asset_type,ip_address,department,location,criticality,status,created_at)
                          VALUES(?,?,?,?,?,?,?,?)''',
                       (asset_id, kind, address, 'Security Lab', 'Lab', 'High', 'Active', now()))
    if changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(credentials, indent=2))
        path.chmod(0o600)
        print('Development passwords saved to ignored data/demo-credentials.json; existing credentials retained.')
    print('Services 1–3 development metadata initialized; existing metadata retained.')

if __name__ == '__main__':
    main()
