"""Create development identities and assets. Never import demo users into production."""
import json
import secrets
from pathlib import Path
from app.db import initialize, connect
from app.auth import hash_password

def seed():
    initialize()
    credentials={}
    with connect() as db:
        for id,role in enumerate(('admin','analyst','employee','auditor'),1):
            if db.execute('SELECT id FROM users WHERE username=?',(role,)).fetchone():
                continue
            password=secrets.token_urlsafe(18)
            db.execute('INSERT INTO users(id,full_name,username,password_hash,role) VALUES(?,?,?,?,?)',(id,f'Demo {role.title()}',role,hash_password(password),role))
            credentials[role]=password
        db.execute("INSERT OR IGNORE INTO assets VALUES(1,'Lab server',1)")
        db.execute("INSERT OR IGNORE INTO assets VALUES(2,'Lab workstation',1)")
    if credentials:
        path=Path('data/demo-credentials.json')
        path.write_text(json.dumps(credentials,indent=2))
        path.chmod(0o600)
        print(f'Development passwords saved to {path}; this file is excluded from Git.')
    else:
        print('Existing users retained; passwords unchanged.')

if __name__=='__main__':
    seed()
