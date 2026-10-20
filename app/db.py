import os
import sqlite3
from pathlib import Path
from contextlib import contextmanager

DB_PATH = os.getenv('DATABASE_PATH', 'data/security.sqlite3')

@contextmanager
def connect():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def initialize():
    with connect() as db:
        db.executescript(Path(__file__).with_name('schema.sql').read_text())
        db.executescript(Path(__file__).with_name('sprint123_schema.sql').read_text())
        db.executescript(Path(__file__).with_name('sprint456_schema.sql').read_text())
