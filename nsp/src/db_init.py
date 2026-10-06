from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "nsp/data/nsp.db"

DB_PATH.parent.mkdir(parents=True, exist_ok=True)

with sqlite3.connect(DB_PATH) as conn:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS smd_records (
            rid_smd TEXT PRIMARY KEY,
            s_nsp   BLOB NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()

DB_PATH.chmod(0o600)

with sqlite3.connect(DB_PATH) as conn:
    tables = conn.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type='table' AND name='smd_records'
    """).fetchall()

    count = conn.execute(
        "SELECT COUNT(*) FROM smd_records"
    ).fetchone()[0]

print("Database:", DB_PATH)
print("Table:", tables[0][0] if tables else "NOT FOUND")
print("Stored SMD records:", count)
print("Permissions:", oct(DB_PATH.stat().st_mode & 0o777))
print("STATUS: NSP DATABASE READY")
