from pathlib import Path
import sqlite3


ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "nsp/data/nsp.db"


def insert_record(rid_smd: str, s_nsp: bytes):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO smd_records (rid_smd, s_nsp) VALUES (?, ?)",
            (rid_smd, s_nsp)
        )
        conn.commit()


def get_record(rid_smd: str):
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT rid_smd, s_nsp, created_at "
            "FROM smd_records WHERE rid_smd = ?",
            (rid_smd,)
        ).fetchone()

    return row


def replace_record(old_rid: str, new_rid: str, new_s_nsp: bytes):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO smd_records (rid_smd, s_nsp) VALUES (?, ?)",
            (new_rid, new_s_nsp)
        )

        conn.execute(
            "DELETE FROM smd_records WHERE rid_smd = ?",
            (old_rid,)
        )

        conn.commit()


def delete_record(rid_smd: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "DELETE FROM smd_records WHERE rid_smd = ?",
            (rid_smd,)
        )
        conn.commit()


def count_records():
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM smd_records"
        ).fetchone()[0]
