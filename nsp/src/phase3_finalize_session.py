from pathlib import Path
import base64
import hashlib
import hmac
import json
import sqlite3
import struct


ROOT = Path(__file__).resolve().parents[2]

ACK_PATH = ROOT / "nsp/import/phase3_ack.json"
PENDING_PATH = ROOT / "nsp/data/phase3_response_pending.json"
DB_PATH = ROOT / "nsp/data/nsp.db"
RESULT_PATH = ROOT / "nsp/data/phase3_session_complete.json"


def enc_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def h_fields(*fields: bytes) -> bytes:
    h = hashlib.sha256()

    for field in fields:
        h.update(enc_field(field))

    return h.digest()


def main():
    if RESULT_PATH.exists():
        existing = json.loads(
            RESULT_PATH.read_text()
        )

        if existing.get("status") == "PHASE3_COMPLETED":
            print("STATUS: PHASE 3 ALREADY COMPLETED")
            print(
                "Session key SHA256:",
                existing["session_key_sha256"],
            )
            return

        raise RuntimeError(
            "Existing Phase 3 result has unexpected state"
        )

    pending = json.loads(
        PENDING_PATH.read_text()
    )

    if pending.get("status") != "WAITING_FOR_SMD_V2":
        raise RuntimeError(
            "NSP is not waiting for V2_SMD"
        )

    ack = json.loads(
        ACK_PATH.read_text()
    )

    v2_text = ack.get("v2_smd")

    if not v2_text:
        raise RuntimeError(
            "V2_SMD missing"
        )

    v2_smd = base64.urlsafe_b64decode(
        v2_text.encode("ascii")
    )

    if len(v2_smd) != 32:
        raise RuntimeError(
            "V2_SMD must be 32 bytes"
        )

    eid_smd = pending["eid_smd"]

    rid_new = base64.urlsafe_b64decode(
        pending["rid_new"].encode("ascii")
    )

    if len(rid_new) != 32:
        raise RuntimeError(
            "RID_new must be 32 bytes"
        )

    session_key = base64.urlsafe_b64decode(
        pending["session_key"].encode("ascii")
    )

    if len(session_key) != 32:
        raise RuntimeError(
            "SK_NSP must be 32 bytes"
        )







    expected_v2 = h_fields(
        eid_smd.encode("utf-8"),
        rid_new,
        session_key,
    )

    v2_ok = hmac.compare_digest(
        expected_v2,
        v2_smd,
    )

    print("V2_SMD verification:", v2_ok)

    if not v2_ok:
        raise RuntimeError(
            "Final SMD acknowledgement verification failed"
        )

    old_rid = pending["old_rid_smd"]
    new_rid = pending["rid_new"]








    conn = sqlite3.connect(DB_PATH)

    try:
        old_before = conn.execute(
            """
            SELECT COUNT(*)
            FROM smd_records
            WHERE rid_smd = ?
            """,
            (old_rid,),
        ).fetchone()[0]

        new_before = conn.execute(
            """
            SELECT COUNT(*)
            FROM smd_records
            WHERE rid_smd = ?
            """,
            (new_rid,),
        ).fetchone()[0]

        print("Old RID before deletion:", old_before)
        print("New RID present:", new_before == 1)

        if new_before != 1:
            raise RuntimeError(
                "New RID record is missing; refusing to delete old state"
            )

        if old_before == 1:
            conn.execute(
                """
                DELETE FROM smd_records
                WHERE rid_smd = ?
                """,
                (old_rid,),
            )
            conn.commit()
            deletion_result = "DELETED"

        elif old_before == 0:


            deletion_result = "ALREADY_ABSENT"

        else:
            raise RuntimeError(
                "Unexpected duplicate old RID records"
            )

        old_after = conn.execute(
            """
            SELECT COUNT(*)
            FROM smd_records
            WHERE rid_smd = ?
            """,
            (old_rid,),
        ).fetchone()[0]

        new_after = conn.execute(
            """
            SELECT COUNT(*)
            FROM smd_records
            WHERE rid_smd = ?
            """,
            (new_rid,),
        ).fetchone()[0]

        total_records = conn.execute(
            "SELECT COUNT(*) FROM smd_records"
        ).fetchone()[0]

    finally:
        conn.close()

    print("Old RID deletion:", deletion_result)
    print("Old RID after deletion:", old_after)
    print("New RID after deletion:", new_after)
    print("NSP DB record count:", total_records)

    if old_after != 0:
        raise RuntimeError(
            "Old RID record was not removed"
        )

    if new_after != 1:
        raise RuntimeError(
            "New RID record was not preserved"
        )









    session_key_sha256 = hashlib.sha256(
        session_key
    ).hexdigest()

    result = {
        "eid_smd": eid_smd,
        "old_rid_smd": old_rid,
        "rid_new": new_rid,
        "session_key_sha256": session_key_sha256,
        "v2_verified": True,
        "old_record_deleted": True,
        "new_record_preserved": True,
        "status": "PHASE3_COMPLETED",
    }

    RESULT_PATH.write_text(
        json.dumps(
            result,
            indent=2,
        ) + "\n"
    )

    RESULT_PATH.chmod(0o600)

    pending["status"] = "PHASE3_COMPLETED"

    PENDING_PATH.write_text(
        json.dumps(
            pending,
            indent=2,
        ) + "\n"
    )

    PENDING_PATH.chmod(0o600)

    print(
        "Session key SHA256:",
        session_key_sha256,
    )
    print("Result:", RESULT_PATH)
    print()
    print(
        "STATUS: PHASE 3 SESSION KEY EXCHANGE COMPLETED"
    )


if __name__ == "__main__":
    main()
