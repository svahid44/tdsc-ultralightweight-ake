from pathlib import Path
from datetime import datetime, timezone
import argparse
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from phase3_create_request import (
    REG_STATE_PATH,
    SERIAL_PATH,
    P256_ORDER,
    decrypt_s_smd,
    derive_smd_storage_key,
    encrypt_e_smd,
    hash_to_scalar,
    load_sk_smd,
)

import h1_verify as verifier


ROOT = Path(__file__).resolve().parents[2]

PK_PATH = ROOT / "smd/data/pk_smd.pem"
A_PUBLIC_PATH = ROOT / "smd/data/A_smd.pem"

LAB_BASE = ROOT / "smd/data/phase3_retry_lab"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def decode_b64(value, field_name):
    require(
        isinstance(value, str),
        f"{field_name} must be a Base64 string",
    )

    try:
        return base64.urlsafe_b64decode(
            value.encode("ascii")
        )
    except Exception as exc:
        raise RuntimeError(
            f"Cannot decode {field_name}"
        ) from exc


def write_private_json(path, data):
    with path.open("x", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    path.chmod(0o600)


def load_context():
    required_files = [
        REG_STATE_PATH,
        SERIAL_PATH,
        PK_PATH,
        A_PUBLIC_PATH,
    ]

    for path in required_files:
        require(
            path.is_file(),
            f"Required file missing: {path.name}",
        )

    registration = json.loads(
        REG_STATE_PATH.read_text(encoding="utf-8")
    )

    require(
        registration.get("status")
        == "REGISTRATION_MATERIAL_STORED",
        "SMD registration is not ready",
    )

    serial = SERIAL_PATH.read_text(
        encoding="utf-8"
    ).strip()

    require(bool(serial), "SMD serial is empty")

    require(
        registration.get("serial") == serial,
        "SMD serial mismatch",
    )

    id_smd = registration["id_smd"]
    id_nsp = registration["id_nsp"]

    require(
        isinstance(id_smd, str) and id_smd,
        "Invalid ID_SMD",
    )

    require(
        isinstance(id_nsp, str) and id_nsp,
        "Invalid ID_NSP",
    )

    sk_smd = load_sk_smd()

    storage_key = derive_smd_storage_key(
        sk_smd,
        serial,
        id_smd,
    )

    secret = decrypt_s_smd(
        registration["s_smd"],
        storage_key,
    )

    required_fields = {
        "eid_smd",
        "rid_smd",
        "a_smd",
        "st_smd",
        "dt_smd",
    }

    missing = required_fields - set(secret)

    require(
        not missing,
        f"Missing S_SMD fields: {sorted(missing)}",
    )

    eid_smd = secret["eid_smd"]

    rid_smd = decode_b64(
        secret["rid_smd"], "RID_SMD"
    )

    a_smd = decode_b64(
        secret["a_smd"], "a_SMD"
    )

    st_smd = decode_b64(
        secret["st_smd"], "ST_SMD"
    )

    dt_smd = decode_b64(
        secret["dt_smd"], "DT_SMD"
    )

    for name, value in (
        ("RID_SMD", rid_smd),
        ("a_SMD", a_smd),
        ("ST_SMD", st_smd),
        ("DT_SMD", dt_smd),
    ):
        require(
            len(value) == 32,
            f"{name} must be 32 bytes",
        )

    require(
        isinstance(eid_smd, str) and eid_smd,
        "Invalid EID_SMD",
    )

    sk_scalar = (
        sk_smd.private_numbers().private_value
    )

    a_scalar = int.from_bytes(a_smd, "big")

    require(
        1 <= a_scalar < P256_ORDER,
        "Invalid a_SMD scalar",
    )

    require(
        P256_ORDER == verifier.N,
        "P-256 curve-order mismatch",
    )

    pk_public = serialization.load_pem_public_key(
        PK_PATH.read_bytes()
    )

    a_public = serialization.load_pem_public_key(
        A_PUBLIC_PATH.read_bytes()
    )

    require(
        isinstance(pk_public, ec.EllipticCurvePublicKey),
        "PK_SMD is not an EC public key",
    )

    require(
        isinstance(a_public, ec.EllipticCurvePublicKey),
        "A_SMD is not an EC public key",
    )

    pk_point = verifier.get_public_point(pk_public)
    a_point = verifier.get_public_point(a_public)

    # Verify that the private and public keys match.
    require(
        verifier.scalar_mult(
            sk_scalar, verifier.G
        ) == pk_point,
        "sk_SMD does not match PK_SMD",
    )

    require(
        verifier.scalar_mult(
            a_scalar, verifier.G
        ) == a_point,
        "a_SMD does not match A_SMD",
    )

    print("[PASS] Registration material loaded")
    print("[PASS] sk_SMD matches PK_SMD")
    print("[PASS] a_SMD matches A_SMD")
    print("[PASS] S_SMD decrypted successfully")

    return {
        "eid_smd": eid_smd,
        "id_nsp": id_nsp,
        "rid_smd": rid_smd,
        "a_scalar": a_scalar,
        "st_smd": st_smd,
        "dt_smd": dt_smd,
        "sk_scalar": sk_scalar,
        "pk_point": pk_point,
        "a_point": a_point,
        "secret": secret,
    }


def generate_attempts(context, count):
    generated = []

    seen_r = set()
    seen_v1 = set()

    max_trials = count * 10 + 100
    trials = 0

    while len(generated) < count:
        trials += 1

        require(
            trials <= max_trials,
            "Could not generate enough unique attempts",
        )

        # Step 1: Generate a fresh r_SMD.
        r_smd = os.urandom(32)

        if r_smd in seen_r:
            continue

        seen_r.add(r_smd)

        # Step 2: Compute h using the existing
        # protocol's length-prefixed SHA-256 encoding.
        h_scalar = hash_to_scalar(
            context["rid_smd"],
            context["eid_smd"].encode("utf-8"),
            context["id_nsp"].encode("utf-8"),
            r_smd,
            context["st_smd"],
        )

        # Step 3: Compute V1_SMD.
        v1_scalar = (
            h_scalar * context["sk_scalar"]
            + context["a_scalar"]
        ) % P256_ORDER

        # A zero scalar is not accepted.
        if v1_scalar == 0:
            continue

        v1_smd = v1_scalar.to_bytes(32, "big")

        # Require distinct V1 values for this lab run.
        if v1_smd in seen_v1:
            continue

        # Step 4: Independently verify the curve equation:
        #
        # V1_SMD * G == h * PK_SMD + A_SMD
        lhs = verifier.scalar_mult(
            v1_scalar,
            verifier.G,
        )

        h_times_pk = verifier.scalar_mult(
            h_scalar,
            context["pk_point"],
        )

        rhs = verifier.point_add(
            h_times_pk,
            context["a_point"],
        )

        require(
            lhs == rhs,
            "V1_SMD equation verification failed",
        )

        # Step 5: Re-encrypt the new r_SMD and V1_SMD.
        e_smd = encrypt_e_smd(
            context["dt_smd"],
            r_smd,
            v1_smd,
        )

        rid_b64 = base64.urlsafe_b64encode(
            context["rid_smd"]
        ).decode("ascii")

        request = {
            "rid_smd": rid_b64,
            "e_smd": e_smd,
        }

        # Keep sensitive attempt data in a private file.
        pending = {
            "attempt": len(generated) + 1,
            "eid_smd": context["eid_smd"],
            "id_nsp": context["id_nsp"],
            "rid_smd": rid_b64,
            "r_smd": base64.urlsafe_b64encode(
                r_smd
            ).decode("ascii"),
            "st_smd": context["secret"]["st_smd"],
            "dt_smd": context["secret"]["dt_smd"],
            "v1_smd": base64.urlsafe_b64encode(
                v1_smd
            ).decode("ascii"),
            "e_smd_sha256": hashlib.sha256(
                e_smd.encode("ascii")
            ).hexdigest(),
            "status": "LAB_GENERATED_NO_NSP_RESPONSE",
        }

        seen_v1.add(v1_smd)

        generated.append({
            "request": request,
            "pending": pending,
        })

    return generated


def save_attempts(generated):
    LAB_BASE.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    LAB_BASE.chmod(0o700)

    stamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    run_dir = LAB_BASE / stamp
    suffix = 1

    while run_dir.exists():
        run_dir = LAB_BASE / f"{stamp}-{suffix:02d}"
        suffix += 1

    run_dir.mkdir(mode=0o700)
    run_dir.chmod(0o700)

    for index, item in enumerate(generated, start=1):
        attempt_dir = run_dir / f"attempt_{index:03d}"

        attempt_dir.mkdir(mode=0o700)
        attempt_dir.chmod(0o700)

        write_private_json(
            attempt_dir / "request.json",
            item["request"],
        )

        write_private_json(
            attempt_dir / "pending.json",
            item["pending"],
        )

    return run_dir


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Offline SMD Phase 3 retry-generation lab"
        )
    )

    parser.add_argument(
        "--attempts",
        type=int,
        default=3,
        help="Number of independent attempts (1-20)",
    )

    args = parser.parse_args()

    require(
        1 <= args.attempts <= 20,
        "Choose between 1 and 20 attempts",
    )

    print("=" * 58)
    print("SMD PHASE 3 RETRY LAB")
    print("=" * 58)

    print("Mode: offline generation and verification")
    print("NSP contacted: NO")
    print("Original phase3 files will not be modified")
    print()

    context = load_context()
    generated = generate_attempts(
        context,
        args.attempts,
    )

    run_dir = save_attempts(generated)

    for index, item in enumerate(generated, start=1):
        pending = item["pending"]

        print(f"Attempt {index}:")
        print("  Fresh r_SMD: PASS (32 bytes)")
        print("  V1_SMD generated: PASS (32 bytes)")
        print("  V1_SMD equation: PASS")
        print("  E_SMD regenerated: PASS")
        print(
            "  V1_SMD fingerprint:",
            pending["e_smd_sha256"][:16],
            "(E_SMD SHA-256 prefix)",
        )
        print()

    print("RESULT: ALL ATTEMPTS GENERATED AND VERIFIED")
    print("Distinct r_SMD values: PASS")
    print("Distinct V1_SMD values: PASS")
    print("NSP response received: NO")
    print("Private output permissions: 600")
    print("Output directory:", run_dir.relative_to(ROOT))
    print()
    print("V1_SMD and r_SMD are not printed to the terminal.")


if __name__ == "__main__":
    main()
