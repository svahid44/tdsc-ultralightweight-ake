from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "smd/data"

SK_PATH = DATA / "sk_smd.pem"
PK_PATH = DATA / "pk_smd.pem"
A_SECRET_PATH = DATA / "a_smd.key"
A_PUBLIC_PATH = DATA / "A_smd.pem"

paths = [
    SK_PATH,
    PK_PATH,
    A_SECRET_PATH,
    A_PUBLIC_PATH,
]

existing = [str(p) for p in paths if p.exists()]

if existing:
    raise SystemExit(
        "ERROR: SMD identity material already exists:\n"
        + "\n".join(existing)
        + "\nNothing was overwritten."
    )







sk_smd = ec.generate_private_key(ec.SECP256R1())
pk_smd = sk_smd.public_key()

SK_PATH.write_bytes(
    sk_smd.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
)

PK_PATH.write_bytes(
    pk_smd.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
)







a_private = ec.generate_private_key(ec.SECP256R1())

a_value = a_private.private_numbers().private_value

A_smd = a_private.public_key()

A_SECRET_PATH.write_bytes(
    a_value.to_bytes(32, "big")
)

A_PUBLIC_PATH.write_bytes(
    A_smd.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
)



SK_PATH.chmod(0o600)
A_SECRET_PATH.chmod(0o600)


PK_PATH.chmod(0o644)
A_PUBLIC_PATH.chmod(0o644)


print("sk_SMD:", SK_PATH)
print("PK_SMD:", PK_PATH)
print("a_SMD:", A_SECRET_PATH)
print("A_SMD:", A_PUBLIC_PATH)

print("sk_SMD permission:", oct(SK_PATH.stat().st_mode & 0o777))
print("a_SMD permission:", oct(A_SECRET_PATH.stat().st_mode & 0o777))
print("a_SMD size:", A_SECRET_PATH.stat().st_size, "bytes")

print("STATUS: SMD IDENTITY GENERATED")
