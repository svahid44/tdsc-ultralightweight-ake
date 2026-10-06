from pathlib import Path
import base64
import json

ROOT = Path(__file__).resolve().parents[2]

FILES = {
    "SMD->NSP request": ROOT / "nsp/import/archive/session2/phase3_request.json",
    "NSP->SMD response": ROOT / "nsp/export/archive/session2/phase3_response.json",
    "SMD->NSP ack": ROOT / "nsp/import/archive/session2/phase3_ack.json",
}

def b64len(value: str) -> int:
    return len(base64.urlsafe_b64decode(value.encode()))

total_file = 0
total_compact = 0
total_binary = 0

print("=== Session 2 Communication Measurement ===")

for label, path in FILES.items():
    if not path.exists():
        raise FileNotFoundError(path)

    raw_file = path.read_bytes()
    obj = json.loads(raw_file.decode())

    compact = json.dumps(
        obj,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()

    binary_fields = {
        key: b64len(value)
        for key, value in obj.items()
    }

    binary_total = sum(binary_fields.values())

    print()
    print(label)
    print("  file:", path)
    print("  JSON file bytes:", len(raw_file))
    print("  compact JSON bytes:", len(compact))
    print("  decoded field bytes:")
    for key, size in binary_fields.items():
        print(f"    {key}: {size}")
    print("  decoded payload total:", binary_total)

    total_file += len(raw_file)
    total_compact += len(compact)
    total_binary += binary_total

print()
print("=== Totals ===")
print("Pretty JSON wire bytes:", total_file)
print("Compact JSON wire bytes:", total_compact)
print("Decoded binary field bytes:", total_binary)
print("Paper theoretical Phase-3 communication: 136 bytes")
print()
print(
    "NOTE: decoded binary field bytes are still implementation-specific "
    "because ciphertext packages include AEAD nonce/tag and serialized plaintext."
)
