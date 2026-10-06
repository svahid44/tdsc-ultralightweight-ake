from __future__ import annotations

import hashlib
import json
import platform
import shutil
import socket
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "evidence" / "final_smd"
OUT.mkdir(parents=True, exist_ok=True)

PUBLIC_FILES = [
    ROOT / "smd/export/archive/session1/phase3_request.json",
    ROOT / "smd/export/archive/session1/phase3_ack.json",
    ROOT / "smd/import/archive/session1/phase3_response.json",
    ROOT / "smd/export/archive/session2/phase3_request.json",
    ROOT / "smd/export/archive/session2/phase3_ack.json",
    ROOT / "smd/import/archive/session2/phase3_response.json",
    ROOT / "smd/export/phase3_request.json",
]

def run(args):
    return subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


system = {
    "captured_at_utc": datetime.now(timezone.utc).isoformat(),
    "role": "SMD",
    "hostname": socket.gethostname(),
    "python": platform.python_version(),
    "platform": platform.platform(),
}
openssl = run(["openssl", "version"])
system["openssl"] = openssl.stdout.strip() or openssl.stderr.strip()
(OUT / "system_info.json").write_text(
    json.dumps(system, indent=2) + "\n"
)


bench = run([sys.executable, "smd/src/benchmark_smd_primitives.py"])
(OUT / "benchmark_smd_primitives.txt").write_text(
    bench.stdout + bench.stderr
)
if bench.returncode != 0:
    raise RuntimeError("SMD benchmark failed; see evidence log")


pub = OUT / "public_messages"
pub.mkdir(exist_ok=True)
for src in PUBLIC_FILES:
    if src.exists():
        label = src.relative_to(ROOT).as_posix().replace("/", "__")
        shutil.copy2(src, pub / label)


notes = {
    "puf_mode": "SIMULATED",
    "puf_implementation": "HMAC-SHA256 with persistent local secret",
    "physical_puf_claim": False,
    "warning": (
        "This implementation does not demonstrate physical-PUF "
        "unclonability or physical leakage resilience."
    ),
    "session3_context": (
        "The current phase3_request.json was generated after on-chain "
        "revocation and was expected to be rejected by NSP."
    ),
}
(OUT / "implementation_notes.json").write_text(
    json.dumps(notes, indent=2) + "\n"
)


entries = []
for p in sorted(OUT.rglob("*")):
    if p.is_file() and p.name != "SHA256SUMS.txt":
        entries.append(
            f"{sha256_file(p)}  {p.relative_to(OUT).as_posix()}"
        )
(OUT / "SHA256SUMS.txt").write_text("\n".join(entries) + "\n")

archive = ROOT / "evidence" / "tdsc_smd_evidence.tar.gz"
with tarfile.open(archive, "w:gz") as tf:
    tf.add(OUT, arcname="final_smd")

print("SMD evidence directory:", OUT)
print("SMD evidence archive:", archive)
print("Files:", len(entries) + 1)
print("STATUS: SMD EVIDENCE CAPTURED")
