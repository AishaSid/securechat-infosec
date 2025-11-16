"""Export transcript DB entries into human-readable JSON files.

For each entry this script writes a JSON file containing:
- id, timestamp, sender_cn
- cert_pem (string)
- signature (base64)
- ciphertext (hex + base64)
- nonce (hex + base64)
- message (utf-8 string) if present, otherwise message_hash (sha256 hex)
- verified: boolean (signature + cert verification)

Usage:
  python tests/tools/export_transcripts.py --db transcripts.db --out exports --all
  python tests/tools/export_transcripts.py --db transcripts.db --out exports --id 3
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

import sys
repo_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(repo_root))

from storage import transcript as t


def to_hex(b: bytes | None) -> str | None:
    return None if b is None else b.hex()


def to_b64(b: bytes | None) -> str | None:
    return None if b is None else base64.b64encode(b).decode()


def export_entry(entry: dict, ca_pem: bytes, out_dir: Path) -> Path:
    eid = entry["id"]
    cert_pem = entry["cert_pem"]
    sig = entry.get("signature") or b""
    ciphertext = entry.get("ciphertext")
    nonce = entry.get("nonce")
    message = entry.get("message")

    if message:
        try:
            message_text = message.decode("utf-8")
        except Exception:
            message_text = None
    else:
        message_text = None

    if message_text is None and message is None and ciphertext is not None:
        # compute message hash placeholder (we don't have plaintext)
        message_hash = hashlib.sha256(ciphertext).hexdigest()
    elif message is not None:
        message_hash = hashlib.sha256(message).hexdigest()
    else:
        message_hash = None

    verified = False
    try:
        verified = t.verify_entry(entry, ca_pem)
    except Exception:
        verified = False

    payload = {
        "id": eid,
        "timestamp": entry.get("timestamp"),
        "sender_cn": entry.get("sender_cn"),
        "cert_pem": cert_pem.decode() if isinstance(cert_pem, (bytes, bytearray)) else cert_pem,
        "signature_b64": to_b64(sig),
        "signature_hex": to_hex(sig),
        "ciphertext_b64": to_b64(ciphertext),
        "ciphertext_hex": to_hex(ciphertext),
        "nonce_b64": to_b64(nonce),
        "nonce_hex": to_hex(nonce),
        "message_utf8": message_text,
        "message_hash_sha256": message_hash,
        "verified": verified,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"transcript_{eid}.json"
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return out_path


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--db", default="transcripts.db", help="Path to transcript DB")
    p.add_argument("--out", default="exports", help="Output directory")
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("--all", action="store_true")
    grp.add_argument("--id", type=int)
    p.add_argument("--ca", default=None, help="Path to CA PEM for verification (optional)")
    args = p.parse_args()

    dbp = args.db
    outp = Path(args.out)
    ca_pem = None
    if args.ca:
        ca_pem = Path(args.ca).read_bytes()
    else:
        # try environment default
        import os
        capath = os.getenv("CA_PATH", "certs/ca-cert.crt")
        if Path(capath).exists():
            ca_pem = Path(capath).read_bytes()

    if args.all:
        for e in t.list_entries(dbp):
            pth = export_entry(e, ca_pem, outp)
            print("exported", pth)
    else:
        found = False
        for e in t.list_entries(dbp):
            if e["id"] == args.id:
                pth = export_entry(e, ca_pem, outp)
                print("exported", pth)
                found = True
                break
        if not found:
            print("entry not found")


if __name__ == "__main__":
    main()
*** End Patch
