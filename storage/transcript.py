"""Simple transcript storage and verification using SQLite.

Provides a small API for storing message transcripts with signatures and
verifying them against a CA certificate using the existing PKI/sign helpers.

Schema:
 - id INTEGER PRIMARY KEY
 - timestamp TEXT (ISO UTC)
 - sender_cn TEXT
 - cert_pem BLOB
 - message BLOB
 - ciphertext BLOB
 - nonce BLOB
 - signature BLOB
"""
from __future__ import annotations

import sqlite3
from typing import Optional, Iterable, Dict, Any
from datetime import datetime, timezone
import base64

from app.crypto import sign as sign_mod
from app.crypto import pki


def init_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS transcripts (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            sender_cn TEXT NOT NULL,
            cert_pem BLOB NOT NULL,
            message BLOB,
            ciphertext BLOB,
            nonce BLOB,
            signature BLOB NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def add_entry(db_path: str, sender_cn: str, cert_pem: bytes, message: Optional[bytes], ciphertext: Optional[bytes], nonce: Optional[bytes], signature: bytes) -> int:
    ts = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO transcripts (timestamp, sender_cn, cert_pem, message, ciphertext, nonce, signature) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ts, sender_cn, cert_pem, message, ciphertext, nonce, signature),
    )
    rowid = cur.lastrowid
    conn.commit()
    conn.close()
    return rowid


def list_entries(db_path: str) -> Iterable[Dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, timestamp, sender_cn, cert_pem, message, ciphertext, nonce, signature FROM transcripts ORDER BY id")
    for row in cur.fetchall():
        yield {
            "id": row[0],
            "timestamp": row[1],
            "sender_cn": row[2],
            "cert_pem": row[3],
            "message": row[4],
            "ciphertext": row[5],
            "nonce": row[6],
            "signature": row[7],
        }
    conn.close()


def verify_entry(entry: Dict[str, Any], ca_pem: bytes, expected_cn: Optional[str] = None) -> bool:
    """Verify a single transcript entry.

    - Validates the certificate is signed by the CA and within validity window using `pki.validate_certificate`.
    - Verifies the attached signature over the `message` (if present) using the public key from the cert.

    Returns True on success, False otherwise.
    """
    cert_pem = entry["cert_pem"]
    try:
        # validate certificate against CA and optional CN
        pki.validate_certificate(cert_pem, ca_pem, expected_cn)
    except Exception:
        return False

    # verify signature over the message if message present, otherwise over ciphertext
    payload = entry.get("message") or entry.get("ciphertext") or b""
    sig = entry.get("signature")
    if sig is None:
        return False

    try:
        pub = sign_mod.load_public_key_from_cert(cert_pem)
        # verify_bytes will raise on failure
        sign_mod.verify_bytes(pub, payload, sig)
        return True
    except Exception:
        return False


def verify_all(db_path: str, ca_pem_path: str) -> Dict[int, bool]:
    """Verify all transcript entries against the provided CA PEM.

    Returns a mapping of entry id -> verification boolean.
    """
    ca_pem = open(ca_pem_path, "rb").read()
    results: Dict[int, bool] = {}
    for e in list_entries(db_path):
        ok = verify_entry(e, ca_pem)
        results[e["id"]] = ok
    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="List and verify transcript DB entries")
    parser.add_argument("db", help="Path to transcripts DB (sqlite)")
    parser.add_argument("--ca", help="Path to CA PEM to verify certificates")
    parser.add_argument("--list", action="store_true", help="List stored transcript entries")
    parser.add_argument("--verify-all", action="store_true", help="Verify all entries using --ca")
    args = parser.parse_args()

    if args.list:
        for e in list_entries(args.db):
            print(f"{e['id']}: {e['timestamp']} {e['sender_cn']} message_len={len(e.get('message') or b'')} sig_len={len(e.get('signature') or b'')}")
    elif args.verify_all:
        if not args.ca:
            print("--ca is required for --verify-all")
        else:
            results = verify_all(args.db, args.ca)
            good = sum(1 for v in results.values() if v)
            print(f"verified {good}/{len(results)} entries")
    else:
        parser.print_help()
