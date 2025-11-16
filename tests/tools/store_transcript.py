#!/usr/bin/env python3
"""Create and store a signed transcript entry for testing.

Usage: python tests/tools/store_transcript.py --cert certs/server-cert.crt --key certs/server-private.key --db transcripts.db --message "hello"

This script signs the provided message with the private key and stores the
certificate, signature, and payload in an SQLite DB via `storage.transcript`.
"""
import argparse
import base64
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from storage import transcript
from app.crypto import sign as sign_mod


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cert", required=True, help="Path to PEM certificate")
    p.add_argument("--key", required=True, help="Path to PEM private key")
    p.add_argument("--db", default="transcripts.db", help="SQLite DB path")
    p.add_argument("--message", default="Hello from signer", help="Message to sign")
    p.add_argument("--nonce", default=None, help="Optional nonce (hex) for ciphertext field")
    args = p.parse_args()

    with open(args.cert, "rb") as f:
        cert_pem = f.read()
    with open(args.key, "rb") as f:
        key_pem = f.read()

    priv = sign_mod.load_private_key(key_pem)

    message = args.message.encode()
    signature = sign_mod.sign_bytes(priv, message)

    transcript.init_db(args.db)
    # store message; ciphertext/nonce left empty for this simple example
    sender_cn = "unknown"
    try:
        # try to extract CN from cert
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        cert = x509.load_pem_x509_certificate(cert_pem)
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            sender_cn = cn_attrs[0].value
    except Exception:
        pass

    rowid = transcript.add_entry(args.db, sender_cn, cert_pem, message, None, None, signature)
    print(f"Inserted transcript id={rowid}")


if __name__ == "__main__":
    main()
*** End Patch
