#!/usr/bin/env python3
"""Tamper debug: copy DB, flip a byte in signature for an entry, and show verification before/after.

This is a single, minimal script used for debugging tamper detection. It:
- copies a source DB to `tests/transcripts_test.db`
- reads a single transcript entry by id
- verifies signature before tamper
- flips one byte in the signature and updates the DB
- verifies signature after tamper
"""
from __future__ import annotations

import argparse
import shutil
import sqlite3
import os
import pathlib
import sys

# add project root so imports work when running from repo root
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from storage import transcript as ts
from app.crypto import sign as sign_mod


def get_entry(conn: sqlite3.Connection, entry_id: int):
    cur = conn.cursor()
    cur.execute(
        "SELECT id, timestamp, sender_cn, cert_pem, message, ciphertext, nonce, signature FROM transcripts WHERE id = ?",
        (entry_id,)
    )
    row = cur.fetchone()
    if not row:
        return None
    return {
        'id': row[0], 'timestamp': row[1], 'sender_cn': row[2], 'cert_pem': row[3], 'message': row[4], 'ciphertext': row[5], 'nonce': row[6], 'signature': row[7]
    }


def print_sig_summary(sig: bytes, label: str = ''):
    if not sig:
        print(f"{label}<no signature>")
        return
    print(f"{label}{sig[:16].hex()}... (len={len(sig)})")


def main() -> None:
    p = argparse.ArgumentParser(description='Tamper-debug helper')
    p.add_argument('--src', default='transcripts.db', help='Source DB (backup or main)')
    p.add_argument('--db', default=os.path.join('tests', 'transcripts_test.db'), help='Working DB to create')
    p.add_argument('--id', type=int, default=3, help='Transcript entry id to tamper')
    p.add_argument('--xor', default='01', help='Hex byte to xor into first signature byte')
    args = p.parse_args()

    if not os.path.exists(args.src):
        print('Source DB not found:', args.src)
        return

    shutil.copy2(args.src, args.db)
    print('Copied', args.src, '->', args.db)

    conn = sqlite3.connect(args.db)
    entry = get_entry(conn, args.id)
    if entry is None:
        print('Entry id not found:', args.id)
        conn.close()
        return

    print('\nBefore tamper:')
    print_sig_summary(entry.get('signature'), 'signature: ')
    before_ok = ts.verify_entry(entry, open('certs/ca-cert.crt', 'rb').read())
    print('verify_entry ->', before_ok)

    sig = bytearray(entry.get('signature') or b'')
    if not sig:
        print('No signature to tamper')
        conn.close()
        return

    b = int(args.xor, 16)
    sig[0] ^= b
    cur = conn.cursor()
    cur.execute('UPDATE transcripts SET signature = ? WHERE id = ?', (bytes(sig), args.id))
    conn.commit()

    entry2 = get_entry(conn, args.id)
    print('\nAfter tamper:')
    print_sig_summary(entry2.get('signature'), 'signature: ')
    after_ok = ts.verify_entry(entry2, open('certs/ca-cert.crt', 'rb').read())
    print('verify_entry ->', after_ok)

    conn.close()


if __name__ == '__main__':
    main()
