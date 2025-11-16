"""Session receipt creation and verification helpers.

A session receipt is a signed JSON summary of a session's transcripts.
It includes session id, start/end timestamps, participant list, entry ids and
SHA-256 hashes of each entry payload (message or ciphertext).
"""
from __future__ import annotations

import sqlite3
import json
from datetime import datetime, timezone
from typing import Iterable, Dict, Any
import hashlib

from app.crypto import sign as sign_mod


def _hash_payload(payload: bytes | None) -> str:
    if payload is None:
        return ''
    h = hashlib.sha256()
    h.update(payload)
    return h.hexdigest()


def create_receipt(db_path: str, session_id: str, start_ts: str, end_ts: str, signer_cert_pem: bytes, signer_priv_key_path: str) -> int:
    """Create a signed session receipt for entries between start_ts and end_ts.

    - `start_ts` and `end_ts` are ISO timestamp strings (inclusive).
    - Returns the inserted `session_receipts.id`.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # fetch relevant transcripts
    cur.execute(
        'SELECT id, timestamp, sender_cn, cert_pem, message, ciphertext FROM transcripts WHERE timestamp >= ? AND timestamp <= ? ORDER BY id',
        (start_ts, end_ts),
    )
    entries = []
    participants = set()
    for row in cur.fetchall():
        eid, ts, sender_cn, cert_pem, msg, ctxt = row
        participants.add(sender_cn)
        payload = msg if msg is not None else ctxt
        entries.append({'id': eid, 'timestamp': ts, 'sender_cn': sender_cn, 'payload_hash': _hash_payload(payload)})

    receipt = {
        'session_id': session_id,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'start_ts': start_ts,
        'end_ts': end_ts,
        'participants': sorted(list(participants)),
        'entry_count': len(entries),
        'entries': entries,
    }

    receipt_json = json.dumps(receipt, separators=(',', ':'), sort_keys=True).encode('utf-8')

    # sign receipt_json using signer private key
    signer_priv = sign_mod.load_private_key(signer_priv_key_path)
    signature = sign_mod.sign_bytes(signer_priv, receipt_json)

    # extract signer CN from cert
    signer_cn = 'unknown'
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        cert = x509.load_pem_x509_certificate(signer_cert_pem)
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            signer_cn = cn_attrs[0].value
    except Exception:
        pass

    # store into session_receipts table (init should have created it)
    cur.execute('INSERT INTO session_receipts (session_id, created_at, signer_cn, receipt_json, signature) VALUES (?, ?, ?, ?, ?)',
                (session_id, receipt['created_at'], signer_cn, receipt_json, signature))
    rowid = cur.lastrowid
    conn.commit()
    conn.close()
    return rowid


def verify_receipt(db_path: str, receipt_id: int, ca_pem: bytes | None = None) -> bool:
    """Verify stored session receipt signature.

    Returns True if signature verifies with signer cert present in transcripts.
    If CA is provided, optionally validate signer cert chain (not implemented here).
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('SELECT receipt_json, signature, signer_cn FROM session_receipts WHERE id=?', (receipt_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return False
    receipt_json, signature, signer_cn = row

    # Try to find the signer's public key from transcripts table
    cur.execute('SELECT cert_pem FROM transcripts WHERE sender_cn=? LIMIT 1', (signer_cn,))
    r = cur.fetchone()
    conn.close()
    if not r:
        return False
    signer_cert_pem = r[0]
    pub = sign_mod.load_public_key_from_cert(signer_cert_pem)
    return bool(sign_mod.verify_bytes(pub, receipt_json, signature))
