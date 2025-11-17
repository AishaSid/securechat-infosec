#!/usr/bin/env python3
"""Report replay-detection findings in a readable JSON format.

Usage: python tests/tools/report_replays.py
"""
import json
import base64
import hashlib
from storage import transcript

DB = "tests/transcripts_test.db"

def main():
    issues = transcript.detect_replays(DB)
    entries = {e['id']: e for e in transcript.list_entries(DB)}
    rows = []
    for k in sorted(issues.keys(), key=lambda x: int(x)):
        rid = int(k)
        e = entries[rid]
        nonce_b64 = base64.b64encode(e['nonce'] or b"").decode()
        ctxt = e['ciphertext'] or b""
        ctxt_sha256 = hashlib.sha256(ctxt).hexdigest() if ctxt else ""
        sig_sha256 = hashlib.sha256(e['signature'] or b"").hexdigest() if e['signature'] else ""
        rows.append({
            'id': rid,
            'timestamp': e['timestamp'],
            'sender_cn': e['sender_cn'],
            'nonce_b64': nonce_b64,
            'ciphertext_sha256': ctxt_sha256,
            'signature_sha256': sig_sha256,
            'issues': issues[k],
        })

    out = {
        'db': DB,
        'flagged_count': len(rows),
        'details': rows,
    }
    print(json.dumps(out, indent=2))

if __name__ == '__main__':
    main()
