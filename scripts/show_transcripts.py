from dotenv import load_dotenv
load_dotenv()
import os
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(repo_root))

from storage import transcript as t

DB = os.getenv('TRANSCRIPT_DB', 'transcripts.db')
CA = os.getenv('CA_PATH', 'certs/ca-cert.crt')

print(f"Using transcript DB: {DB}")
print(f"Using CA: {CA}")

if not Path(DB).exists():
    print('No transcript DB found')
    raise SystemExit(1)

entries = list(t.list_entries(DB))
print(f"Found {len(entries)} entries")
for e in entries:
    eid = e['id']
    ts = e['timestamp']
    cn = e['sender_cn']
    mlen = len(e.get('message') or b'')
    clen = len(e.get('ciphertext') or b'')
    slen = len(e.get('signature') or b'')
    print(f"id={eid} ts={ts} sender={cn} message_len={mlen} ciphertext_len={clen} sig_len={slen}")
    try:
        ok = t.verify_entry(e, open(CA,'rb').read())
    except Exception as exc:
        ok = False
        print('verify raised', exc)
    print('  verified:', ok)
