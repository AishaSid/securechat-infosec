#!/usr/bin/env python3
"""Check MySQL users table existence + row count using storage.db helper.

This was previously appended accidentally to `check_db.py` — moved here.
"""
from dotenv import load_dotenv
load_dotenv()
import os
import traceback
import sys
from pathlib import Path

# Ensure repository root is on sys.path when running this script from tests/tools/
repo_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(repo_root))

try:
    import storage.db as db
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=%s AND table_name='users'", (os.getenv('DB_NAME','securechat'),))
    row = cur.fetchone()
    if isinstance(row, dict):
        exists = list(row.values())[0]
    else:
        exists = row[0]
    print('users_table_exists=', exists)
    if exists:
        try:
            cur.execute('SELECT COUNT(*) FROM users')
            row2 = cur.fetchone()
            if isinstance(row2, dict):
                rows = list(row2.values())[0]
            else:
                rows = row2[0]
            print('users_rows=', rows)
        except Exception as e:
            print('query users failed:', e)
    conn.close()
except Exception:
    print('connection failed:')
    traceback.print_exc()
