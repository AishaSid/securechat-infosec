"""Tamper a transcript field by XORing one byte.

This is a simplified port of earlier scripts for use in tests/tamper.
"""
import sqlite3
import argparse
import shutil
import time
import os


def xor_byte(b: bytearray, offset: int, xorv: int):
    if offset < 0 or offset >= len(b):
        raise IndexError('offset')
    b[offset] = b[offset] ^ xorv


def tamper(db: str, rec_id: int, field: str, offset: int, xorv: int):
    bak = f"{db}.bak.{int(time.time())}"
    shutil.copy2(db, bak)
    print('Backed up DB to', bak)
    con = sqlite3.connect(db)
    cur = con.cursor()
    cur.execute('SELECT id, signature, ciphertext FROM transcripts WHERE id=?', (rec_id,))
    row = cur.fetchone()
    if not row:
        raise ValueError('record not found')
    sig = row[1]
    ctxt = row[2]
    if field == 'signature':
        if not sig:
            raise ValueError('no signature')
        ba = bytearray(sig)
        xor_byte(ba, offset, xorv)
        cur.execute('UPDATE transcripts SET signature=? WHERE id=?', (bytes(ba), rec_id))
    elif field == 'ciphertext':
        if not ctxt:
            raise ValueError('no ciphertext')
        ba = bytearray(ctxt)
        xor_byte(ba, offset, xorv)
        cur.execute('UPDATE transcripts SET ciphertext=? WHERE id=?', (bytes(ba), rec_id))
    else:
        raise ValueError('unsupported field')
    con.commit()
    print('Tampered', field, 'id', rec_id)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default='tests/transcripts_test.db')
    parser.add_argument('--id', type=int, required=True)
    parser.add_argument('--field', choices=['signature', 'ciphertext'], required=True)
    parser.add_argument('--offset', type=int, default=0)
    parser.add_argument('--xor', type=lambda s: int(s, 0), default='0x01')
    args = parser.parse_args()
    tamper(args.db, args.id, args.field, args.offset, args.xor)


if __name__ == '__main__':
    main()

