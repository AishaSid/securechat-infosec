"""MySQL-backed user store for SecureChat.

Provides helper functions to initialize the users table, create users with
salted SHA-256 password hashing, and verify credentials.

Connection parameters are read from environment variables with sensible
defaults matching the README Docker example.
"""
from __future__ import annotations

import os
import hashlib
import os as _os
from typing import Optional, Tuple
import pymysql


def _get_conn_params() -> dict:
    return {
        "host": os.getenv("DB_HOST", "127.0.0.1"),
        "port": int(os.getenv("DB_PORT", "3306")),
        "user": os.getenv("DB_USER", "scuser"),
        "password": os.getenv("DB_PASSWORD", "scpass"),
        "db": os.getenv("DB_NAME", "securechat"),
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
    }


def get_connection():
    params = _get_conn_params()
    return pymysql.connect(**params)


def init_db() -> None:
    """Create the `users` table if it does not exist."""
    sql = """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        salt VARBINARY(64) NOT NULL,
        pw_hash VARBINARY(64) NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
    finally:
        conn.close()


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.sha256(salt + password.encode("utf-8")).digest()


def create_user(username: str, password: str) -> int:
    """Create a new user with a random salt and return the new user id."""
    salt = _os.urandom(16)
    pw_hash = _hash_password(password, salt)
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, salt, pw_hash) VALUES (%s, %s, %s)",
                (username, salt, pw_hash),
            )
            conn.commit()
            return cur.lastrowid
    finally:
        conn.close()


def get_user_credentials(username: str) -> Optional[Tuple[bytes, bytes]]:
    """Return (salt, pw_hash) for username or None if not found."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT salt, pw_hash FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
            if not row:
                return None
            return row["salt"], row["pw_hash"]
    finally:
        conn.close()


def verify_user(username: str, password: str) -> bool:
    creds = get_user_credentials(username)
    if creds is None:
        return False
    salt, pw_hash = creds
    return _hash_password(password, salt) == pw_hash


def change_password(username: str, new_password: str) -> bool:
    salt = _os.urandom(16)
    pw_hash = _hash_password(new_password, salt)
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET salt=%s, pw_hash=%s WHERE username=%s", (salt, pw_hash, username))
            conn.commit()
            return cur.rowcount > 0
    finally:
        conn.close()


if __name__ == "__main__":
    import argparse
    import getpass

    parser = argparse.ArgumentParser(description="Manage SecureChat MySQL user store")
    parser.add_argument("--init", action="store_true", help="Initialize the users table")
    parser.add_argument("--add", metavar="USERNAME", help="Add a user (prompts for password)")
    parser.add_argument("--verify", metavar="USERNAME", help="Verify a user's password (prompts for password)")
    parser.add_argument("--change", metavar="USERNAME", help="Change a user's password (prompts)")
    args = parser.parse_args()

    if args.init:
        init_db()
        print("users table initialized")
    elif args.add:
        pwd = getpass.getpass("Password: ")
        uid = create_user(args.add, pwd)
        print(f"created user id={uid}")
    elif args.verify:
        pwd = getpass.getpass("Password: ")
        ok = verify_user(args.verify, pwd)
        print("OK" if ok else "FAIL")
    elif args.change:
        pwd = getpass.getpass("New password: ")
        ok = change_password(args.change, pwd)
        print("changed" if ok else "not found")
    else:
        parser.print_help()
