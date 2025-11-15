#!/usr/bin/env python3
"""Quick test for DH (X25519) + AES-GCM helpers."""

import sys
import pathlib

# Ensure project root is on sys.path so `app` package imports work when
# running the script directly.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.crypto.dh import generate_keypair, derive_shared_secret, derive_aes_key_from_shared
from app.crypto.aes import encrypt, decrypt


def main() -> None:
    # Generate two parties
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()

    # Derive shared secrets
    a_secret = derive_shared_secret(a_priv, b_pub)
    b_secret = derive_shared_secret(b_priv, a_pub)

    print("Shared secrets equal:", a_secret == b_secret)

    # Derive AES key
    key = derive_aes_key_from_shared(a_secret, info=b"securechat test", length=32)

    msg = b"This is a secret message"
    print("Plaintext:", msg)

    nonce, ct = encrypt(key, msg)
    print("Encrypted (len):", len(ct), "nonce:", nonce.hex())

    pt = decrypt(key, nonce, ct)
    print("Decrypted matches:", pt == msg)


if __name__ == "__main__":
    main()
