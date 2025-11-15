from __future__ import annotations

"""AES helpers for authenticated encryption using AES-GCM.

Functions:
- `generate_random_key(length=32)` -> bytes
- `derive_key(shared_secret, salt=None, info=b'handshake data', length=32)` -> bytes
- `encrypt(key, plaintext, aad=None)` -> tuple(nonce, ciphertext)
- `decrypt(key, nonce, ciphertext, aad=None)` -> plaintext

Uses `cryptography` primitives (HKDF and AESGCM).
"""

import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def generate_random_key(length: int = 32) -> bytes:
	"""Return cryptographically random key of `length` bytes.

	Default is 32 bytes (AES-256).
	"""
	return os.urandom(length)


def derive_key(shared_secret: bytes, salt: Optional[bytes] = None, info: bytes = b"handshake data", length: int = 32) -> bytes:
	"""Derive a symmetric key from a shared secret using HKDF-SHA256.

	- `length` is number of output bytes (e.g., 16 for AES-128, 32 for AES-256).
	"""
	hkdf = HKDF(
		algorithm=hashes.SHA256(),
		length=length,
		salt=salt,
		info=info,
	)
	return hkdf.derive(shared_secret)


def encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
	"""Encrypt `plaintext` with AES-GCM using `key`.

	Returns `(nonce, ciphertext)` where `ciphertext` includes the auth tag (AEAD).
	Nonce is 12 bytes.
	"""
	aesgcm = AESGCM(key)
	nonce = os.urandom(12)
	ct = aesgcm.encrypt(nonce, plaintext, aad)
	return nonce, ct


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
	"""Decrypt `ciphertext` with AES-GCM using `key` and `nonce`.

	Returns plaintext bytes or raises an exception on auth failure.
	"""
	aesgcm = AESGCM(key)
	return aesgcm.decrypt(nonce, ciphertext, aad)
