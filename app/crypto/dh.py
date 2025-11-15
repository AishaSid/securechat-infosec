from __future__ import annotations

"""DH helpers using X25519 (Curve25519) for ECDH and HKDF-based key derivation.

This module provides simple helpers to generate keypairs, serialize/deserialize
public keys, derive a shared secret, and produce a symmetric key suitable for
AES-GCM via HKDF-SHA256.
"""

from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


def generate_keypair() -> Tuple[X25519PrivateKey, bytes]:
    """Generate an X25519 keypair and return (private_key_obj, public_bytes).

    `public_bytes` is the 32-byte raw public key.
    """
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


def public_bytes_from_private(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_private_from_bytes(b: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(b)


def load_public_from_bytes(b: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(b)


def derive_shared_secret(priv: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    """Compute raw shared secret bytes using ECDH (X25519)."""
    peer_pub = load_public_from_bytes(peer_public_bytes)
    secret = priv.exchange(peer_pub)
    return secret


def derive_aes_key_from_shared(secret: bytes, salt: bytes | None = None, info: bytes = b"handshake data", length: int = 32) -> bytes:
    """Derive an AES key from shared secret using HKDF-SHA256.

    Return `length`-byte symmetric key (e.g., 16 or 32).
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(secret)

