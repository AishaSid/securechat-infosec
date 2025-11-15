"""RSA PKCS#1 v1.5 SHA-256 sign/verify helpers.

Functions provided:
- load_private_key(path_or_pem, password=None)
- load_public_key_from_cert(path_or_pem)
- sign_bytes(private_key, data) -> bytes
- verify_bytes(public_key, data, signature) -> bool

Uses `cryptography` primitives.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from typing import Union


def load_private_key(path_or_pem: Union[str, bytes], password: Union[None, bytes] = None) -> rsa.RSAPrivateKey:
	"""Load an RSA private key from a PEM file path or PEM bytes."""
	if isinstance(path_or_pem, str):
		with open(path_or_pem, "rb") as f:
			data = f.read()
	else:
		data = path_or_pem
	return load_pem_private_key(data, password=password)


def load_public_key_from_cert(path_or_pem: Union[str, bytes]):
	"""Load public key from a certificate PEM (file path or bytes)."""
	if isinstance(path_or_pem, str):
		with open(path_or_pem, "rb") as f:
			data = f.read()
	else:
		data = path_or_pem
	cert = x509.load_pem_x509_certificate(data)
	return cert.public_key()


def sign_bytes(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
	"""Sign `data` with RSA PKCS#1 v1.5 and SHA-256. Returns signature bytes."""
	return private_key.sign(
		data,
		padding.PKCS1v15(),
		hashes.SHA256(),
	)


def verify_bytes(public_key, data: bytes, signature: bytes) -> bool:
	"""Verify signature over data using RSA PKCS#1 v1.5 SHA-256.

	Returns True on success, False on failure.
	"""
	try:
		public_key.verify(
			signature,
			data,
			padding.PKCS1v15(),
			hashes.SHA256(),
		)
		return True
	except Exception:
		return False

