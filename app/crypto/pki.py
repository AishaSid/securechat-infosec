"""X.509 validation helpers: signed-by-CA, validity window, CN/SAN.

Functions:
- load_pem_cert(path_or_bytes): load a PEM certificate from path or bytes
- is_signed_by(cert, ca_cert): verify cert signature using CA public key
- is_within_validity(cert, now=datetime.utcnow()): check notBefore/notAfter
- matches_cn_or_san(cert, expected_cn): check CN or SAN DNSName matches expected
- validate_certificate(cert_pem, ca_pem, expected_cn=None): convenience validator

These helpers use the `cryptography` library and return booleans or raise
ValueError with a short reason when validation fails.
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from datetime import datetime
from typing import Union


def load_pem_cert(data: Union[str, bytes]):
	"""Load an X.509 certificate from a file path or from PEM bytes/string.

	Returns an instance of `cryptography.x509.Certificate`.
	"""
	if isinstance(data, str):
		# treat as path
		with open(data, "rb") as f:
			data = f.read()
	if isinstance(data, str):
		data = data.encode()
	return x509.load_pem_x509_certificate(data)


def is_signed_by(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
	"""Return True if `cert` is signed by `ca_cert` (verifies signature).

	This performs a single-step signature verification (does not build chains).
	"""
	pub = ca_cert.public_key()
	try:
		pub.verify(
			cert.signature,
			cert.tbs_certificate_bytes,
			padding.PKCS1v15(),
			cert.signature_hash_algorithm,
		)
		return True
	except Exception:
		return False


def is_within_validity(cert: x509.Certificate, now: datetime | None = None) -> bool:
	"""Return True if certificate is within its not_valid_before/after window."""
	if now is None:
		now = datetime.utcnow()
	# cert.not_valid_before / not_valid_after are timezone-naive in this project
	return cert.not_valid_before <= now <= cert.not_valid_after


def matches_cn_or_san(cert: x509.Certificate, expected_cn: str) -> bool:
	"""Return True if `expected_cn` matches certificate CN or DNS SAN entries."""
	# Check CN
	try:
		cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
		if cn_attrs:
			cn = cn_attrs[0].value
			if cn == expected_cn:
				return True
	except Exception:
		pass

	# Check SAN DNS names
	try:
		ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
		for name in ext.value.get_values_for_type(x509.DNSName):
			if name == expected_cn:
				return True
	except x509.ExtensionNotFound:
		pass
	except Exception:
		pass

	return False


def validate_certificate(cert_pem: Union[str, bytes], ca_pem: Union[str, bytes], expected_cn: str | None = None) -> None:
	"""Validate certificate against the CA and optional expected CN.

	Raises ValueError with a short reason on failure. Returns None on success.
	Reasons:
	  - 'BAD_SIGNATURE' : signature does not verify under CA
	  - 'EXPIRED'       : certificate is outside validity window
	  - 'CN_MISMATCH'   : expected CN not found in CN or SAN
	"""
	cert = load_pem_cert(cert_pem)
	ca = load_pem_cert(ca_pem)

	if not is_signed_by(cert, ca):
		raise ValueError("BAD_SIGNATURE")

	if not is_within_validity(cert):
		raise ValueError("EXPIRED")

	if expected_cn is not None and not matches_cn_or_san(cert, expected_cn):
		raise ValueError("CN_MISMATCH")

	# all checks passed
	return None

