import os
import pytest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.crypto import pki


ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), '..'))
CERTS_DIR = os.path.join(ROOT, 'certs')


def _path(name: str) -> str:
    return os.path.join(CERTS_DIR, name)


def _ensure_ca_files():
    ca_cert = _path('ca-cert.crt')
    ca_key = _path('ca-private.key')
    if not (os.path.exists(ca_cert) and os.path.exists(ca_key)):
        pytest.skip('CA cert/key not found in certs/ – skipping expiry test')
    return ca_cert, ca_key


def test_expired_certificate_raises():
    ca_cert_path, ca_key_path = _ensure_ca_files()

    # load CA private key
    with open(ca_key_path, 'rb') as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # create a new RSA key for the test cert
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # build an expired certificate (validity entirely in the past)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'expired.local')])
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now - timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    # validation should raise EXPIRED
    with pytest.raises(ValueError) as exc:
        pki.validate_certificate(cert_pem, ca_cert_path)
    assert str(exc.value) == 'EXPIRED'
