import os
import pytest

from app.crypto import pki


CERT_DIR = os.path.join(os.path.dirname(__file__), "..", "certs")
CERT_DIR = os.path.normpath(CERT_DIR)


def _path(name: str) -> str:
    return os.path.join(CERT_DIR, name)


def _ensure_certs():
    # minimal existence checks for CA and an entity cert
    ca = _path("ca-cert.crt")
    server = _path("server-cert.crt")
    if not (os.path.exists(ca) and os.path.exists(server)):
        pytest.skip("certs not found in project `certs/` – skip PKI tests")
    return ca, server


def test_validate_signed_certificate():
    ca, server = _ensure_certs()
    # should not raise for a valid cert signed by the CA
    pki.validate_certificate(server, ca)


def test_validate_cn_mismatch_raises():
    ca, server = _ensure_certs()
    # request a CN that almost certainly doesn't exist in the cert
    with pytest.raises(ValueError) as exc:
        pki.validate_certificate(server, ca, expected_cn="__nonexistent_cn__")
    assert str(exc.value) == "CN_MISMATCH"


def test_validate_with_wrong_ca_fails_signature():
    ca, server = _ensure_certs()
    # use the server cert as a bogus CA -> signature verification must fail
    with pytest.raises(ValueError) as exc:
        pki.validate_certificate(server, server)
    assert str(exc.value) == "BAD_SIGNATURE"
