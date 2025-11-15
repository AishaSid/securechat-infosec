"""Test script: sign a message with server private key and verify with server cert."""
import sys
from pathlib import Path
import base64

# Ensure project root is on sys.path so the local 'app' package can be imported when running this script directly
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.crypto import sign


def main():
    msg = b"The quick brown fox jumps over the lazy dog"

    priv_path = "certs/server-private.key"
    cert_path = "certs/server-cert.crt"

    print("Loading private key from:", priv_path)
    priv = sign.load_private_key(priv_path)

    print("Signing message...")
    sig = sign.sign_bytes(priv, msg)
    b64 = base64.b64encode(sig).decode()
    print("Signature (base64):", b64)

    print("Loading public key from cert:", cert_path)
    pub = sign.load_public_key_from_cert(cert_path)

    print("Verifying signature...")
    ok = sign.verify_bytes(pub, msg, sig)
    print("Verification result:", ok)

    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
