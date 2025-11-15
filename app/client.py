"""Simple demo client that pairs with `app/server.py` demo server. It
exchanges certificates, validates the server cert, performs X25519 ECDH,
derives an AES key, receives an encrypted welcome message, and replies with
an encrypted acknowledgement.
"""

import os
import socket
from dotenv import load_dotenv

load_dotenv()

from app.crypto import pki, dh, aes


def _send_bytes(s: socket.socket, data: bytes) -> None:
    s.sendall(len(data).to_bytes(4, "big") + data)


def _recv_bytes(s: socket.socket) -> bytes:
    length = s.recv(4)
    if not length or len(length) < 4:
        raise ConnectionError("failed to read length")
    n = int.from_bytes(length, "big")
    buf = bytearray()
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


def main(host: str = None, port: int = None, *, ca_path: str | None = None, client_cert: str | None = None) -> None:
    if host is None:
        host = os.getenv("HOST", "127.0.0.1")
    if port is None:
        port = int(os.getenv("PORT", "9000"))
    if ca_path is None:
        ca_path = os.getenv("CA_PATH", "certs/ca-cert.crt")
    if client_cert is None:
        client_cert = os.getenv("CLIENT_CERT", "certs/client-cert.crt")

    with socket.create_connection((host, port)) as s:
        # receive server certificate
        server_cert = _recv_bytes(s)
        try:
            pki.validate_certificate(server_cert, ca_path)
        except ValueError as e:
            print("Server certificate validation failed:", e)
            return

        # send client certificate
        cert_bytes = open(client_cert, "rb").read()
        _send_bytes(s, cert_bytes)

        # perform X25519
        priv, pub = dh.generate_keypair()
        peer_pub = _recv_bytes(s)
        _send_bytes(s, pub)

        secret = dh.derive_shared_secret(priv, peer_pub)
        key = dh.derive_aes_key_from_shared(secret, info=b"securechat handshake", length=32)

        # receive encrypted welcome
        enc = _recv_bytes(s)
        nonce = enc[:12]
        ct = enc[12:]
        try:
            pt = aes.decrypt(key, nonce, ct)
            print("Server says:", pt)
        except Exception as e:
            print("Failed to decrypt server message:", e)

        # send encrypted acknowledgement
        nonce2, ct2 = aes.encrypt(key, b"Hello from client")
        _send_bytes(s, nonce2 + ct2)


if __name__ == "__main__":
    main()
