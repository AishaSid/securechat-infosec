"""Simple demo server that performs a certificate exchange + X25519 ECDH
and then sends/receives AES-GCM encrypted messages. This is a minimal demo
to integrate the crypto helpers implemented in `app/crypto`.
"""

import os
import socket
from typing import Tuple

from dotenv import load_dotenv

load_dotenv()  # load .env file if present

from app.crypto import pki, dh, aes


def _send_bytes(conn: socket.socket, data: bytes) -> None:
    n = len(data).to_bytes(4, "big")
    conn.sendall(n + data)


def _recv_bytes(conn: socket.socket) -> bytes:
    length = conn.recv(4)
    if not length or len(length) < 4:
        raise ConnectionError("failed to read length")
    n = int.from_bytes(length, "big")
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


def handle_client(conn: socket.socket, *, ca_path: str | None = None, server_cert_path: str | None = None) -> None:
    # send server certificate
    if ca_path is None:
        ca_path = os.getenv("CA_PATH", "certs/ca-cert.crt")
    if server_cert_path is None:
        server_cert_path = os.getenv("SERVER_CERT", "certs/server-cert.crt")

    server_cert = open(server_cert_path, "rb").read()
    _send_bytes(conn, server_cert)

    # receive client certificate
    client_cert = _recv_bytes(conn)
    # validate client certificate (signed by CA)
    try:
        pki.validate_certificate(client_cert, ca_path)
    except ValueError as e:
        print("Client certificate validation failed:", e)
        conn.close()
        return

    # perform X25519 key exchange
    priv, pub = dh.generate_keypair()
    # send our public bytes
    _send_bytes(conn, pub)
    peer_pub = _recv_bytes(conn)

    secret = dh.derive_shared_secret(priv, peer_pub)
    key = dh.derive_aes_key_from_shared(secret, info=b"securechat handshake", length=32)

    # send an encrypted welcome message
    nonce, ct = aes.encrypt(key, b"Welcome from server")
    _send_bytes(conn, nonce + ct)

    # receive encrypted response
    resp = _recv_bytes(conn)
    recv_nonce = resp[:12]
    recv_ct = resp[12:]
    try:
        pt = aes.decrypt(key, recv_nonce, recv_ct)
        print("Received from client:", pt)
    except Exception as e:
        print("Decryption failed:", e)


def main(host: str = None, port: int = None) -> None:
    # read from environment if not provided
    if host is None:
        host = os.getenv("HOST", "127.0.0.1")
    if port is None:
        port = int(os.getenv("PORT", "9000"))

    print(f"Server listening on {host}:{port}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print("Accepted connection from", addr)
            handle_client(conn)


if __name__ == "__main__":
    main()
