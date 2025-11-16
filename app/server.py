"""Simple demo server that performs a certificate exchange + X25519 ECDH
and then sends/receives AES-GCM encrypted messages. This is a minimal demo
to integrate the crypto helpers implemented in `app/crypto`.
"""

import os
import socket
from typing import Tuple

from dotenv import load_dotenv

load_dotenv()  # load .env file if present

from app.crypto import pki, dh, aes, sign as sign_mod
from storage import transcript as transcript_store
import base64


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

    # load server private key for signing outgoing messages
    server_key_path = os.getenv("SERVER_KEY", "certs/server-private.key")
    try:
        server_priv = sign_mod.load_private_key(server_key_path)
    except Exception:
        server_priv = None

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
    welcome = b"Welcome from server"
    # sign the welcome message with server long-term key if available
    sig = sign_mod.sign_bytes(server_priv, welcome) if server_priv is not None else b""
    payload = len(sig).to_bytes(2, "big") + sig + welcome
    nonce, ct = aes.encrypt(key, payload)
    _send_bytes(conn, nonce + ct)

    # store server-sent transcript entry
    try:
        transcript_db = os.getenv("TRANSCRIPT_DB", "transcripts.db")
        transcript_store.init_db(transcript_db)
        # sender_cn from server cert
        sender_cn = "server"
        try:
            # attempt to extract CN
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            cert = x509.load_pem_x509_certificate(server_cert)
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attrs:
                sender_cn = cn_attrs[0].value
        except Exception:
            pass
        transcript_store.add_entry(transcript_db, sender_cn, server_cert, welcome, ct, nonce, sig)
    except Exception:
        pass

    # receive encrypted response
    resp = _recv_bytes(conn)
    recv_nonce = resp[:12]
    recv_ct = resp[12:]
    try:
        pt = aes.decrypt(key, recv_nonce, recv_ct)
        # payload format: 2-byte siglen | signature | plaintext
        if len(pt) >= 2:
            siglen = int.from_bytes(pt[:2], "big")
            sig = pt[2:2+siglen]
            message = pt[2+siglen:]
        else:
            sig = b""
            message = pt

        # verify signature using client_cert
        verified = False
        try:
            pub = sign_mod.load_public_key_from_cert(client_cert)
            verified = sign_mod.verify_bytes(pub, message, sig)
        except Exception:
            verified = False

        print("Received from client:", message, "signature OK:" , verified)

        # store received transcript entry (signed by client)
        try:
            transcript_db = os.getenv("TRANSCRIPT_DB", "transcripts.db")
            transcript_store.init_db(transcript_db)
            # extract client CN if possible
            sender_cn = "client"
            try:
                from cryptography import x509
                from cryptography.x509.oid import NameOID
                cert = x509.load_pem_x509_certificate(client_cert)
                cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_attrs:
                    sender_cn = cn_attrs[0].value
            except Exception:
                pass
            transcript_store.add_entry(transcript_db, sender_cn, client_cert, message, recv_ct, recv_nonce, sig)
        except Exception:
            pass
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
