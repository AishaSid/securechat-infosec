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
import threading
import sys


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


def handle_client(conn: socket.socket, server_cert: bytes, server_priv, key: bytes, client_cert: bytes, *, ca_path: str | None = None, server_cert_path: str | None = None) -> None:
    # send server certificate
    if ca_path is None:
        ca_path = os.getenv("CA_PATH", "certs/ca-cert.crt")
    if server_cert_path is None:
        server_cert_path = os.getenv("SERVER_CERT", "certs/server-cert.crt")

    # send an encrypted welcome message (first message)
    welcome = b"Welcome from server"
    sig = sign_mod.sign_bytes(server_priv, welcome) if server_priv is not None else b""
    payload = len(sig).to_bytes(2, "big") + sig + welcome
    nonce, ct = aes.encrypt(key, payload)
    _send_bytes(conn, nonce + ct)

    # store server-sent transcript entry
    try:
        transcript_db = os.getenv("TRANSCRIPT_DB", "transcripts.db")
        transcript_store.init_db(transcript_db)
        sender_cn = "server"
        try:
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

    # start receiver thread to handle incoming messages continuously
    stop_flag = threading.Event()

    def receiver():
        while not stop_flag.is_set():
            try:
                resp = _recv_bytes(conn)
            except Exception:
                break
            if not resp:
                break
            recv_nonce = resp[:12]
            recv_ct = resp[12:]
            try:
                pt = aes.decrypt(key, recv_nonce, recv_ct)
                if len(pt) >= 2:
                    siglen = int.from_bytes(pt[:2], "big")
                    sig = pt[2:2+siglen]
                    message = pt[2+siglen:]
                else:
                    sig = b""
                    message = pt

                verified = False
                try:
                    pub = sign_mod.load_public_key_from_cert(client_cert)
                    verified = sign_mod.verify_bytes(pub, message, sig)
                except Exception:
                    verified = False

                print("\n[client]", message.decode(errors='replace'), "(signature OK:", verified, ")")

                # store received transcript entry
                try:
                    transcript_db = os.getenv("TRANSCRIPT_DB", "transcripts.db")
                    transcript_store.init_db(transcript_db)
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
                print("Decryption/verify failed:", e)

    t_recv = threading.Thread(target=receiver, daemon=True)
    t_recv.start()

    # sender loop reads from stdin and sends messages until EOF or /quit
    try:
        print("Enter messages to send to client. Type /quit to exit.")
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            text = line.rstrip('\n')
            if text == '/quit':
                break
            data = text.encode()
            sig = sign_mod.sign_bytes(server_priv, data) if server_priv is not None else b""
            payload = len(sig).to_bytes(2, "big") + sig + data
            nonce, ct = aes.encrypt(key, payload)
            try:
                _send_bytes(conn, nonce + ct)
            except Exception:
                break
            # store server-sent transcript
            try:
                transcript_db = os.getenv("TRANSCRIPT_DB", "transcripts.db")
                transcript_store.init_db(transcript_db)
                sender_cn = "server"
                try:
                    from cryptography import x509
                    from cryptography.x509.oid import NameOID
                    cert = x509.load_pem_x509_certificate(server_cert)
                    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    if cn_attrs:
                        sender_cn = cn_attrs[0].value
                except Exception:
                    pass
                transcript_store.add_entry(transcript_db, sender_cn, server_cert, data, ct, nonce, sig)
            except Exception:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        stop_flag.set()
        try:
            conn.close()
        except Exception:
            pass


def main(host: str | None = None, port: int | None = None) -> None:
    if host is None:
        host = os.getenv("HOST", "127.0.0.1")
    if port is None:
        port = int(os.getenv("PORT", "9000"))

    ca_path = os.getenv("CA_PATH", "certs/ca-cert.crt")
    server_cert_path = os.getenv("SERVER_CERT", "certs/server-cert.crt")
    server_key_path = os.getenv("SERVER_KEY", "certs/server-private.key")

    server_cert = open(server_cert_path, "rb").read()
    try:
        server_priv = sign_mod.load_private_key(server_key_path)
    except Exception:
        server_priv = None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        print(f"Server listening on {host}:{port}")
        conn, addr = s.accept()
        with conn:
            print("Accepted connection from", addr)

            # exchange certificates
            _send_bytes(conn, server_cert)
            client_cert = _recv_bytes(conn)

            # perform X25519 key exchange
            priv, pub = dh.generate_keypair()
            peer_pub = _recv_bytes(conn)
            _send_bytes(conn, pub)

            secret = dh.derive_shared_secret(priv, peer_pub)
            key = dh.derive_aes_key_from_shared(secret, info=b"securechat handshake", length=32)

            # hand off to interactive handler
            handle_client(conn, server_cert, server_priv, key, client_cert, ca_path=ca_path, server_cert_path=server_cert_path)


if __name__ == "__main__":
    main()
