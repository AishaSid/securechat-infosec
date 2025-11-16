"""Simple demo client that pairs with `app/server.py` demo server. It
exchanges certificates, validates the server cert, performs X25519 ECDH,
derives an AES key, receives an encrypted welcome message, and replies with
an encrypted acknowledgement.
"""

import os
import socket
from dotenv import load_dotenv

load_dotenv()

from app.crypto import pki, dh, aes, sign as sign_mod
from storage import transcript as transcript_store
import threading
import sys


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
        _send_bytes(s, pub)
        peer_pub = _recv_bytes(s)

        secret = dh.derive_shared_secret(priv, peer_pub)
        key = dh.derive_aes_key_from_shared(secret, info=b"securechat handshake", length=32)

        # receive encrypted welcome
        enc = _recv_bytes(s)
        nonce = enc[:12]
        ct = enc[12:]
        try:
            pt = aes.decrypt(key, nonce, ct)
            # extract signature length and signature
            if len(pt) >= 2:
                siglen = int.from_bytes(pt[:2], "big")
                sig = pt[2:2+siglen]
                message = pt[2+siglen:]
            else:
                sig = b""
                message = pt

            # verify server signature against received server_cert
            verified = False
            try:
                pub = sign_mod.load_public_key_from_cert(server_cert)
                verified = sign_mod.verify_bytes(pub, message, sig)
            except Exception:
                verified = False

            print("Server says:", message, "signature OK:", verified)

            # store received transcript entry
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
                transcript_store.add_entry(transcript_db, sender_cn, server_cert, message, ct, nonce, sig)
            except Exception:
                pass
        except Exception as e:
            print("Failed to decrypt server message:", e)

        # load client private key (if available)
        client_key_path = os.getenv("CLIENT_KEY", "certs/client-private.key")
        try:
            client_priv = sign_mod.load_private_key(client_key_path)
        except Exception:
            client_priv = None

        # send initial acknowledgement
        ack = b"Hello from client"
        sig = sign_mod.sign_bytes(client_priv, ack) if client_priv is not None else b""
        payload = len(sig).to_bytes(2, "big") + sig + ack
        nonce2, ct2 = aes.encrypt(key, payload)
        _send_bytes(s, nonce2 + ct2)

        # store client-sent transcript entry
        try:
            transcript_db = os.getenv("TRANSCRIPT_DB", "transcripts.db")
            transcript_store.init_db(transcript_db)
            sender_cn = "client"
            try:
                from cryptography import x509
                from cryptography.x509.oid import NameOID
                cert = x509.load_pem_x509_certificate(cert_bytes)
                cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_attrs:
                    sender_cn = cn_attrs[0].value
            except Exception:
                pass
            transcript_store.add_entry(transcript_db, sender_cn, cert_bytes, ack, ct2, nonce2, sig)
        except Exception:
            pass

        # start receiver thread to handle incoming messages continuously
        stop_flag = threading.Event()

        def receiver():
            while not stop_flag.is_set():
                try:
                    resp = _recv_bytes(s)
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
                        pub = sign_mod.load_public_key_from_cert(server_cert)
                        verified = sign_mod.verify_bytes(pub, message, sig)
                    except Exception:
                        verified = False

                    print("\n[server]", message.decode(errors='replace'), "(signature OK:", verified, ")")

                    # store received transcript entry
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
                        transcript_store.add_entry(transcript_db, sender_cn, server_cert, message, recv_ct, recv_nonce, sig)
                    except Exception:
                        pass
                except Exception as e:
                    print("Decryption/verify failed:", e)

        t_recv = threading.Thread(target=receiver, daemon=True)
        t_recv.start()

        # sender loop reads from stdin and sends messages until EOF or /quit
        try:
            print("Enter messages to send to server. Type /quit to exit.")
            while True:
                line = sys.stdin.readline()
                if not line:
                    break
                text = line.rstrip('\n')
                if text == '/quit':
                    break
                data = text.encode()
                sig = sign_mod.sign_bytes(client_priv, data) if client_priv is not None else b""
                payload = len(sig).to_bytes(2, "big") + sig + data
                nonce, ct = aes.encrypt(key, payload)
                try:
                    _send_bytes(s, nonce + ct)
                except Exception:
                    break
                # store client-sent transcript
                try:
                    transcript_db = os.getenv("TRANSCRIPT_DB", "transcripts.db")
                    transcript_store.init_db(transcript_db)
                    sender_cn = "client"
                    try:
                        from cryptography import x509
                        from cryptography.x509.oid import NameOID
                        cert = x509.load_pem_x509_certificate(cert_bytes)
                        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                        if cn_attrs:
                            sender_cn = cn_attrs[0].value
                    except Exception:
                        pass
                    transcript_store.add_entry(transcript_db, sender_cn, cert_bytes, data, ct, nonce, sig)
                except Exception:
                    pass
        except KeyboardInterrupt:
            pass
        finally:
            stop_flag.set()
            try:
                s.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
