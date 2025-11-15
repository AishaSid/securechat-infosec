````markdown
# Quick Commands — SecureChat 

# Step 1 - Scripts 

Install dependencies:

```bash
pip install -r requirements.txt
```

- Generate Root CA (example name):

```bash
python scripts/gen_ca.py --name "FAST-NU Root CA"
```

- Issue server certificate (signed by Root CA):

```bash
python scripts/gen_cert.py --cn server.local --out certs/server
```

- Issue client certificate (signed by Root CA):

```bash
python scripts/gen_cert.py --cn client.local --out certs/client
```

Notes
- Generated certs and private keys are stored under `certs/` 
```bash
python scripts/gen_ca.py --name "FAST-NU Root CA"
```
# Step 2 - PKI

- **What was added:**  `app/crypto/pki.py` (X.509 validation helpers), `app/crypto/sign.py` (RSA sign/verify helpers), and `scripts/test_sign.py` (sign & verify demo).

- **How to run the implemented features (PowerShell):**

```powershell
# Run CA creation (if not already created)
python scripts/gen_ca.py --name "FAST-NU Root CA"

# Issue server and client certs
python scripts/gen_cert.py --cn server.local --out certs/server
python scripts/gen_cert.py --cn client.local --out certs/client

# Run sign/verify test
python scripts/test_sign.py
```

Expected result: the test prints a base64 signature and `Verification result: True`.


# Step 3 — AES / DH (Key agreement + AEAD)

- **What was added:** `app/crypto/aes.py` (AES-GCM encrypt/decrypt + HKDF key derivation), `app/crypto/dh.py` (X25519 ECDH helpers), and `scripts/test_aes_dh.py` (end-to-end DH key agreement + AES-GCM encrypt/decrypt test).

- **How to run the AES/DH test (PowerShell):**

```powershell
# Run DH + AES quick test
python scripts/test_aes_dh.py
```

Expected result (example):
- `Shared secrets equal: True`
- `Encrypted (len): <n> nonce: <hex>`
- `Decrypted matches: True`

Notes:
- The DH helper uses X25519 (Curve25519) to derive a raw shared secret; HKDF-SHA256 derives an AES key from that secret.
- AES-GCM is used for authenticated encryption (nonce length = 12 bytes). Keep nonces unique per key.

## Configuration via `.env`

You can set runtime values in a `.env` file at the repository root (an example `.env` is provided). The server and client read these variables automatically using `python-dotenv`.

Key variables:
- `HOST` — server bind address (default `127.0.0.1`)
- `PORT` — server port (default `9000`)
- `CA_PATH` — path to Root CA certificate (default `certs/ca-cert.crt`)
- `SERVER_CERT` — server certificate path (default `certs/server-cert.crt`)
- `CLIENT_CERT` — client certificate path (default `certs/client-cert.crt`)


# Step 4 — Client / Server Demo (integration)

- **What was added:**
	- `app/server.py` and `app/client.py` — simple TCP demo that exchanges certificates, validates them against the Root CA, performs X25519 ECDH, derives an AES key via HKDF, and exchanges AES‑GCM encrypted messages.
	- `scripts/run_demo.py` — helper that starts the server in a background thread and runs the client to perform one handshake (useful for a single-run demo).

- **How to run the demo (PowerShell):**

```powershell
# Option A: run the combined demo (one-shot)
python scripts/run_demo.py

# Option B: run server and client separately (two terminals)
# Terminal 1 (server)
python -c "from app import server; server.main()"
# Terminal 2 (client)
python -c "from app import client; client.main()"
```

- **Expected clean output:**

```
Server listening on 127.0.0.1:9000
Accepted connection from ('127.0.0.1', <port>)
Server says: b'Welcome from server'
Received from client: b'Hello from client'
```

- **Notes / configuration:**
	- The demo reads `.env` values for `HOST`, `PORT`, and certificate paths if present. See the `.env` sample earlier in this README.
	- The client and server validate certificates using `app/crypto/pki.py` (signature + validity window). By default CN/SAN matching is not enforced in the demo; enable it by passing `expected_cn` to `validate_certificate` if you require a strict name check.

- **Suggested git commit for integration:**

```powershell
git add app/server.py app/client.py scripts/run_demo.py docs/readme.md
git commit -m "Integrate DH/AES and PKI: add client/server demo and run_demo helper"
git push origin main
```





