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




