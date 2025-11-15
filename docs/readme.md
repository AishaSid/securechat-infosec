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

## Git: commit & push

Suggested commands and commit message:

```powershell
git add -A
git commit -m "Add CA/cert generation; implement PKI validation and RSA sign/verify test"
git push origin main
```

# Step 3 
