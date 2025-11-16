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

---

# Step 5a — Storage / Transcript (implemented)

- Implementations provided in this repository:
	- `storage/db.py` — MySQL-backed user store (functions: `init_db()`, `create_user()`, `verify_user()`, `change_password()`) and a small CLI for `--init`, `--add`, `--verify`, `--change`.
	- `storage/transcript.py` — SQLite append-only transcript store and verifier (`init_db()`, `add_entry()`, `list_entries()`, `verify_entry()`, `verify_all()`), plus a small CLI to list/verify entries.

- Quick initialization commands (PowerShell):

	- Initialize the MySQL `users` table (reads DB credentials from `.env`):

		```powershell
		# If you have Docker Desktop running, use the helper to create a local MySQL and init the table
		.\scripts\init_mysql_local.ps1

		# OR, if a MySQL server is already accessible (and .env contains credentials):
		python -m storage.db --init
		```

	- Initialize the transcript SQLite DB (creates `transcripts.db` by default):

		```powershell
		python -c "from dotenv import load_dotenv; load_dotenv(); import storage.transcript as t; t.init_db('transcripts.db'); print('transcript DB initialized')"
		```

# Step 5b - DB integration 

This project uses two storage backends:

- **MySQL (`storage/db.py`)** — stores application user accounts (`users` table). Use the provided helper to initialize the schema and manage users.
- **SQLite `transcripts.db` (`storage/transcript.py`)** — append-only transcript log where chat ciphertexts, signatures and sender certificates are stored for offline verification and non-repudiation.

What to do for the assignment:

- Initialize the MySQL users table (reads DB credentials from `.env`):

	```powershell
	# use the helper to start a local MySQL container and initialize the schema
	.\scripts\init_mysql_local.ps1

	# or, if you already have a MySQL server and .env is configured:
	python -m storage.db --init
	```

- Create a user (example):

	```powershell
	# interactive (prompts for password)
	python -m storage.db --add alice

	# programmatic (non-interactive)
	python - <<'PY'
	from dotenv import load_dotenv
	load_dotenv()
	import storage.db as db
	print('created id:', db.create_user('alice','TestPass123!'))
	PY
	```

- Initialize the transcript DB (SQLite):

	```powershell
	python -c "from dotenv import load_dotenv; load_dotenv(); import storage.transcript as t; t.init_db('transcripts.db'); print('transcript DB initialized')"
	```

- Run the demo to generate transcripts and then export them into readable JSON:

	```powershell
	# run the one-shot demo (generates transcript entries)
	python scripts/run_demo.py

	# export all transcripts to human-readable JSON files (exports/)
	python scripts/export_transcripts.py --all --db transcripts.db --out exports
	```

	The exporter produces files like `exports/transcript_1.json` containing:
	- `cert_pem` (PEM string)
	- `signature_b64` / `signature_hex`
	- `ciphertext_b64` / `ciphertext_hex`
	- `nonce_b64` / `nonce_hex`
	- `message_utf8` (if plaintext was recorded) or `message_hash_sha256`
	- `verified` (boolean: result of verifying the signature and certificate against the CA)

Security & privacy notes
- The transcript log currently stores plaintext `message` when the application records it. If you require privacy, consider storing only `ciphertext` + `signature` + `cert_pem` and a `message_hash` (SHA-256) instead of plaintext.
- Protect `transcripts.db` and MySQL credentials: do not commit secrets to the repository. Use filesystem protections and an appropriate retention policy for stored transcripts.

Inspecting data
- Quick checks:
	- List transcripts:
		```powershell
		python -m storage.transcript transcripts.db --list
		```
	- Verify all transcripts against the CA:
		```powershell
		python -m storage.transcript transcripts.db --verify-all --ca certs/ca-cert.crt
		```

- Quick initialization commands (PowerShell):

	- Initialize the MySQL `users` table (reads DB credentials from `.env`):

		```powershell
		# If you have Docker Desktop running, use the helper to create a local MySQL and init the table
		.\scripts\init_mysql_local.ps1

		# OR, if a MySQL server is already accessible (and .env contains credentials):
		python -m storage.db --init
		```

	- Initialize the transcript SQLite DB (creates `transcripts.db` by default):

		```powershell
		python -c "from dotenv import load_dotenv; load_dotenv(); import storage.transcript as t; t.init_db('transcripts.db'); print('transcript DB initialized')"
		```

- Verify stored transcripts (example):

	```powershell
	# List entries
	python -m storage.transcript transcripts.db --list

	# Verify all entries using the CA certificate
	python -m storage.transcript transcripts.db --verify-all --ca certs/ca-cert.crt

# Step 6 — Tamper Tests & Replay Detection

- **Purpose:** Demonstrate that stored transcripts are tamper-evident and to exercise replay-detection and session receipts added to the storage layer.
- **Where:** authoritative tamper/debug scripts are under `tests/tamper/`.

- Scripts and usage:
	- `tests/tamper/tamper_transcript.py` — flip a byte in a transcript row (ciphertext, signature, or message), creating a timestamped backup of the DB first. Example:

		```powershell
		# tamper the signature of entry id=3
		python .\tests\tamper\tamper_transcript.py --db transcripts.db --id 3 --field signature --xor 01
		```

	- `tests/tamper/tamper_debug.py` — helper that copies a source DB to `tests/transcripts_test.db`, prints verification for a chosen entry, flips a signature byte, and prints verification again (useful for reproducing report output):

		```powershell
		python .\tests\tamper\tamper_debug.py --src transcripts.db --db tests\transcripts_test.db --id 3 --xor 01
		```

- **Expected behavior:**
	- Before tamper: `verify_entry -> True` (if the CA and certs are available and signatures match)
	- After tamper: `verify_entry -> False` (signature/ciphertext mismatch should be detected)

- **Replay detection & receipts:**
	- The transcript module includes `detect_replays()` which looks for duplicated ciphertext/nonce pairs and signature re-use across different messages. Run it from a small script or import `storage.transcript.detect_replays` to inspect suspicious entries.
	- The server now issues a signed session receipt at session end. Receipts are stored in the `session_receipts` table in the DB. Use `storage.session.create_receipt(...)` and `storage.session.verify_receipt(...)` to create and verify receipts programmatically.

- **Quick workflow to produce evidence for the report:**
	1. Initialize transcripts: `python -c "import storage.transcript as t; t.init_db('transcripts.db')"`
 2. Run the demo to produce transcript entries: `python .\tests\demo\run_demo.py` (or the one-shot `python scripts/run_demo.py` stub which points to `tests/demo`)
 3. Run the debug tamper script to reproduce verification failure: `python .\tests\tamper\tamper_debug.py --src transcripts.db --id 3`
 4. Export transcripts (optional): `python .\tests\tools\export_transcripts.py --all --db transcripts.db --out exports`

- **Security note:** tamper tests operate on copies or create backups; do not run destructive tamper commands against production or canonical DBs unless you intend to alter them. The `tamper_transcript.py` script creates a `.bak.<ts>` backup before modifying the DB.
	```

Notes:
- `storage/db.py` reads DB connection parameters from `.env` (or environment): `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` (defaults are `127.0.0.1:3306`, `scuser`, `scpass`, `securechat`).
- `storage/transcript.py` stores full certificate PEMs and signatures in the SQLite `transcripts` table as BLOBs; `verify_entry()` validates the cert against the CA and checks the signature.



