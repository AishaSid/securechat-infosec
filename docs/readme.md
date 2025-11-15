# Quick Commands — SecureChat (one command per bash block)

Follow these commands in separate bash shells (one command per code block). Adjust paths/env as needed.

- Create and activate a virtual environment (Bash):

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

- Install dependencies:

```bash
pip install -r requirements.txt
```

- Copy example environment file:

```bash
cp .env.example .env
```

- (Optional) Start MySQL via Docker (recommended):

```bash
docker run -d --name securechat-db -e MYSQL_ROOT_PASSWORD=rootpass -e MYSQL_DATABASE=securechat -e MYSQL_USER=scuser -e MYSQL_PASSWORD=scpass -p 3306:3306 mysql:8
```

- Create database tables (runs app storage init):

```bash
python -m app.storage.db --init
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

- (Optional) Verify issued certificate against CA using OpenSSL:

```bash
openssl verify -CAfile certs/ca-cert.crt certs/server-cert.crt
```

- Run the server (in a new terminal):

```bash
python -m app.server
```

- Run the client (in another terminal):

```bash
python -m app.client
```

Notes
- The project intentionally implements application-layer crypto; do NOT use `ssl` wrappers.
- Generated certs and private keys are stored under `certs/` — do not commit them.
- If your platform uses PowerShell instead of Bash, replace `source .venv/bin/activate` with:

```bash
.venv\Scripts\Activate.ps1
```
