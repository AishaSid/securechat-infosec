````markdown
# Quick Commands — SecureChat 

- Install dependencies:

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
