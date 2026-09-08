# UNG-VAULT

UNG-VAULT is the Uganda National Grid secure data vault service.

## Security model
- AES-256-GCM envelope encryption with a unique DEK and nonce per object.
- JANUS-compatible signed JWT access claims with clearance and compartment checks.
- PostgreSQL persistence only; production fails closed when required configuration is missing.
- Tamper-evident hash-chained audit log, including denied-access events.
- Health and readiness endpoints for production orchestration.

## Run
```bash
pip install -r requirements.txt
export DATABASE_URL=postgresql://...
export VAULT_MASTER_KEY_B64=$(python -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')
export JANUS_JWT_PUBLIC_KEY='-----BEGIN PUBLIC KEY-----...'
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

`/health` is process liveness. `/ready` verifies configuration and database connectivity.

## Production
Use Dockerfile or deploy the repository directly. Never commit production keys. Rotate VAULT_MASTER_KEY_B64 through a managed secrets/KMS workflow and provision JANUS verification material through the deployment platform.
