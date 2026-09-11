# UNG-VAULT

UNG-VAULT is the Uganda National Grid secure data vault service.

## Security model
- AES-256-GCM envelope encryption with a unique DEK and nonce per object.
- Pluggable key-wrapping backends: local AES master key, AWS KMS, Google Cloud KMS, or HashiCorp Vault Transit.
- New ciphertext uses envelope format v2 with provider/key identity; legacy v1 envelopes remain decryptable when the legacy master key is available.
- JANUS live token introspection with clearance and compartment checks.
- PostgreSQL persistence only; production fails closed when required configuration is missing.
- Tamper-evident hash-chained audit log, including denied-access events.
- Health and readiness endpoints for production orchestration.

## Run
```bash
pip install -r requirements.txt
export DATABASE_URL=postgresql://...
export JANUS_INTROSPECT_URL=https://janus.example/v1/auth/introspect
export VAULT_KEY_BACKEND=local
export VAULT_MASTER_KEY_B64=$(python -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

`/health` is process liveness. `/ready` verifies configuration and database connectivity.

## Production key backends
Set `VAULT_KEY_BACKEND` to exactly one of the following:

### AWS KMS
```bash
export VAULT_KEY_BACKEND=aws-kms
export AWS_KMS_KEY_ID=arn:aws:kms:REGION:ACCOUNT:key/KEY_ID
```
Use the runtime's AWS IAM role/identity; do not store long-lived AWS credentials in the repository.

### Google Cloud KMS
```bash
export VAULT_KEY_BACKEND=gcp-kms
export GCP_KMS_KEY_NAME=projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY
```
Use Application Default Credentials or the workload identity assigned to the runtime.

### HashiCorp Vault Transit
```bash
export VAULT_KEY_BACKEND=hashicorp-vault
export HASHICORP_VAULT_ADDR=https://vault.example
export HASHICORP_VAULT_TOKEN=...
export HASHICORP_VAULT_TRANSIT_KEY=ung-vault-dek
export HASHICORP_VAULT_TRANSIT_MOUNT=transit
```
Prefer a short-lived workload token supplied by the deployment platform.

### Legacy v1 ciphertext
If existing v1 objects must remain readable after switching to a managed KMS backend, continue supplying the previous `VAULT_MASTER_KEY_B64` during the migration window. It is used only to unwrap legacy v1 DEKs.

## Production
Use the Dockerfile or deploy the repository directly. Never commit production keys or provider credentials. Grant the VAULT runtime only encrypt/decrypt permission on the specific KMS/Transit key it needs.
