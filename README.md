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


## Selective redaction
VAULT also supports audited, irreversible sharing copies for PDF, PNG and JPEG files.

- Choose a redaction level from 0% to 95%.
- VAULT generates deterministic black redaction blocks covering approximately that percentage of each page/image.
- PDF redaction removes underlying text/image content before export; it is not just a visual overlay.
- Every redaction export is written to the VAULT audit chain with the selected percentage.
- Redaction is **not encryption** and is not reversible. Keep the original protected with VAULT encryption if it must remain recoverable.

Endpoint:
```
POST /vault/files/redact
multipart/form-data:
  file=<PDF/PNG/JPEG>
  percentage=<0..95>
```


## Code-protected sharing packages
VAULT can create a single `.ungshare` package containing:
- an irreversible redacted preview at the sender-selected percentage; and
- the complete original encrypted with AES-256-GCM under a key derived from the sender's full-access code using scrypt.

The access code is never stored in the package or written to the audit log. A receiver with the matching code can use VAULT's Full-access unlock workflow to recover the exact original file. Without the code, only the redacted preview is available.

Security notes:
- Minimum access-code length: 12 characters.
- Sender should deliver the code through a separate channel from the file.
- Wrong-code attempts fail authentication and are audit-logged.
- Redaction remains irreversible; the full view comes from decrypting the separately encrypted original embedded in the package, not from reversing redaction.


## Full-file encryption bypass
Selective redaction is optional. UNG-VAULT always keeps a direct full-file encryption path that applies **no redaction at all**.

- UI: choose **Full encryption only — no redaction**.
- API: use `POST /vault/files/encrypt`.
- Output: a normal `.ungvault` encrypted package containing the complete original.
- The redaction percentage is ignored because no redaction step runs.
- Decryption uses the existing authenticated `POST /vault/files/decrypt` workflow.

This guarantees that redaction never replaces or blocks VAULT's original full-file encryption capability.


## Digital SCIF mode
UNG-VAULT includes a high-assurance Digital SCIF viewing mode for restricted and top-secret objects.

Digital SCIF is a software containment control. It does **not** replace or claim physical ICD 705 accreditation, RF/TEMPEST shielding, acoustic isolation, or other facility controls.

Controls implemented:
- JANUS top-secret clearance and explicit SCIF entitlement.
- MFA-authenticated session requirement.
- JANUS trusted-device posture requirement.
- Compartment authorization remains mandatory.
- Time-limited sessions from 5 to 120 minutes.
- Optional **SCIF + two-person control** requiring two independent SCIF-authorized approvers.
- Session owner cannot self-approve.
- Secure, HttpOnly, SameSite=Strict SCIF entry cookie.
- No-store/no-cache response policy and restrictive CSP/permissions policy.
- Browser-side print, copy, cut, paste, save and context-menu deterrence.
- Dynamic viewer/session/timestamp watermarking.
- Server-side decryption only for the active request; plaintext is not persisted to a SCIF workspace.
- Session close/revocation endpoint and expiration enforcement.
- Tamper-evident audit events for creation, approvals, entry, viewing, denied entry and closure.

Browser controls cannot guarantee prevention of operating-system-level screenshots or photography. Watermarking provides attribution/deterrence when capture cannot be technically prevented.

Typical flow:
```
JANUS identity + MFA + trusted device
  -> top-secret clearance + compartment
  -> create SCIF session
  -> optional independent approvals
  -> enter controlled viewer
  -> session expires / closes / is revoked
```


### Continuous SCIF authorization
Active SCIF viewing is continuously re-authorized against JANUS rather than relying only on the original entry decision.

- The JANUS bearer context is stored only as a VAULT-encrypted session envelope.
- Every SCIF view request performs a fresh JANUS introspection before plaintext is released.
- The controlled viewer sends a same-origin authorization heartbeat every 15 seconds.
- Each check re-validates identity, SCIF entitlement, MFA state, trusted-device posture, clearance and compartment access.
- If identity or authorization is revoked or changes, VAULT revokes the SCIF session and destroys the stored encrypted JANUS context.
- If JANUS is temporarily unavailable, the viewer fails closed immediately but the session is not permanently revoked solely because of the outage.
- Closing, revoking or expiring a session destroys the stored SCIF authorization envelope.


### SCIF device/session binding
Digital SCIF sessions are bound to the trusted device and browser context used at entry.

- VAULT records a one-way device-binding hash at SCIF entry.
- When JANUS exposes a trusted device identifier, that identity becomes part of the binding.
- Stable browser/device signals are included without binding to source IP, so normal roaming and VPN changes do not automatically terminate a legitimate session.
- Every SCIF view and 15-second heartbeat re-checks the device binding.
- A JANUS device identity change or browser/device mismatch immediately revokes the session, destroys the encrypted SCIF authorization envelope, and writes a tamper-evident audit event.
- Copying only the SCIF cookie/session token to a different browser or device is therefore insufficient to continue viewing.
