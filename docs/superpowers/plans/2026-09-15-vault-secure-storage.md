# UNG-VAULT Secure Storage V2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build encrypted persistent file storage, three access-security levels, secure sharing, and a functional JANUS-authorized VAULT administration portal.

**Architecture:** PostgreSQL owns file/share/policy metadata and audit state while a storage adapter owns ciphertext payloads. Per-file keys encrypt file data; recipient credentials wrap/unlock access without persisting plaintext credentials. Existing object APIs remain compatible while new stored-file, share, verification, and admin APIs are introduced in focused modules.

**Tech Stack:** FastAPI, PostgreSQL/psycopg, cryptography, JANUS bearer authentication, Python multipart uploads, existing VAULT audit/key-management components.

**Spec:** `docs/superpowers/specs/2026-09-15-vault-secure-storage-design.md`

## Global Constraints
- Never persist plaintext file content.
- Never log plaintext, access codes, OTPs, secret/recovery keys, decrypted content, or encryption keys.
- Preserve existing `/vault/objects`, `/vault/files/encrypt`, `/vault/files/decrypt`, and `/audit/verify` behavior.
- Level 3 must remain identity-bound through JANUS and may not degrade to anonymous code-only access.
- Every authorization, sharing, verification, decryption, policy, and admin mutation is audited.

---

### Task 1: Storage schema and repository
**Files:** Create `app/file_store.py`; modify `app/db.py`; create `tests/test_file_store.py`.
- [ ] Write failing tests for encrypted-object metadata, owner scoping, lifecycle state, and ciphertext-only persistence.
- [ ] Add PostgreSQL migrations/init statements for stored files, shares, verification grants, second-person approvals, and policy records.
- [ ] Implement storage repository interfaces and local durable ciphertext adapter with a configurable storage root.
- [ ] Run focused tests and commit.

### Task 2: File cryptography and access-code wrapping
**Files:** Create `app/file_crypto.py`; test `tests/test_file_crypto.py`.
- [ ] Write failing round-trip, wrong-code, and tamper tests.
- [ ] Implement per-file random DEKs, authenticated file encryption, memory-hard code KDF, wrapped DEKs, and secret-key wrapping.
- [ ] Ensure raw credentials never enter persisted metadata.
- [ ] Run focused tests and commit.

### Task 3: Stored-file API and My Vault
**Files:** Create `app/files_api.py`; modify `app/main.py`; modify `ui/index.html`; test `tests/test_files_api.py`.
- [ ] Write API tests for upload/list/metadata/download/rename/archive/delete and owner isolation.
- [ ] Implement upload -> encrypt -> persist ciphertext transaction and stored-file lifecycle endpoints.
- [ ] Add My Vault UI with upload, search, file inventory, security level, sharing state, expiration and access history.
- [ ] Verify no plaintext permanent object exists after upload; commit.

### Task 4: Level 1 sharing
**Files:** Create `app/sharing.py`; modify `app/main.py`; modify `ui/index.html`; test `tests/test_sharing.py`.
- [ ] Write tests for share creation, correct/wrong code, expiration, access limits and revocation.
- [ ] Implement secure share IDs, code-based unlock, rate-limited failures, revocation and download limits.
- [ ] Add Share/Send UI and recipient decrypt screen.
- [ ] Run tests and commit.

### Task 5: Level 2 second factors
**Files:** Create `app/verification.py`; modify `app/sharing.py`; modify UI; test `tests/test_verification.py`.
- [ ] Write tests for code+email confirmation and code+secret-key flows, including expiration/replay rejection.
- [ ] Implement single-use short-lived verification grants and email-confirmation provider interface.
- [ ] Implement recovery/secret-key possession verification.
- [ ] Run tests and commit.

### Task 6: Level 3 TOP SECRET policy
**Files:** Create `app/security_policy.py`; modify `app/sharing.py`; test `tests/test_security_policy.py`.
- [ ] Write tests requiring JANUS identity, code, strong-auth/MFA evidence, clearance, compartment, recipient restriction and optional second-person approval.
- [ ] Implement policy evaluator with deny-by-default behavior.
- [ ] Implement approval lifecycle and audit events.
- [ ] Run tests and commit.

### Task 7: Functional Admin Portal
**Files:** Create `app/admin_api.py`; create `ui/admin.html`; modify `ui_portal.py`; test `tests/test_admin_api.py`.
- [ ] Write authorization tests proving non-admins cannot invoke admin mutations.
- [ ] Implement inventory/utilization, shares, revoke/expire, code invalidation, retention, quarantine, policy, failed-access and audit-search endpoints.
- [ ] Add functional Admin UI wired to those APIs.
- [ ] Verify admin metadata privilege does not bypass file plaintext policy; commit.

### Task 8: Audit, regression, and production acceptance
**Files:** modify tests as required; update `README.md`.
- [ ] Add audit assertions for every new sensitive event.
- [ ] Run the full existing and new test suite.
- [ ] Test existing `.ungvault` round trip for backward compatibility.
- [ ] Test Level 1/2/3 end-to-end flows, tamper rejection, expired/revoked access and admin authorization.
- [ ] Document production storage/KMS configuration and deployment variables.
- [ ] Commit final acceptance evidence before merge/deployment.
