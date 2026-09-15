# UNG-VAULT Secure Storage V2 Design

## Goal
Expand UNG-VAULT from protected-object/file processing into an encrypted document repository with secure sharing, three security levels, and a functional administrative portal.

## Core storage rule
Plaintext is never persisted in permanent storage. Upload flow is: receive file -> encrypt -> persist encrypted payload. PostgreSQL stores metadata, authorization state, share state, and audit records; the storage backend stores ciphertext only.

## Security levels
### Level 1 · PROTECTED
Access code is required to decrypt a shared file. Codes are never embedded in plaintext in the package and are stored only as hardened verifier/key-wrapping material. Failed attempts are audited and rate-limited.

### Level 2 · RESTRICTED
Requires the access code plus one configured second factor: short-lived email confirmation OR possession of a secret/recovery key. Verification is single-use where applicable and expires.

### Level 3 · TOP SECRET
Requires JANUS authenticated identity, access code, MFA/strong-auth evidence, JANUS clearance and compartment authorization, and all configured recipient restrictions. Policy can additionally require second-person approval before plaintext release. Every verification gate must pass.

## My Vault storage
Authenticated users receive a My Vault interface for upload, encrypted storage, folders/logical organization, search, download, rename, archive/delete, security-level assignment, expiration, sharing state, and access history. File records include owner, original filename, media type, byte size, encrypted-object location, security level, created/updated timestamps, retention state, and cryptographic metadata.

## Sharing
Owners can create revocable shares with recipient restrictions, expiration, download/access limits, and Level 1/2 access-code flows. Sharing supports secure links plus downloading the encrypted .ungvault package for out-of-band delivery. Level 3 shares remain identity-bound and cannot become anonymous code-only links.

## Cryptography
Use authenticated encryption through the existing VAULT crypto/key-management boundary. Per-file random data-encryption keys protect file bytes. Access codes derive key-encryption material using a memory-hard password KDF with random salt; raw codes are never stored. The server master/key-encryption boundary remains separate from recipient credentials. Integrity failure returns no plaintext.

## Administration
Add a JANUS-authorized VAULT Admin Portal with real server-side functions: file metadata inventory, encrypted-storage utilization, active/revoked/expired shares, revoke/expire actions, compromised-code invalidation, security-level policy controls, retention/archive controls, failed-access investigation, audit-event search, and quarantine controls. Admin metadata access does not automatically grant plaintext file access; plaintext release still follows file security policy.

## Audit requirements
Audit upload/encryption, file retrieval, share creation, share access, failed code/factor attempts, successful verification, decrypt/download, rename, archive/delete, expiration, revocation, policy changes, admin actions, and integrity failures. Existing audit-chain verification remains supported.

## Safety and operational controls
Apply upload-size limits, normalized filenames, content-disposition hardening, no-store responses for plaintext, rate limiting/lockouts for credential attempts, short-lived verification grants, revocable shares, and cryptographic integrity checks. Do not log plaintext, access codes, secret keys, email OTP values, decrypted file contents, or encryption keys.

## Compatibility
Preserve existing protected-object endpoints and existing .ungvault encrypt/decrypt workflow while adding stored-file and sharing APIs. JANUS remains the identity/clearance authority. VAULT remains the encryption/key-material boundary and is not conflated with other storage systems.

## Acceptance
1. Uploading a file creates an encrypted stored object and never a persisted plaintext object.
2. Level 1 decrypt succeeds only with the correct code.
3. Level 2 requires code plus its configured second factor.
4. Level 3 requires authenticated multi-verification and clearance/compartment policy.
5. Revoked/expired shares cannot release plaintext.
6. Admin actions are authorization-protected and audited.
7. Tampered ciphertext is rejected.
8. Existing object and file encrypt/decrypt functionality continues to work.
