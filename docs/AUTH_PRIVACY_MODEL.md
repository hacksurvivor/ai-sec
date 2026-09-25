# Auth Privacy Model (Anti-Deanonymization)

This auth service is built to reduce profile linkability and passive identity correlation.

## Threats Addressed

- Cross-service account linking by stable identifiers.
- Replay of stolen long-lived session credentials.
- Metadata-rich logs becoming a correlation oracle.

## Controls Implemented

- Pairwise pseudonymous subjects: `sub = HMAC(user_id, audience)`.
- Short-lived access tokens with audience scoping.
- Rotating refresh tokens with replay/reuse detection.
- Argon2id password hashing.
- Minimal logging with hashed user identifiers (`emailHash`) and no raw email.
- Generic login failures (`invalid_grant`) to reduce user enumeration.

## Current Limitations (MVP)

- In-memory persistence only.
- No MFA/WebAuthn yet.
- No hardware-backed key management.
- No device binding for proof-of-possession.

## Production Hardening Path

1. Move `AuthStore` to Postgres with transactional rotation/revocation.
2. Store secrets in KMS/HSM and rotate signing keys (`kid` + JWKS).
3. Add WebAuthn/passkeys and optional step-up challenge.
4. Add IP/device risk scoring and adaptive auth policies.
5. Add per-tenant data isolation and retention/erasure workflows.
