# OpenID Provider

This project is a small OpenID Connect provider backed by SQLite. It is intentionally focused on a narrow, understandable feature set instead of trying to be a full commercial identity platform.

It acts as the OpenID Provider (OP) for confidential clients and currently centers on the authorization code flow, signed ID tokens, opaque access tokens, and rotating refresh tokens.

## Current Feature Set

- OpenID Connect discovery at `/.well-known/openid-configuration`
- JWKS publishing at `/.well-known/jwks.json`
- Authorization code flow for configured confidential clients
- Client authentication at `/token` and `/revoke` via HTTP Basic auth
- Signed ID tokens using RS256 and an RSA keypair
- Opaque access tokens with a configured lifetime
- Opaque refresh tokens with:
  - secure random generation
  - SHA-256 hashing at rest
  - rotation on every successful refresh
  - family revocation on replay detection
  - explicit revocation through `POST /revoke`
- Scope and claim support backed by SQLite
- Built-in account management flows:
  - registration with email verification
  - password reset
  - account deletion verification
- Background cleanup for expired authorization codes, verification tokens, and refresh tokens

## Protocol Behavior

### Supported OAuth/OIDC flows

- `authorization_code`
- `refresh_token`

### Token behavior

- `access_token`
  - opaque
  - not persisted
  - returned with `expires_in`
- `id_token`
  - signed with RS256
  - includes standard issuer, subject, audience, issued-at, and expiry claims
  - includes `auth_time` for the authenticated session family
  - includes configured user claims for the granted scopes
- `refresh_token`
  - issued to confidential clients on successful code exchange
  - rotated on every successful refresh
  - bound to the client that received it
  - revoked for the whole token family if a rotated token is replayed

### Revocation behavior

- `POST /revoke` supports refresh-token revocation
- revocation is idempotent and does not reveal whether a token existed
- password reset revokes all refresh tokens for the user
- account deletion removes the user and their refresh tokens

## User and Claim Model

Users are stored in SQLite and identified by email.

Scopes and claims are also stored in SQLite. The server currently seeds:

- `openid`
- `profile`
- `email`

Claims are resolved dynamically from the current database state when issuing ID tokens. Refresh token families snapshot granted scope names, not claim values, so refreshed ID tokens pick up changed claim values for the same granted scopes.

## Running the Server

Build all binaries:

```bash
./scripts/build.sh
```

Run the server with the example configuration:

```bash
go run cmd/server/main.go --config example-config.jsonc
```

Run the test suite:

```bash
./scripts/test.sh
```

Run linting:

```bash
./scripts/lint.sh
```

## Configuration Notes

Use `example-config.jsonc` as the starting point.

Important settings include:

- registered confidential clients and their Basic auth secrets
- RSA private/public key files for ID token signing and JWKS
- token lifetime settings under `jwt`
  - `idtokenvalidityminutes`
  - `accesstokenvalidityminutes`
  - `refreshtokeninactivityvalidityhours`
- SMTP settings for registration, password reset, and delete-account emails

## Security Model and Limits

- TLS is still required in deployment. This service expects TLS termination at a reverse proxy.
- The server does not maintain persistent OP login sessions. Each authorization request reauthenticates the user.
- Only configured confidential clients are supported. Public clients are not supported.
- Access token introspection is not implemented.
- Access tokens are opaque and non-persisted.
- Revocation currently applies to refresh tokens only.
- Dynamic client registration is not supported.
- DPoP, mutual TLS, and logout/session management are not supported.

## Unsupported Authorization Request Parameters

The authorization endpoint still does not implement:

- `nonce`
- `display`
- `prompt`
- `max_age`
- `ui_locales`
- `id_token_hint`
- `login_hint`
- `acr_values`

Request objects as JWTs are also not supported.

## ID Token Notes

ID tokens are signed with RS256. The implementation remains intentionally small and does not currently add:

- `at_hash`
- `acr`
- `amr`

`auth_time` is now emitted based on the original successful authentication for the token family.
