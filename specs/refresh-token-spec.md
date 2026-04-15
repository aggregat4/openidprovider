# Refresh Token Implementation Specification

## Status

Draft 1

## Goal

Add end-to-end refresh token support to this OpenID Provider without changing its character.

This implementation should remain:

- focused on the existing authorization code flow
- limited to already configured confidential clients that authenticate with HTTP Basic auth at the token endpoint
- backed by SQLite persistence
- simple enough to reason about and test

This implementation should not try to become a general-purpose commercial OAuth platform.

## Current State

Today the server:

- supports the authorization code flow
- requires confidential clients to authenticate to `/token` with HTTP Basic auth
- stores one-time authorization codes in SQLite
- issues an opaque `access_token` and a signed `id_token`
- rejects any `grant_type` other than `authorization_code`

Today the server does not:

- issue refresh tokens
- persist access tokens
- expose a revocation endpoint
- advertise `grant_types_supported` or revocation metadata in discovery

## Scope

This feature includes:

- issuing refresh tokens for eligible authorization code exchanges
- accepting `grant_type=refresh_token` at `/token`
- rotating refresh tokens on every successful refresh
- revoking refresh tokens explicitly and implicitly
- revoking entire token families on detected replay
- cleaning up expired and revoked refresh token records
- updating discovery metadata
- adding tests for normal flow, rotation, revocation, expiry, and replay

This feature explicitly does not include:

- public-client refresh token support
- DPoP
- mutual TLS
- dynamic client registration
- access token introspection
- a user-facing consent UI beyond what the project already has
- arbitrary client policies or per-client refresh token customization

## Standards and Design Inputs

This design is guided by:

- OAuth 2.0, RFC 6749
- OAuth 2.0 Token Revocation, RFC 7009
- OpenID Connect Core 1.0, Section 12
- OAuth 2.0 Security Best Current Practice, RFC 9700

Important consequences for this project:

- confidential clients must authenticate when refreshing tokens
- refresh tokens must be unguessable and protected in transit and at rest
- refresh tokens must remain bound to the client they were issued to
- refresh tokens for a simple browser-oriented implementation should use rotation and replay detection
- revocation should not leak whether a token existed

## Product Positioning

This IDP should issue refresh tokens only when they improve the current login experience for first-party style confidential web clients.

This means:

- only the existing confidential clients in `registeredclients` are eligible
- the implementation should default to issuing refresh tokens for the authorization code flow once enabled
- a future policy knob may disable refresh token issuance globally or per client, but that is not required for the first version

Because this project does not currently expose a protected resource server with token introspection, refresh token support is primarily about allowing the client to get a fresh `id_token` and replacement opaque `access_token` without forcing the user through `/authorize` again.

## High-Level Behavior

### Authorization Code Exchange

When a confidential client exchanges a valid authorization code at `/token` with `grant_type=authorization_code`, the server shall:

1. validate client authentication exactly as it does today
2. validate and consume the authorization code exactly once
3. load the user and scope claims as it does today
4. issue:
   - a new opaque `access_token`
   - a new signed `id_token`
   - a new opaque `refresh_token`
5. persist the refresh token record before returning the response

The token response shall include:

- `access_token`
- `token_type` = `Bearer`
- `id_token`
- `expires_in`
- `refresh_token`

`expires_in` should be added now because refresh tokens are most useful when paired with a clear access token lifetime contract.

### Refresh Grant

When a confidential client posts to `/token` with `grant_type=refresh_token`, the server shall:

1. require client authentication with the existing Basic auth mechanism
2. require a `refresh_token` form field
3. load the refresh token record by token identifier
4. reject the request with `invalid_grant` if the token:
   - does not exist
   - is expired
   - is revoked
   - is already rotated away
   - belongs to a different client
   - belongs to a deleted user
5. load the user and granted scopes from stored token state, not from client input
6. issue a replacement:
   - `access_token`
   - `id_token`
   - `refresh_token`
7. rotate refresh token state atomically:
   - mark the presented token as rotated/revoked
   - create the replacement token
   - preserve family linkage for replay detection

The refresh request shall not accept scope escalation. The response scope is the originally granted scope set.

## Token Model

### Refresh Token Format

Refresh tokens should be opaque random strings, not self-contained JWTs.

Rationale:

- the project already uses opaque random strings for authorization codes and access tokens
- opaque tokens keep revocation and rotation logic server-side
- opaque tokens avoid unnecessary signing and claim design complexity

Token generation requirement:

- use a cryptographically secure random value with at least 256 bits of entropy, encoded for transport

UUIDs are not sufficient for refresh tokens in this design. Use a stronger random token generator than the current UUID-based access token/code style.

### Stored Refresh Token Record

Add a new persisted refresh token entity with fields equivalent to:

- `token_hash`
- `token_hint_prefix`
- `client_id`
- `email`
- `scopes`
- `created_at`
- `last_used_at`
- `expires_at`
- `revoked_at`
- `revoke_reason`
- `replaced_by_token_hash`
- `family_id`

Notes:

- store only a hash of the refresh token, not the raw token
- `token_hint_prefix` is an optional short prefix from the clear token used only to make debugging easier in logs and admin tooling
- `family_id` identifies all rotated descendants of the same original grant
- `replaced_by_token_hash` links one token to its replacement

### Hashing Requirement

The server should hash refresh tokens before storing them using SHA-256 over the raw token bytes.

This is sufficient for a high-entropy opaque token generated server-side. A password hash is not required because the token is already random and unguessable. The purpose is to reduce damage if the database leaks.

## Persistence

### New Table

Add a `refresh_tokens` table with indexes for:

- lookup by `token_hash`
- cleanup by `expires_at`
- cleanup/reporting by `revoked_at`
- family revocation by `family_id`
- user cleanup by `email`

Suggested schema shape:

```sql
CREATE TABLE refresh_tokens (
    token_hash TEXT NOT NULL PRIMARY KEY,
    token_hint_prefix TEXT NOT NULL,
    family_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    email TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revoke_reason TEXT,
    replaced_by_token_hash TEXT,
    FOREIGN KEY (email) REFERENCES users(email)
);

CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_email ON refresh_tokens(email);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_revoked_at ON refresh_tokens(revoked_at);
```

### Repository API

Add repository operations for:

- creating a refresh token
- finding a refresh token by presented raw token
- rotating a refresh token in one transaction
- revoking one refresh token
- revoking an entire family
- revoking all refresh tokens for a user
- deleting expired refresh tokens
- deleting revoked refresh tokens older than a retention window

Rotation must be transactional. The old token cannot remain valid if the new token was returned.

## Rotation and Replay Detection

### Rotation Policy

Every successful refresh request shall rotate the refresh token.

That means:

- the presented token becomes unusable immediately
- the response includes a new refresh token
- the new token belongs to the same `family_id`

### Replay Detection

If a refresh request presents a token that has already been rotated and therefore has a non-null `replaced_by_token_hash`, the server shall treat this as potential replay.

On detected replay:

1. revoke the entire token family
2. return `invalid_grant`
3. log the event at warning or error level with client ID, user email, family ID, and reason

This is intentionally strict. It matches the simple security posture recommended for refresh token rotation and avoids trying to distinguish an attacker from a legitimate client.

## Expiration Policy

The first version should use fixed global lifetimes instead of per-client policy.

Recommended defaults:

- access token lifetime: 5 minutes
- refresh token absolute lifetime: 30 days
- refresh token inactivity timeout: 7 days since last successful use

Refresh token validity check should fail if either:

- `expires_at` is in the past
- `last_used_at` is older than the inactivity window

On successful rotation:

- the new token gets a fresh inactivity window
- the family does not extend indefinitely past the absolute lifetime unless explicitly chosen

To keep the implementation simple and bounded, the first version should preserve an absolute family lifetime based on the original issuance time. In other words, refreshing extends inactivity, not total lifetime.

## Revocation

### Revocation Endpoint

Add `POST /revoke`.

This endpoint should:

- require client authentication with the same Basic auth rules as `/token`
- accept `token`
- optionally accept `token_type_hint`
- always return success for syntactically valid requests, even if the token is unknown or already revoked

Initial supported revocation target:

- refresh tokens

Behavior for unsupported or unknown `token_type_hint`:

- ignore the hint and attempt refresh-token lookup
- still return success

This keeps the implementation aligned with RFC 7009 behavior without requiring access token persistence in version 1.

### Implicit Revocation Events

The server shall revoke refresh tokens automatically when:

- a refresh token replay event is detected
- a user changes their password
- a user deletes their account

The server should revoke refresh tokens automatically when:

- the user explicitly logs out in a future server-side logout flow

### Revocation Scope

For simplicity, the first version should revoke all refresh tokens for the user on password reset.

Rationale:

- password reset is a strong security signal
- this project does not need fine-grained session management yet
- revoking all user refresh tokens is easier to reason about than revoking only one family

For explicit `/revoke`, only the targeted token family needs to be revoked.

## Discovery Metadata

Extend the discovery document to advertise the new capability.

Add at least:

- `grant_types_supported`: `["authorization_code", "refresh_token"]`
- `revocation_endpoint`: `<baseUrl>/revoke`
- `revocation_endpoint_auth_methods_supported`: `["client_secret_basic"]`

If the current discovery struct does not expose these fields yet, extend it conservatively rather than attempting a full discovery metadata implementation.

## Error Handling

### Token Endpoint

For refresh grant failures, return OAuth token errors consistent with the current style:

- `invalid_client` for failed client authentication
- `invalid_request` for missing required form fields
- `invalid_grant` for expired, revoked, replayed, or mismatched refresh tokens
- `unsupported_grant_type` for unknown grant types

### Revocation Endpoint

Return:

- `200 OK` for valid authenticated revocation requests regardless of whether the token was found
- `401 Unauthorized` if client authentication fails
- `400 Bad Request` only for malformed requests that do not meet the endpoint contract at all

## Logging and Privacy

The implementation must not log raw refresh tokens.

Allowed log fields:

- client ID
- email
- family ID
- token hint prefix
- revoke reason

Disallowed log fields:

- full refresh token
- hashed token value

## Configuration

The first version should avoid introducing many knobs.

Add only these configuration fields if needed:

- `jwt.accessTokenValidityMinutes`
- `jwt.refreshTokenAbsoluteValidityHours`
- `jwt.refreshTokenInactivityValidityHours`

If keeping these under `jwt` feels misleading, a new `tokens` section is acceptable. What matters more is keeping the config surface small and obvious.

## Handler Changes

### `/token`

Refactor the current token handler into:

- `handleAuthorizationCodeGrant`
- `handleRefreshTokenGrant`

Shared token response creation should move into a helper so that authorization code and refresh flows issue tokens consistently.

### `/revoke`

Add a new handler and route:

- `POST /revoke`

It should use the same client authentication middleware as `/token`.

## Cleanup

Extend the cleanup job to:

- delete expired refresh tokens
- optionally delete old revoked refresh token records after a retention period, for example 30 days

Retention is useful for diagnosing replay or abuse, but the first version should keep it simple and bounded.

## Security Requirements

The implementation must satisfy these requirements:

- refresh tokens are only issued to confidential clients supported by the current implementation
- refresh tokens are generated from cryptographically secure random data
- refresh tokens are stored hashed, not in cleartext
- refresh tokens are bound to the authenticated client that received them
- refresh requests require client authentication
- refresh token rotation happens on every successful refresh
- replay of a rotated token revokes the whole family
- refresh token scope cannot exceed the original authorization grant
- refresh token failures do not leak whether a token belonged to another client or user
- raw refresh tokens are never logged
- refresh token exchange and revocation must only be served over TLS in deployment

## Testing Requirements

Add tests for at least:

- authorization code exchange returns `refresh_token`
- refresh token exchange returns a new `refresh_token`
- old refresh token cannot be reused after rotation
- reuse of a rotated token revokes the active family member
- revoked refresh token returns `invalid_grant`
- expired refresh token returns `invalid_grant`
- refresh token bound to client A cannot be used by client B
- `/revoke` succeeds for an active refresh token
- `/revoke` is idempotent for unknown or already revoked tokens
- password reset revokes all refresh tokens for the user

## Migration Plan

Implementation should proceed in this order:

1. add database migration and repository methods
2. add token generation and hashing helpers
3. refactor `/token` into per-grant handlers
4. implement refresh issuance for authorization code exchange
5. implement refresh token rotation and replay handling
6. add `/revoke`
7. update discovery metadata
8. extend cleanup job
9. add tests

## Open Questions

These decisions should be made before implementation starts:

1. Should refresh tokens be issued for every confidential client by default, or only when the `offline_access` scope is requested?
2. Should `offline_access` be introduced as a real scope in this project, or is that unnecessary complexity for the current audience?
3. Should access tokens remain purely opaque and non-persisted in version 1, with revocation limited to refresh tokens?

## Recommended Decisions for Version 1

To stay in the spirit of this project, version 1 should choose:

- issue refresh tokens for confidential authorization-code clients without introducing `offline_access` yet
- keep access tokens opaque and non-persisted
- support revocation for refresh tokens only
- use rotation plus family revocation on replay
- revoke all user refresh tokens on password reset and account deletion

This yields a coherent end-to-end feature with manageable code and test scope.
