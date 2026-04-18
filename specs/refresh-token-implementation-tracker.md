# Refresh Token Implementation Tracker

Status against [refresh-token-spec.md](./refresh-token-spec.md).

## Plan

- [x] Review the spec and map it onto the current server, repository, discovery, cleanup, and account-management code.
- [x] Add refresh-token persistence, shared token helpers, cleanup/revocation repository methods, and token lifetime config.
- [x] Refactor `/token` into grant-specific handlers and issue refresh tokens on authorization-code exchange.
- [x] Implement refresh-token rotation, replay detection, and family revocation.
- [x] Add `POST /revoke` and advertise refresh/revocation metadata in discovery.
- [x] Revoke refresh tokens on password reset and account deletion.
- [x] Extend cleanup to remove expired and old revoked refresh-token records.
- [x] Add tests for issuance, refresh, replay, revocation, expiry, wrong-client handling, concurrency, and discovery metadata.

## Notes

- Version 1 follows the spec's recommended defaults: refresh tokens are issued to existing confidential clients without introducing `offline_access`.
- Access tokens remain opaque and non-persisted in this version.
