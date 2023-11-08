# OpenID Provider

This is a minimal OpenID Connect protocol implementation with a sqlite backing store for user accounts.

This service acts as the OpenID Provider (OP) in the OpenID Connect protocol.

The implementation currently implements the following specs:

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html): only the Authorization Code Flow is supported

Limitations of the implementation:

- TLS is delegated to a reverse proxy. Since OpenID Connect requires TLS for various interactions you MUST operate a reverse proxy in front of this service.
- The provider does not implement persistent sessions: if an authorization request is received, the user will always have to login. It is up to the client to maintain a session if so desired.
