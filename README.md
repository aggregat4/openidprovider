# OpenID Provider

This is a minimal OpenID Connect protocol implementation with a sqlite backing store for user accounts.

This service acts as the OpenID Provider (OP) in the OpenID Connect protocol.

The implementation currently implements the following specs:

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html): only the Authorization Code Flow is supported

Limitations of the implementation:

- TLS is delegated to a reverse proxy. Since OpenID Connect requires TLS for various interactions you MUST operate a reverse proxy in front of this service.
- The provider does not implement persistent sessions: if an authorization request is received, the user will always have to login. It is up to the client to maintain a session if so desired.
- Unsupported Authorization Request parameters:
  - `response_mode`
  - `display`
  - `prompt`: At the moment the server _always_ reauthenticates the user and we _don't_ immediately return an error if prompt is `none`
  - `max_age`
  - `ui_locales`
  - `id_token_hint`
  - `login_hint`
  - `acr_values`
- The provider does not support passing request parameters as JWTs as per <https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests>

## TODO

- Support `prompt` with the value `none` in the authorization request by immediately returning an error (since we always reauthenticate, and in this case we shouldn't)
- Support `nonce` in the authorization request
- Go through all the security considerations of the OAuth 2 spec and verify whether additional measures are needed