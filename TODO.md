# TODO

## OIDC an OAuth Features

* Support `prompt` with the value `none` in the authorization request by immediately returning an error (since we always reauthenticate, and in this case we shouldn't)
* Support `nonce` in the authorization request (and all the way through ID token generation)
* Go through all the security considerations of the OAuth 2 spec and verify whether additional measures are needed

## Scopes and Claims ❌

We need to support our own services that require something like a set of 'groups' associated with a user so we can distinguish between various kinds of users with different capabilities. The way to implement that is with scopes and claims:

* ❌ implement scopes and claims generically
  * ❌ Database Changes:
    * ❌ Create tables for scopes and claims
    * ❌ Create a table for storing claim values per user
  * ❌ Configuration Changes:
    * ❌ Add configuration for supported scopes and their associated claims
  * ❌ Repository Layer Changes:
    * ❌ Add methods for managing user claim values
    * ❌ Add methods for managing scopes and claims
  * ❌ Authorization Endpoint Changes:
    * ❌ Validate requested scopes against configured scopes
    * ❌ Store requested scopes with the authorization code
  * ❌ Token Endpoint Changes:
    * ❌ Generate claims based on requested scopes
    * ❌ Include claims in ID token
  * ❌ Testing:
    * ❌ Add tests for scope validation
    * ❌ Add tests for claims generation
  * ❌ Documentation:
    * ❌ Update OpenID configuration to include supported scopes
    * ❌ Add documentation for supported scopes and claims

## User Management CLI ❌

Expand the existing createuser command into a comprehensive user management tool:

* ❌ Rename `createuser` to `usermgmt` to reflect its broader purpose
* ❌ Add subcommands:
  * ❌ User Management:
    * ❌ `create` - Create a new user (existing functionality)
    * ❌ `delete` - Delete a user
    * ❌ `list` - List all users
    * ❌ `show` - Show details of a specific user
    * ❌ `set-password` - Change a user's password
  * ❌ Claim Management:
    * ❌ `set-claim` - Set a claim value for a user
    * ❌ `remove-claim` - Remove a claim value from a user
    * ❌ `list-claims` - List all claims for a user
  * ❌ Scope Management:
    * ❌ `create-scope` - Create a new scope
    * ❌ `delete-scope` - Delete a scope
    * ❌ `list-scopes` - List all scopes
    * ❌ `add-claim-to-scope` - Add a claim to a scope
    * ❌ `remove-claim-from-scope` - Remove a claim from a scope
    * ❌ `list-scope-claims` - List all claims for a scope
* ❌ Add common flags:
  * ❌ `--db` - Database file path
  * ❌ `--username` - Username for operations
  * ❌ `--json` - Output in JSON format
* ❌ Add proper error handling and validation
* ❌ Add documentation for each subcommand

## Misc Improvements

* Implement a `.well-known/change-password` endpoint as per <https://w3c.github.io/webappsec-change-password-url/> that can be used by password managers tot automatically redirect and trigger a password change flow.
* the config file parsing is case sensitive and this can lead to unnecessary errors. Can we make it parse it case insensitively?
* we need to make the experience for registered users better: once the registration flow is complete and they log in they currently just land on the main page but there is no sesion and no indication that they are logged into their account. First of all we need sessions for the openidprovider and then we need to provide a different experience for logged in users where they can manage their account and see details about their account
