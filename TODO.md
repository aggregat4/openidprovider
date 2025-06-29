# TODO

## Switch to a new transactional email provider

Ask mailpace whether I can be on the free plan?

## See how hard it would be to migrate away from Echo to a plain go webserver with gorilla sessions and chi router (or whatever router is du jour)


## Fixes

  * verify why the demo setup login does not work, it says invalid credentials even if I use the same user and password used for created the demo db

## OIDC an OAuth Features

  * Support `prompt` with the value `none` in the authorization request by immediately returning an error (since we always reauthenticate, and in this case we shouldn't)
  * Support `nonce` in the authorization request (and all the way through ID token generation)
  * Go through all the security considerations of the OAuth 2 spec and verify whether additional measures are needed

## Self-Registration ✅

### Allow **registration**
  * ✅ add register link to login page
  * ✅ add a registration page
    * ✅ allow specifying email and password (2 times) on that page
    * ✅ registering triggers a queued verification email
      * ✅ send the mail using Sendgrid
  * ✅ when a valid verification code is provided the user is registered and redirected to the login page
  * ✅ a cleanup job must be run to remove unverified users after a certain amount of time

### Allow **forgot password** ✅
  * ✅ add forgot password link to login page
  * ✅ allow specifying email
  * ✅ sending a forgot password email triggers a queued verification email
  * ✅ when a valid verification code is provided the user is redirected to the registration page to provide a new password
    * ✅ in this case we don't send the verification email since we already verified it

### Allow **delete account** ✅
  * ✅ add delete account link to login page
  * ✅ clicking on the delete button triggers a queued verification email
  * ✅ when a valid verification code is provided the user is deleted and redirected to the login page
  * ✅ cleanup of all user-related data (verification tokens, authorization codes)

### Email sending debounce logic and abuse prevention ❌
	* ✅ We need general debounce logic for all email sending:
	  * ✅ we need to back off sending the next mail to the same address when we already sent one in the last X minutes, this should progressively get longer and only be done at max 3 times per hour
	  * ✅ we need a global limit to the number of emails we send in total (per day) as it would otherwise exhaust the subscription we have
	* ✅ if a user already exists here and is verified, we should pretend to register and do nothing (or should we send confirmation email to the user?)
	* ✅ if a user already exists and is not verified, we should send another verification email as per the debouncing logic above
	* ✅ we should also have some upper bound to the number of verification emails that can be sent to an email address and then block that address from trying more verifications for a certain period of time
  * ❌ write tests for all the email cleanup, backoff and blocking logic

### Registration Spam Protection

  * Integrate the ALTCHA Go library and the frontend component and test whether it works for a self-hosted captcha solution: the [Open Source Option from the website](https://altcha.org/docs/v2/)

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

## Demo System for Integration Testing ✅

Create a simple demo system to test the OpenID Provider integration:

* ✅ Create a basic demo web application:
  * ✅ Simple HTML/CSS/JS frontend that requires authentication
  * ✅ Protected and public pages
  * ✅ Login/logout functionality
  * ✅ Display of user information from ID token
  * ✅ Error handling and display

* ✅ Demo System Features:
  * ✅ Public landing page with login button
  * ✅ Protected dashboard page showing:
    * ✅ User email
    * ✅ ID token claims
    * ✅ Logout button
  * ✅ Error page for failed authentication
  * ✅ Responsive design for testing on different devices

* ✅ Integration Testing Setup:
  * ✅ Configure demo app as a registered client in OpenID Provider
  * ✅ Set up test user accounts
  * ✅ Create test scenarios:
    * ✅ Successful login flow
    * ✅ Failed login attempts
    * ✅ Session expiration
    * ✅ Logout flow
    * ✅ Error handling

* ✅ Documentation:
  * ✅ Setup instructions for demo system
  * ✅ Test scenarios and expected behavior
  * ✅ Troubleshooting guide
  * ✅ Integration testing guide

* ✅ Development Requirements:
  * ✅ Use the same HTML and CSS approach as for the main opeidprovider implementation
  * ✅ Use modern web standards
  * ✅ Minimal dependencies
  * ✅ Easy to deploy and run locally
  * ✅ Clear separation from main OpenID Provider codebase


## Misc Improvements

  * Implement a `.well-known/change-password` endpoint as per <https://w3c.github.io/webappsec-change-password-url/> that can be used by password managers tot automatically redirect and trigger a password change flow.
