# TODO

## Self-Registration

### Allow **registration**
  * add register link to login page 
  * add a regsitration page
    * allow specifying email and password (2 times) on that page
    * registering triggers a queued verification email
      * send the mail using Sendgrid
  * when a valid verification code is provided the user is registered and redirected to the login page
  * a cleanup job must be run to remove unverified users after a certain amount of time

### Allow **forgot password**
  * add forgot password link to login page
  * allow specifying email
  * sending a forgot password email triggers a queued verification email
  * when a valid verification code is provided the user is redirected to the registration page to provide a new password
    * in this case we don't send the verification email since we already verified it

### Allow **delete account**
  * we need either a link to a delete account page or a general settings page
  * clicking on the delete button triggers a queued verification email
  * when a valid verification code is provided the user is deleted and redirected to the login page

## Scopes and Claims

* implement scopes and claims generically
  * the DB structure should be generic, but we can consider hardcoding some of the scopes and claims
  * what should we hardcode and what should we allow to be configured?
  * don't need the profile scope for now
  * we do need something like a "groups" scope that contains one claim called `groups` that contains a list of groups (do we store json strings or allow for actual lists?)

## Refresh Tokens

* implement refresh tokens so clients can invalidate sessions

