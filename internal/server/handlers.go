package server

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/logging"
	"aggregat4/openidprovider/internal/repository"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/aggregat4/go-baselib/crypto"
	gojose "github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type RegisterPage struct {
	Email           string
	Error           string
	Success         string
	AltchaChallenge string
}

type VerifyPage struct {
	Code    string
	Error   string
	Success string
}

type ForgotPasswordPage struct {
	Email   string
	Error   string
	Success string
}

type ResetPasswordPage struct {
	Token   string
	Error   string
	Success string
}

type DeleteAccountPage struct {
	Email   string
	Error   string
	Success string
}

type VerifyDeletePage struct {
	Code    string
	Error   string
	Success string
}

type LoginPage struct {
	ClientId    string
	RedirectUri string
	State       string
	Scope       string
}

var handlersLogger = logging.ForComponent("server.handlers")

// StatusHandler handles the status endpoint
func (controller *Controller) StatusHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Status endpoint")
	stringResponse(w, http.StatusOK, "OK")
}

// JwksHandler handles the JWKS endpoint
func (controller *Controller) JwksHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "JWKS endpoint")

	// Create JWKS document
	jwks := gojose.JSONWebKeySet{
		Keys: []gojose.JSONWebKey{
			{
				Key:       controller.Config.JwtConfig.PublicKey,
				KeyID:     "id-token-key",
				Use:       "sig",
				Algorithm: "RS256",
			},
		},
	}

	jwksBytes, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		logging.Error(handlersLogger, "Failed to marshal JWKS: %v", err)
		stringResponse(w, http.StatusInternalServerError, "Internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jwksBytes)
}

// OpenIdConfigurationHandler handles the OpenID configuration endpoint
func (controller *Controller) OpenIdConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "OpenID Configuration endpoint")

	// Get all scopes from the database
	scopes, err := controller.Store.ListScopes()
	if err != nil {
		stringResponse(w, http.StatusInternalServerError, "Internal error")
		return
	}

	// Get all claims from the database
	claimsMap := make(map[string]bool)
	for _, scope := range scopes {
		scopeClaims, err := controller.Store.ListScopeClaims(scope.Name)
		if err != nil {
			logging.Error(handlersLogger, "Failed to get scope claims: %v", err)
			stringResponse(w, http.StatusInternalServerError, "Internal error")
			return
		}
		for _, claim := range scopeClaims {
			claimsMap[claim.ClaimName] = true
		}
	}

	// Convert scopes to slice of names
	scopesSupported := make([]string, len(scopes))
	for i, scope := range scopes {
		scopesSupported[i] = scope.Name
	}

	// Convert claims map to slice of claim names
	claimsSupported := make([]string, 0, len(claimsMap))
	for claim := range claimsMap {
		claimsSupported = append(claimsSupported, claim)
	}

	config := domain.OpenIdConfiguration{
		Issuer:                           controller.Config.BaseUrl,
		AuthorizationEndpoint:            controller.Config.BaseUrl + "/authorize",
		TokenEndpoint:                    controller.Config.BaseUrl + "/token",
		JwksUri:                          controller.Config.BaseUrl + "/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  scopesSupported,
		ClaimsSupported:                  claimsSupported,
	}

	jsonResponse(w, http.StatusOK, config)
}

// TokenHandler handles OAuth token requests
// OIDC Token Endpoint is described in:
// https://openid.net/specs/openid-connect-basic-1_0.html#ObtainingTokens
// Reference to the OAuth 2 spec:
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
// Error handling as per https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
func (controller *Controller) TokenHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Token endpoint")

	// Get client_id from basic auth context (set by middleware)
	clientId := r.Context().Value(clientIDContextKey).(string)
	// Validate that the client exists
	client, clientExists := controller.Config.RegisteredClients[clientId]
	if !clientExists {
		sendOauthAccessTokenError(w, "invalid_client")
		return
	}
	// Validate that the redirect URI is registered for the client
	redirectUri := getFormValue(r, "redirect_uri")
	if !slices.Contains(client.RedirectUris, redirectUri) {
		sendOauthAccessTokenError(w, "invalid_client")
		return
	}
	// we assume that basic auth has happened and the secret matches, proceed to verify the grant type and code
	grantType := getFormValue(r, "grant_type")
	if grantType != "authorization_code" {
		sendOauthAccessTokenError(w, "unsupported_grant_type")
		return
	}
	code := getFormValue(r, "code")

	// validate that the code exists
	existingCode, err := controller.Store.FindCode(code)
	if err != nil {
		stringResponse(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if existingCode == nil {
		sendOauthAccessTokenError(w, "invalid_grant")
		return
	}

	// Code was used once, delete it
	err = controller.Store.DeleteCode(code)
	if err != nil {
		stringResponse(w, http.StatusInternalServerError, "Internal error")
		return
	}

	// Validate that the code is for the correct client and redirect URI
	if existingCode.ClientId != clientId || existingCode.RedirectUri != redirectUri {
		sendOauthAccessTokenError(w, "invalid_grant")
		return
	}

	// Get the user
	user, err := controller.Store.FindUser(existingCode.Email)
	if err != nil {
		stringResponse(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if user == nil {
		sendOauthAccessTokenError(w, "invalid_grant")
		return
	}

	// Parse requested scopes
	requestedScopes := strings.Split(existingCode.Scopes, " ")

	// Get claims for the requested scopes
	claims, err := controller.Store.GetUserClaimsForScopes(user.Id, requestedScopes)
	if err != nil {
		stringResponse(w, http.StatusInternalServerError, "Internal error")
		return
	}

	// Convert claims to map for ID token
	claimsMap := make(map[string]any)
	for _, claim := range claims {
		claimsMap[claim.ClaimName] = claim.Value
	}

	// Finally, generate the access token
	accessToken := uuid.New().String()

	// Generate ID token
	idToken, err := GenerateIdToken(controller.Config.JwtConfig, clientId, user.Email, claimsMap)
	if err != nil {
		stringResponse(w, http.StatusInternalServerError, "Internal error")
		return
	}

	// Respond with the access token
	w.Header().Set("Cache-Control", "no-store")
	response := map[string]string{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"id_token":     idToken,
	}
	jsonResponse(w, http.StatusOK, response)
}

// AuthorizeHandler handles OAuth authorization requests
// No support for "nonce", "display", "prompt", "max_age", "ui_locales", "id_token_hint", "login_hint", "acr_values" yet
func (controller *Controller) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Authorize endpoint")

	authReqScopes := strings.Split(getParam(r, "scope"), " ")
	authReqResponseType := getParam(r, "response_type")
	authReqClientId := getParam(r, "client_id")
	authReqRedirectUri := getParam(r, "redirect_uri")
	authReqState := getParam(r, "state")

	// First validate the client and redirect URI before using it for error responses
	client, clientExists := controller.Config.RegisteredClients[authReqClientId]
	if !clientExists {
		stringResponse(w, http.StatusBadRequest, "Invalid client")
		return
	}

	// Create redirect URL for error responses
	redirectUrl, err := url.Parse(authReqRedirectUri)
	if err != nil {
		stringResponse(w, http.StatusBadRequest, "Invalid redirect URI")
		return
	}

	// Validate that the redirect URI is registered for the client
	if !slices.Contains(client.RedirectUris, authReqRedirectUri) {
		stringResponse(w, http.StatusBadRequest, "Invalid redirect URI")
		return
	}

	// Now we can use the redirect URI for error responses
	// Do basic validation whether required parameters are present first
	if len(authReqScopes) == 0 || !slices.Contains(authReqScopes, "openid") {
		sendOauthError(w, r, redirectUrl, "invalid_scope", "Missing or invalid scope", authReqState)
		return
	}

	if authReqResponseType != "code" {
		sendOauthError(w, r, redirectUrl, "unsupported_response_type", "Only code response type is supported", authReqState)
		return
	}

	// Validate requested scopes against database
	for _, scope := range authReqScopes {
		scopeExists, err := controller.Store.ScopeExists(scope)
		if err != nil {
			sendInternalOAuthError(w, r, err, redirectUrl, authReqState)
			return
		}
		if !scopeExists {
			sendOauthError(w, r, redirectUrl, "invalid_scope", "Invalid scope requested: "+scope, authReqState)
			return
		}
	}

	// All is well, redirect to login page with parameters
	loginUrl := fmt.Sprintf("/login?client_id=%s&redirect_uri=%s&state=%s&scope=%s",
		url.QueryEscape(authReqClientId),
		url.QueryEscape(authReqRedirectUri),
		url.QueryEscape(authReqState),
		url.QueryEscape(strings.Join(authReqScopes, " ")))

	redirectResponse(w, r, http.StatusFound, loginUrl)
}

// LoginHandler handles login requests
// It will return normal BAD REQUEST HTTP status codes for all errors pertaining to client id and redirecturi
// validation.
// This is unclear in the spec as https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1 could be
// interpreted as returning a 302 redirect with an error code in the query string for all these errors
// But since this treats a potential malicious client as a real client, this seems unwise? Or is it better
// to return an OAuth error so the implementor of a buggy client can see what's wrong?
func (controller *Controller) LoginHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Login endpoint")

	clientId := getFormValue(r, "clientid")
	redirectUri := getFormValue(r, "redirecturi")
	// Check if this is an OAuth flow by checking if client_id and redirect_uri are present
	isOAuthFlow := clientId != "" && redirectUri != ""

	if isOAuthFlow {
		state := getFormValue(r, "state")
		scopes := getFormValue(r, "scope")
		username := getFormValue(r, "username")
		password := getFormValue(r, "password")
		controller.handleOAuthLogin(w, r, clientId, redirectUri, state, scopes, username, password)
		return
	}

	// if it is NOT an oauth flow, check the method: if it is GET, show the login page
	// if it is POST, handle the login
	method := r.Method
	if method == "GET" {
		controller.showLoginPage(w, r)
		return
	}
	username := getFormValue(r, "username")
	password := getFormValue(r, "password")
	controller.handleRegularLogin(w, r, username, password)
}

// handleRegularLogin handles regular web login
func (controller *Controller) handleRegularLogin(w http.ResponseWriter, r *http.Request, username, password string) {
	logging.Info(handlersLogger, "handleRegularLogin called username=%s", username)
	// Basic validation
	if username == "" || password == "" {
		stringResponse(w, http.StatusBadRequest, "Missing credentials")
		return
	}

	// Validate credentials
	valid, err := controller.validateCredentials(username, password)
	if err != nil {
		logging.Error(handlersLogger, "Error validating credentials: %v", err)
		stringResponse(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	if !valid {
		stringResponse(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// TODO: Set session cookie or handle direct web login success
	redirectResponse(w, r, http.StatusFound, "/")
}

// handleOAuthLogin handles OAuth login flow
func (controller *Controller) handleOAuthLogin(w http.ResponseWriter, r *http.Request, clientId, redirectUri, state, scopes, username, password string) {
	logging.Info(handlersLogger, "handleOAuthLogin called clientId=%s username=%s", clientId, username)
	// Create redirect URL for error responses
	redirectUrl, err := url.Parse(redirectUri)
	if err != nil {
		stringResponse(w, http.StatusBadRequest, "Invalid redirect URI")
		return
	}

	// Basic validation
	if username == "" || password == "" {
		sendOauthError(w, r, redirectUrl, "invalid_request", "Missing credentials", state)
		return
	}

	// Validate credentials
	valid, err := controller.validateCredentials(username, password)
	if err != nil {
		logging.Error(handlersLogger, "Error validating credentials: %v", err)
		sendInternalOAuthError(w, r, err, redirectUrl, state)
		return
	}
	if !valid {
		sendOauthError(w, r, redirectUrl, "access_denied", "Invalid credentials", state)
		return
	}

	// OAuth flow validation
	client, clientExists := controller.Config.RegisteredClients[clientId]
	if !clientExists {
		sendOauthError(w, r, redirectUrl, "invalid_client", "Client does not exist", state)
		return
	}

	if !slices.Contains(client.RedirectUris, redirectUri) {
		sendOauthError(w, r, redirectUrl, "invalid_client", "Invalid redirect URI", state)
		return
	}

	// Get user for OAuth flow
	user, err := controller.Store.FindUser(username)
	if err != nil {
		sendInternalOAuthError(w, r, err, redirectUrl, state)
		return
	}

	if user == nil {
		logging.Debug(handlersLogger, "User not found with username")
		// See https://openid.net/specs/openid-connect-core-1_0.html#AuthError
		sendOauthError(w, r, redirectUrl, "access_denied", "Invalid username or password", state)
		return
	}

	// Generate a code
	// See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2 for the oauth 2 spec on Authorization responses
	// See also https://www.oauth.com/oauth2-servers/authorization/the-authorization-response/ for implementation hints
	code := uuid.New().String()
	err = controller.Store.SaveCode(repository.Code{
		Code:        code,
		Email:       user.Email,
		ClientId:    clientId,
		RedirectUri: redirectUri,
		Created:     time.Now().Unix(),
		Scopes:      scopes,
	})
	if err != nil {
		sendInternalOAuthError(w, r, err, redirectUrl, state)
		return
	}

	query := redirectUrl.Query()
	query.Add("code", code)
	query.Add("state", state)
	redirectUrl.RawQuery = query.Encode()
	logging.Info(handlersLogger, "login request password ok. redirecting")
	redirectResponse(w, r, http.StatusFound, redirectUrl.String())
}

// showLoginPage shows the login page
func (controller *Controller) showLoginPage(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Show login page")

	clientId := getParam(r, "client_id")
	redirectUri := getParam(r, "redirect_uri")
	state := getParam(r, "state")
	scope := getParam(r, "scope")

	page := LoginPage{
		ClientId:    clientId,
		RedirectUri: redirectUri,
		State:       state,
		Scope:       scope,
	}

	controller.renderTemplate(w, "login.html", page, http.StatusOK)
}

// ShowRegisterPageHandler handles the register page display
func (controller *Controller) ShowRegisterPageHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Show register page")

	altchaChallenge, err := controller.CaptchaVerifier.CreateChallenge()
	if err != nil {
		logging.Error(handlersLogger, "Failed to create ALTCHA challenge: %v", err)
		altchaChallenge = ""
	}

	page := RegisterPage{
		Email:           getParam(r, "email"),
		Error:           "",
		Success:         "",
		AltchaChallenge: altchaChallenge,
	}

	controller.renderTemplate(w, "register.html", page, http.StatusOK)
}

// RegisterHandler handles user registration
func (controller *Controller) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Register endpoint")

	email := getFormValue(r, "email")
	password := getFormValue(r, "password")
	confirmPassword := getFormValue(r, "confirmPassword")
	altchaSolution := getFormValue(r, "altcha")

	logging.Info(handlersLogger,
		"register handler form values email=%s password_length=%d confirmPassword_length=%d altcha_solution=%s",
		email,
		len(password),
		len(confirmPassword),
		altchaSolution,
	)

	// Generate ALTCHA challenge for all responses
	altchaChallenge, err := controller.CaptchaVerifier.CreateChallenge()
	if err != nil {
		logging.Error(handlersLogger, "Failed to create ALTCHA challenge: %v", err)
		controller.renderRegisterError(w, email, "Internal error", "", http.StatusInternalServerError)
		return
	}
	logging.Info(handlersLogger, "register handler generated ALTCHA challenge challenge=%s", altchaChallenge)

	// Basic validation
	if email == "" || password == "" || confirmPassword == "" {
		logging.Info(handlersLogger, "register handler validation failed - empty fields")
		controller.renderRegisterError(w, email, "All fields are required", altchaChallenge, http.StatusBadRequest)
		return
	}

	if password != confirmPassword {
		logging.Info(handlersLogger, "register handler validation failed - passwords don't match")
		controller.renderRegisterError(w, email, "Passwords do not match", altchaChallenge, http.StatusBadRequest)
		return
	}

	// verify that the password is at least 8 characters long
	if len(password) < 8 {
		logging.Info(handlersLogger, "register handler validation failed - password too short")
		controller.renderRegisterError(w, email, "Password must be at least 8 characters long", altchaChallenge, http.StatusBadRequest)
		return
	}

	if altchaSolution == "" {
		logging.Info(handlersLogger, "register handler ALTCHA solution missing")
		controller.renderRegisterError(w, email, "Please complete the captcha", altchaChallenge, http.StatusBadRequest)
		return
	}

	// Verify the ALTCHA solution
	ok, err := controller.CaptchaVerifier.VerifySolution(altchaSolution)
	if err != nil {
		logging.Error(handlersLogger, "register handler ALTCHA verification error: %v", err)
		controller.renderRegisterError(w, email, "Captcha verification failed", altchaChallenge, http.StatusBadRequest)
		return
	}
	if !ok {
		logging.Info(handlersLogger, "register handler ALTCHA verification failed")
		controller.renderRegisterError(w, email, "Captcha verification failed", altchaChallenge, http.StatusBadRequest)
		return
	}
	logging.Info(handlersLogger, "register handler ALTCHA verification successful")

	// Check if user already exists
	logging.Info(handlersLogger, "register handler checking if user exists email=%s", email)
	existingUser, err := controller.Store.FindUser(email)
	if err != nil {
		logging.Error(handlersLogger, "register handler error finding user: %v", err)
		controller.renderRegisterError(w, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
		return
	}

	if existingUser != nil {
		logging.Info(handlersLogger, "register handler user exists email=%s verified=%t", email, existingUser.Verified)

		// If user is already verified, redirect to login
		if existingUser.Verified {
			logging.Info(handlersLogger, "register handler redirecting verified user to login")
			redirectResponse(w, r, http.StatusFound, "/login")
			return
		}

		// If user exists but is not verified, check if we should resend verification email
		logging.Info(handlersLogger, "register handler checking if should resend verification for unverified user")
		lastAttempt, err := controller.Store.GetLastRegistrationAttempt(email)
		if err != nil {
			logging.Error(handlersLogger, "register handler error getting last registration attempt: %v", err)
			controller.renderRegisterError(w, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
			return
		}

		// If last attempt was less than 5 minutes ago, show debounce message
		if time.Now().Unix()-lastAttempt < 300 {
			logging.Info(handlersLogger, "register handler email debouncing last_attempt=%d time_since=%d", lastAttempt, time.Now().Unix()-lastAttempt)
			controller.renderRegisterError(w, email, "Please wait a few minutes before trying again", altchaChallenge, http.StatusTooManyRequests)
			return
		}

		// Check for too many failed verification attempts
		failedAttempts, err := controller.Store.GetFailedVerificationAttempts(email)
		if err != nil {
			logging.Error(handlersLogger, "register handler error getting failed verification attempts: %v", err)
			controller.renderRegisterError(w, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
			return
		}

		// Block after 5 failed attempts
		if failedAttempts >= 5 {
			logging.Info(handlersLogger, "register handler too many failed verification attempts failed_attempts=%d", failedAttempts)
			controller.renderRegisterError(w, email, "Too many failed verification attempts. Please try again later.", altchaChallenge, http.StatusTooManyRequests)
			return
		}

		// Check for too many active tokens
		activeTokens, err := controller.Store.GetActiveVerificationTokensCount(email)
		if err != nil {
			logging.Error(handlersLogger, "register handler error getting active tokens count: %v", err)
			controller.renderRegisterError(w, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
			return
		}

		// Maximum 3 active tokens per email
		if activeTokens >= 3 {
			logging.Info(handlersLogger, "register handler too many active tokens active_tokens=%d", activeTokens)
			controller.renderRegisterError(w, email, "Too many active verification links. Please check your email or try again later.", altchaChallenge, http.StatusTooManyRequests)
			return
		}

		// OK, we don't need to debounce the user, we can resend the verification email
		logging.Info(handlersLogger, "register handler resending verification email for unverified user")
		err = controller.sendVerificationEmail(email)
		if err != nil {
			logging.Error(handlersLogger, "register handler error sending verification email: %v", err)
			controller.renderRegisterError(w, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
			return
		}

		logging.Info(handlersLogger, "register handler verification email resent successfully")
		controller.renderRegisterSuccess(w, email, "Verification email sent. Please check your email to verify your account.", altchaChallenge)
		return
	}

	// Create new user
	logging.Info(handlersLogger, "register handler creating new user email=%s", email)
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		logging.Error(handlersLogger, "register handler error hashing password: %v", err)
		controller.renderRegisterError(w, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
		return
	}

	err = controller.Store.CreateUser(email, hashedPassword)
	if err != nil {
		logging.Error(handlersLogger, "register handler error creating user: %v", err)
		controller.renderRegisterError(w, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
		return
	}

	// Send verification email
	logging.Info(handlersLogger, "register handler sending verification email for new user")
	err = controller.sendVerificationEmail(email)
	if err != nil {
		logging.Error(handlersLogger, "register handler error sending verification email: %v", err)
		controller.renderRegisterError(w, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
		return
	}

	logging.Info(handlersLogger, "register handler registration successful")
	controller.renderRegisterSuccess(w, email, "Registration successful! Please check your email to verify your account.", altchaChallenge)
}

// ShowVerificationPageHandler handles the verification page display
func (controller *Controller) ShowVerificationPageHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Show verification page")

	code := getParam(r, "code")
	if code == "" {
		page := VerifyPage{
			Code:  code,
			Error: "Invalid or missing verification code",
		}
		controller.renderTemplate(w, "verify.html", page, http.StatusBadRequest)
		return
	}

	controller.verifyWithCode(w, r, code)
}

// VerifyHandler handles email verification
func (controller *Controller) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Verify endpoint")

	code := getFormValue(r, "code")
	// basic validation
	if code == "" {
		logging.Info(handlersLogger, "verify handler validation failed - code is empty")
		page := VerifyPage{
			Error: "Verification code is required",
		}
		controller.renderTemplate(w, "verify.html", page, http.StatusBadRequest)
		return
	}
	logging.Info(handlersLogger, "verify handler received code=%s", code)

	controller.verifyWithCode(w, r, code)
}

// verifyWithCode handles verification with a specific code
func (controller *Controller) verifyWithCode(w http.ResponseWriter, r *http.Request, code string) {
	logging.Info(handlersLogger, "verifyWithCode handler called code=%s", code)

	// Find and validate token
	verificationToken, err := controller.Store.FindVerificationToken(code)
	if err != nil {
		logging.Error(handlersLogger, "verify handler error finding token: %v", err)
		page := VerifyPage{
			Error: "Internal error",
		}
		controller.renderTemplate(w, "verify.html", page, http.StatusInternalServerError)
		return
	}

	if verificationToken == nil {
		logging.Info(handlersLogger, "verify handler token not found code=%s", code)
		page := VerifyPage{
			Error: "Invalid or expired verification code",
		}
		controller.renderTemplate(w, "verify.html", page, http.StatusBadRequest)
		return
	}

	// Check if token is expired
	if time.Now().Unix() > verificationToken.Expires {
		logging.Info(handlersLogger, "verify handler token expired code=%s expires_at=%d", code, verificationToken.Expires)
		err := controller.Store.DeleteVerificationToken(code)
		if err != nil {
			sendInternalOAuthError(w, r, err, nil, "Internal error")
			return
		}
		page := VerifyPage{
			Error: "Verification link has expired",
		}
		controller.renderTemplate(w, "verify.html", page, http.StatusBadRequest)
		return
	}

	// Mark user as verified
	err = controller.Store.VerifyUser(verificationToken.Email)
	if err != nil {
		logging.Error(handlersLogger, "verify handler error verifying user: %v", err)
		page := VerifyPage{
			Error: "Internal error",
		}
		controller.renderTemplate(w, "verify.html", page, http.StatusInternalServerError)
		return
	}

	// Delete the verification token
	err = controller.Store.DeleteVerificationToken(code)
	if err != nil {
		logging.Error(handlersLogger, "verify handler error deleting token: %v", err)
		sendInternalOAuthError(w, r, err, nil, "Internal error")
		return
	}

	logging.Info(handlersLogger, "verify handler verification successful email=%s", verificationToken.Email)
	page := VerifyPage{
		Success: "Verification successful",
	}
	controller.renderTemplate(w, "verify.html", page, http.StatusOK)
}

// ShowForgotPasswordPageHandler handles the forgot password page display
func (controller *Controller) ShowForgotPasswordPageHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Show forgot password page")

	page := ForgotPasswordPage{
		Email:   getParam(r, "email"),
		Error:   "",
		Success: "",
	}

	controller.renderTemplate(w, "forgot-password.html", page, http.StatusOK)
}

// ForgotPasswordHandler handles forgot password requests
func (controller *Controller) ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Forgot password endpoint")

	email := getFormValue(r, "email")

	// Basic validation
	if email == "" {
		page := ForgotPasswordPage{
			Email: email,
			Error: "Email is required",
		}
		controller.renderTemplate(w, "forgot-password.html", page, http.StatusBadRequest)
		return
	}

	// Check if user exists and is verified
	user, err := controller.Store.FindUser(email)
	if err != nil {
		stringResponse(w, http.StatusInternalServerError, "Internal error")
		return
	}

	if user == nil || !user.Verified {
		// Don't reveal if the email exists or not for security
		page := ForgotPasswordPage{
			Email:   email,
			Success: "If an account exists with this email, you will receive a password reset link.",
		}
		controller.renderTemplate(w, "forgot-password.html", page, http.StatusOK)
		return
	}

	// Generate reset token
	token := uuid.New().String()
	verificationToken := repository.VerificationToken{
		Token:   token,
		Email:   email,
		Type:    "password_reset",
		Created: time.Now().Unix(),
		Expires: time.Now().Add(24 * time.Hour).Unix(),
	}

	err = controller.Store.CreateVerificationToken(verificationToken)
	if err != nil {
		stringResponse(w, http.StatusInternalServerError, "Internal error")
		return
	}

	// Send reset email
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", controller.Config.BaseUrl, token)
	err = controller.EmailService.SendPasswordResetEmail(email, resetLink)
	if err != nil {
		logging.Error(handlersLogger, "Failed to send password reset email: %v", err)
		// Continue with the flow even if email sending fails
	}

	page := ForgotPasswordPage{
		Email:   email,
		Success: "If an account exists with this email, you will receive a password reset link.",
	}
	controller.renderTemplate(w, "forgot-password.html", page, http.StatusOK)
}

// ShowResetPasswordPageHandler handles the reset password page display
func (controller *Controller) ShowResetPasswordPageHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Show reset password page")

	token := getParam(r, "token")

	page := ResetPasswordPage{
		Token:   token,
		Error:   "",
		Success: "",
	}

	controller.renderTemplate(w, "reset-password.html", page, http.StatusOK)
}

// ResetPasswordHandler handles password reset
func (controller *Controller) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Reset password endpoint")

	token := getFormValue(r, "token")
	password := getFormValue(r, "password")
	confirmPassword := getFormValue(r, "confirmPassword")

	// Basic validation
	if token == "" || password == "" || confirmPassword == "" {
		page := ResetPasswordPage{
			Token: token,
			Error: "All fields are required",
		}
		controller.renderTemplate(w, "reset-password.html", page, http.StatusBadRequest)
		return
	}

	if password != confirmPassword {
		page := ResetPasswordPage{
			Token: token,
			Error: "Passwords do not match",
		}
		controller.renderTemplate(w, "reset-password.html", page, http.StatusBadRequest)
		return
	}

	// Find and validate token
	verificationToken, err := controller.Store.FindVerificationToken(token)
	if err != nil {
		page := ResetPasswordPage{
			Error: "Internal error",
		}
		controller.renderTemplate(w, "reset-password.html", page, http.StatusInternalServerError)
		return
	}

	if verificationToken == nil || verificationToken.Type != "password_reset" {
		page := ResetPasswordPage{
			Error: "Invalid or expired reset link",
		}
		controller.renderTemplate(w, "reset-password.html", page, http.StatusBadRequest)
		return
	}

	if verificationToken.Expires < time.Now().Unix() {
		err := controller.Store.DeleteVerificationToken(token)
		if err != nil {
			page := ResetPasswordPage{
				Error: "Internal error",
			}
			controller.renderTemplate(w, "reset-password.html", page, http.StatusInternalServerError)
			return
		}
		page := ResetPasswordPage{
			Error: "Reset link has expired",
		}
		controller.renderTemplate(w, "reset-password.html", page, http.StatusBadRequest)
		return
	}

	// Hash new password
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		page := ResetPasswordPage{
			Error: "Internal error",
		}
		controller.renderTemplate(w, "reset-password.html", page, http.StatusInternalServerError)
		return
	}

	// Update password
	err = controller.Store.UpdateUserPassword(verificationToken.Email, hashedPassword)
	if err != nil {
		page := ResetPasswordPage{
			Error: "Internal error",
		}
		controller.renderTemplate(w, "reset-password.html", page, http.StatusInternalServerError)
		return
	}

	// Delete used token
	err = controller.Store.DeleteVerificationToken(token)
	if err != nil {
		page := ResetPasswordPage{
			Error: "Internal error",
		}
		controller.renderTemplate(w, "reset-password.html", page, http.StatusInternalServerError)
		return
	}

	page := ResetPasswordPage{
		Success: "Password has been reset successfully. You can now log in with your new password.",
	}
	controller.renderTemplate(w, "reset-password.html", page, http.StatusOK)
}

// ShowDeleteAccountPageHandler handles the delete account page display
func (controller *Controller) ShowDeleteAccountPageHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Show delete account page")
	controller.renderTemplate(w, "delete-account.html", DeleteAccountPage{}, http.StatusOK)
}

// DeleteAccountHandler handles account deletion requests
func (controller *Controller) DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Delete account endpoint")

	email := getFormValue(r, "email")
	if email == "" {
		page := DeleteAccountPage{
			Error: "Email is required",
		}
		controller.renderTemplate(w, "delete-account.html", page, http.StatusBadRequest)
		return
	}

	// Check if user exists and is verified
	user, err := controller.Store.FindUser(email)
	if err != nil {
		page := DeleteAccountPage{
			Error: "Internal error",
		}
		controller.renderTemplate(w, "delete-account.html", page, http.StatusInternalServerError)
		return
	}

	if user == nil || !user.Verified {
		// Don't reveal if the email exists or not for security
		page := DeleteAccountPage{
			Success: "If your account exists and is verified, you will receive an email with instructions to delete it.",
		}
		controller.renderTemplate(w, "delete-account.html", page, http.StatusOK)
		return
	}

	// Generate delete token
	token := uuid.New().String()
	verificationToken := repository.VerificationToken{
		Token:   token,
		Email:   email,
		Type:    "delete_account",
		Created: time.Now().Unix(),
		Expires: time.Now().Add(24 * time.Hour).Unix(),
	}

	err = controller.Store.CreateVerificationToken(verificationToken)
	if err != nil {
		page := DeleteAccountPage{
			Error: "Internal error",
		}
		controller.renderTemplate(w, "delete-account.html", page, http.StatusInternalServerError)
		return
	}

	// Send delete verification email
	deleteLink := fmt.Sprintf("%s/verify-delete?token=%s", controller.Config.BaseUrl, token)
	err = controller.EmailService.SendDeleteAccountEmail(email, deleteLink)
	if err != nil {
		logging.Error(handlersLogger, "Failed to send delete account email: %v", err)
	}

	page := DeleteAccountPage{
		Success: "If your account exists and is verified, you will receive an email with instructions to delete it.",
	}
	controller.renderTemplate(w, "delete-account.html", page, http.StatusOK)
}

// TODO: this implementation does not seem right, we just always show the page with an error??
// ShowVerifyDeletePageHandler handles the verify delete page display
func (controller *Controller) ShowVerifyDeletePageHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Show verify delete page")

	token := getParam(r, "token")

	page := VerifyDeletePage{
		Code:    token,
		Error:   "",
		Success: "",
	}

	controller.renderTemplate(w, "verify-delete.html", page, http.StatusOK)
}

// VerifyDeleteHandler handles delete verification
func (controller *Controller) VerifyDeleteHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Verify delete endpoint")

	token := getFormValue(r, "code")
	if token == "" {
		page := VerifyDeletePage{
			Error: "Verification code is required",
		}
		controller.renderTemplate(w, "verify-delete.html", page, http.StatusBadRequest)
		return
	}

	// Find and validate token
	verificationToken, err := controller.Store.FindVerificationToken(token)
	if err != nil {
		page := VerifyDeletePage{
			Error: "Internal error",
		}
		controller.renderTemplate(w, "verify-delete.html", page, http.StatusInternalServerError)
		return
	}

	if verificationToken == nil || verificationToken.Type != "delete_account" {
		page := VerifyDeletePage{
			Error: "Invalid or expired verification code",
		}
		controller.renderTemplate(w, "verify-delete.html", page, http.StatusBadRequest)
		return
	}

	// Check if token is expired
	if time.Now().Unix() > verificationToken.Expires {
		logging.Info(handlersLogger, "verify delete handler token expired token=%s expires_at=%d", token, verificationToken.Expires)
		page := VerifyDeletePage{
			Error: "Verification code has expired",
		}
		controller.renderTemplate(w, "verify-delete.html", page, http.StatusBadRequest)
		return
	}

	// Delete the user
	err = controller.Store.DeleteUser(verificationToken.Email)
	if err != nil {
		page := VerifyDeletePage{
			Error: "Internal error",
		}
		controller.renderTemplate(w, "verify-delete.html", page, http.StatusInternalServerError)
		return
	}

	// Delete the verification token
	err = controller.Store.DeleteVerificationToken(token)
	if err != nil {
		logging.Error(handlersLogger, "verify delete handler error deleting token: %v", err)
		// Don't fail the deletion if we can't delete the token
	}

	logging.Info(handlersLogger, "verify delete handler account deletion successful email=%s", verificationToken.Email)
	page := VerifyDeletePage{
		Success: "Your account has been deleted successfully.",
	}
	controller.renderTemplate(w, "verify-delete.html", page, http.StatusOK)
}

// ResendDeleteVerificationHandler handles resending delete verification
func (controller *Controller) ResendDeleteVerificationHandler(w http.ResponseWriter, r *http.Request) {
	logging.Info(handlersLogger, "Resend delete verification endpoint")

	email := getParam(r, "email")
	if email == "" {
		redirectResponse(w, r, http.StatusFound, "/delete-account")
		return
	}

	// Check if user exists and is verified
	user, err := controller.Store.FindUser(email)
	if err != nil {
		stringResponse(w, http.StatusInternalServerError, "Internal error")
		return
	}

	if user == nil || !user.Verified {
		redirectResponse(w, r, http.StatusFound, "/delete-account")
		return
	}

	// Generate new delete token
	token := uuid.New().String()
	verificationToken := repository.VerificationToken{
		Token:   token,
		Email:   email,
		Type:    "delete_account",
		Created: time.Now().Unix(),
		Expires: time.Now().Add(24 * time.Hour).Unix(),
	}

	err = controller.Store.CreateVerificationToken(verificationToken)
	if err != nil {
		stringResponse(w, http.StatusInternalServerError, "Internal error")
		return
	}

	// Send delete verification email
	deleteLink := fmt.Sprintf("%s/verify-delete?token=%s", controller.Config.BaseUrl, token)
	err = controller.EmailService.SendDeleteAccountEmail(email, deleteLink)
	if err != nil {
		logging.Error(handlersLogger, "Failed to send delete account email: %v", err)
	}

	redirectResponse(w, r, http.StatusFound, "/delete-account")
}

// LandingPageHandler serves the landing page at root
func (controller *Controller) LandingPageHandler(w http.ResponseWriter, r *http.Request) {
	controller.renderTemplate(w, "landing.html", nil, http.StatusOK)
}

// Helper methods

func (controller *Controller) validateCredentials(username, password string) (bool, error) {
	user, err := controller.Store.FindUser(username)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, nil
	}
	return crypto.CheckPasswordHash(password, user.Password), nil
}

func (controller *Controller) sendVerificationEmail(email string) error {
	// Generate verification token
	token := uuid.New().String()
	verificationToken := repository.VerificationToken{
		Token:   token,
		Email:   email,
		Type:    "registration",
		Created: time.Now().Unix(),
		Expires: time.Now().Add(24 * time.Hour).Unix(),
	}

	err := controller.Store.CreateVerificationToken(verificationToken)
	if err != nil {
		return err
	}

	// Send verification email
	verificationLink := fmt.Sprintf("%s/verify?code=%s", controller.Config.BaseUrl, token)
	return controller.EmailService.SendVerificationEmail(email, verificationLink)
}

func (controller *Controller) renderRegisterError(w http.ResponseWriter, email, errorMsg, altchaChallenge string, statusCode int) {
	page := RegisterPage{
		Email:           email,
		Error:           errorMsg,
		AltchaChallenge: altchaChallenge,
	}
	controller.renderTemplate(w, "register.html", page, statusCode)
}

func (controller *Controller) renderRegisterSuccess(w http.ResponseWriter, email, successMsg, altchaChallenge string) {
	page := RegisterPage{
		Email:           email,
		Success:         successMsg,
		AltchaChallenge: altchaChallenge,
	}
	controller.renderTemplate(w, "register.html", page, http.StatusOK)
}

// GenerateIdToken See https://openid.net/specs/openid-connect-basic-1_0.html#IDToken
func GenerateIdToken(jwtConfig domain.JwtConfiguration, clientId string, userName string, claims map[string]any) (string, error) {
	// Start with standard claims
	tokenClaims := jwt.MapClaims{
		"iss": jwtConfig.Issuer,
		"sub": userName,
		"aud": clientId,
		"exp": time.Now().Add(time.Minute * time.Duration(jwtConfig.IdTokenValidityMinutes)).Unix(),
		"iat": time.Now().Unix(),
	}

	maps.Copy(tokenClaims, claims)

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	return t.SignedString(jwtConfig.PrivateKey)
}
