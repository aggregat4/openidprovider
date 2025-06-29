package server

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/repository"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aggregat4/go-baselib/crypto"
	gojose "github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func contains(list []string, item string) bool {
	for _, i := range list {
		if i == item {
			return true
		}
	}
	return false
}

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

// StatusHandler handles the status endpoint
func (controller *ChiController) StatusHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Status endpoint")
	stringResponse(w, http.StatusOK, "OK")
}

// JwksHandler handles the JWKS endpoint
func (controller *ChiController) JwksHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("JWKS endpoint")

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
		logger.Error("Failed to marshal JWKS", "error", err)
		stringResponse(w, http.StatusInternalServerError, "Internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jwksBytes)
}

// OpenIdConfigurationHandler handles the OpenID configuration endpoint
func (controller *ChiController) OpenIdConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("OpenID Configuration endpoint")

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
			logger.Error("Failed to get scope claims", "error", err)
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
func (controller *ChiController) TokenHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Token endpoint")

	// Get client_id from basic auth context (set by middleware)
	clientId := r.Context().Value(clientIDContextKey).(string)
	// Validate that the client exists
	client, clientExists := controller.Config.RegisteredClients[clientId]
	if !clientExists {
		sendOauthAccessTokenErrorChi(w, "invalid_client")
		return
	}
	// Validate that the redirect URI is registered for the client
	redirectUri := getFormValueChi(r, "redirect_uri")
	if !contains(client.RedirectUris, redirectUri) {
		sendOauthAccessTokenErrorChi(w, "invalid_client")
		return
	}
	// we assume that basic auth has happened and the secret matches, proceed to verify the grant type and code
	grantType := getFormValueChi(r, "grant_type")
	if grantType != "authorization_code" {
		sendOauthAccessTokenErrorChi(w, "unsupported_grant_type")
		return
	}
	code := getFormValueChi(r, "code")

	// validate that the code exists
	existingCode, err := controller.Store.FindCode(code)
	if err != nil {
		stringResponse(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if existingCode == nil {
		sendOauthAccessTokenErrorChi(w, "invalid_grant")
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
		sendOauthAccessTokenErrorChi(w, "invalid_grant")
		return
	}

	// Get the user
	user, err := controller.Store.FindUser(existingCode.Email)
	if err != nil {
		stringResponse(w, http.StatusInternalServerError, "Internal error")
		return
	}
	if user == nil {
		sendOauthAccessTokenErrorChi(w, "invalid_grant")
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
	claimsMap := make(map[string]interface{})
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
func (controller *ChiController) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Authorize endpoint")

	authReqScopes := strings.Split(getParamChi(r, "scope"), " ")
	authReqResponseType := getParamChi(r, "response_type")
	authReqClientId := getParamChi(r, "client_id")
	authReqRedirectUri := getParamChi(r, "redirect_uri")
	authReqState := getParamChi(r, "state")

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
	if !contains(client.RedirectUris, authReqRedirectUri) {
		stringResponse(w, http.StatusBadRequest, "Invalid redirect URI")
		return
	}

	// Now we can use the redirect URI for error responses
	// Do basic validation whether required parameters are present first
	if len(authReqScopes) == 0 || !contains(authReqScopes, "openid") {
		sendOauthErrorChi(w, r, redirectUrl, "invalid_scope", "Missing or invalid scope", authReqState)
		return
	}

	if authReqResponseType != "code" {
		sendOauthErrorChi(w, r, redirectUrl, "unsupported_response_type", "Only code response type is supported", authReqState)
		return
	}

	// Validate requested scopes against database
	for _, scope := range authReqScopes {
		scopeExists, err := controller.Store.ScopeExists(scope)
		if err != nil {
			sendInternalErrorChi(w, r, err, redirectUrl, authReqState)
			return
		}
		if !scopeExists {
			sendOauthErrorChi(w, r, redirectUrl, "invalid_scope", "Invalid scope requested: "+scope, authReqState)
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
func (controller *ChiController) LoginHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Login endpoint")

	clientId := getFormValueChi(r, "clientid")
	redirectUri := getFormValueChi(r, "redirecturi")
	// Check if this is an OAuth flow by checking if client_id and redirect_uri are present
	isOAuthFlow := clientId != "" && redirectUri != ""

	if isOAuthFlow {
		state := getFormValueChi(r, "state")
		scopes := getFormValueChi(r, "scope")
		username := getFormValueChi(r, "username")
		password := getFormValueChi(r, "password")
		controller.handleOAuthLoginChi(w, r, clientId, redirectUri, state, scopes, username, password)
		return
	}

	// if it is NOT an oauth flow, check the method: if it is GET, show the login page
	// if it is POST, handle the login
	method := r.Method
	if method == "GET" {
		controller.showLoginPageChi(w, r)
		return
	}
	username := getFormValueChi(r, "username")
	password := getFormValueChi(r, "password")
	controller.handleRegularLoginChi(w, r, username, password)
}

// handleRegularLoginChi handles regular web login
func (controller *ChiController) handleRegularLoginChi(w http.ResponseWriter, r *http.Request, username, password string) {
	logger.Info("handleRegularLogin called", "username", username)
	// Basic validation
	if username == "" || password == "" {
		stringResponse(w, http.StatusBadRequest, "Missing credentials")
		return
	}

	// Validate credentials
	valid, err := controller.validateCredentials(username, password)
	if err != nil {
		logger.Error("Error validating credentials", "error", err)
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

// handleOAuthLoginChi handles OAuth login flow
func (controller *ChiController) handleOAuthLoginChi(w http.ResponseWriter, r *http.Request, clientId, redirectUri, state, scopes, username, password string) {
	logger.Info("handleOAuthLogin called", "clientId", clientId, "username", username)
	// Create redirect URL for error responses
	redirectUrl, err := url.Parse(redirectUri)
	if err != nil {
		stringResponse(w, http.StatusBadRequest, "Invalid redirect URI")
		return
	}

	// Basic validation
	if username == "" || password == "" {
		sendOauthErrorChi(w, r, redirectUrl, "invalid_request", "Missing credentials", state)
		return
	}

	// Validate credentials
	valid, err := controller.validateCredentials(username, password)
	if err != nil {
		logger.Error("Error validating credentials", "error", err)
		sendInternalErrorChi(w, r, err, redirectUrl, state)
		return
	}
	if !valid {
		sendOauthErrorChi(w, r, redirectUrl, "access_denied", "Invalid credentials", state)
		return
	}

	// OAuth flow validation
	client, clientExists := controller.Config.RegisteredClients[clientId]
	if !clientExists {
		sendOauthErrorChi(w, r, redirectUrl, "invalid_client", "Client does not exist", state)
		return
	}

	if !contains(client.RedirectUris, redirectUri) {
		sendOauthErrorChi(w, r, redirectUrl, "invalid_client", "Invalid redirect URI", state)
		return
	}

	// Get user for OAuth flow
	user, err := controller.Store.FindUser(username)
	if err != nil {
		sendInternalErrorChi(w, r, err, redirectUrl, state)
		return
	}

	if user == nil {
		logger.Debug("User not found with username")
		// See https://openid.net/specs/openid-connect-core-1_0.html#AuthError
		sendOauthErrorChi(w, r, redirectUrl, "access_denied", "Invalid username or password", state)
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
		sendInternalErrorChi(w, r, err, redirectUrl, state)
		return
	}

	query := redirectUrl.Query()
	query.Add("code", code)
	query.Add("state", state)
	redirectUrl.RawQuery = query.Encode()
	logger.Info("login request password ok. redirecting")
	redirectResponse(w, r, http.StatusFound, redirectUrl.String())
}

// showLoginPageChi shows the login page
func (controller *ChiController) showLoginPageChi(w http.ResponseWriter, r *http.Request) {
	logger.Info("Show login page")

	clientId := getParamChi(r, "client_id")
	redirectUri := getParamChi(r, "redirect_uri")
	state := getParamChi(r, "state")
	scope := getParamChi(r, "scope")

	page := LoginPage{
		ClientId:    clientId,
		RedirectUri: redirectUri,
		State:       state,
		Scope:       scope,
	}

	controller.renderTemplate(w, "login.html", page)
}

// ShowRegisterPageHandler handles the register page display
func (controller *ChiController) ShowRegisterPageHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Show register page")

	altchaChallenge, err := controller.CaptchaVerifier.CreateChallenge()
	if err != nil {
		logger.Error("Failed to create ALTCHA challenge", "error", err)
		altchaChallenge = ""
	}

	page := RegisterPage{
		Email:           getParamChi(r, "email"),
		Error:           "",
		Success:         "",
		AltchaChallenge: altchaChallenge,
	}

	controller.renderTemplate(w, "register.html", page)
}

// RegisterHandler handles user registration
func (controller *ChiController) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Register endpoint")

	email := getFormValueChi(r, "email")
	password := getFormValueChi(r, "password")
	confirmPassword := getFormValueChi(r, "confirmPassword")
	altchaSolution := getFormValueChi(r, "altcha")

	logger.Info("register handler form values", "email", email, "password_length", len(password), "confirmPassword_length", len(confirmPassword), "altcha_solution", string(altchaSolution))

	// Generate ALTCHA challenge for all responses
	altchaChallenge, err := controller.CaptchaVerifier.CreateChallenge()
	if err != nil {
		logger.Error("Failed to create ALTCHA challenge", "error", err)
		controller.renderRegisterErrorChi(w, r, email, "Internal error", "", http.StatusInternalServerError)
		return
	}
	logger.Info("register handler generated ALTCHA challenge", "challenge", altchaChallenge)

	// Basic validation
	if email == "" || password == "" || confirmPassword == "" {
		logger.Info("register handler validation failed - empty fields")
		controller.renderRegisterErrorChi(w, r, email, "All fields are required", altchaChallenge, http.StatusBadRequest)
		return
	}

	if password != confirmPassword {
		logger.Info("register handler validation failed - passwords don't match")
		controller.renderRegisterErrorChi(w, r, email, "Passwords do not match", altchaChallenge, http.StatusBadRequest)
		return
	}

	// verify that the password is at least 8 characters long
	if len(password) < 8 {
		logger.Info("register handler validation failed - password too short")
		controller.renderRegisterErrorChi(w, r, email, "Password must be at least 8 characters long", altchaChallenge, http.StatusBadRequest)
		return
	}

	if altchaSolution == "" {
		logger.Info("register handler ALTCHA solution missing")
		controller.renderRegisterErrorChi(w, r, email, "Please complete the captcha", altchaChallenge, http.StatusBadRequest)
		return
	}

	// Verify the ALTCHA solution
	ok, err := controller.CaptchaVerifier.VerifySolution(altchaSolution)
	if err != nil {
		logger.Error("register handler ALTCHA verification error", "error", err)
		controller.renderRegisterErrorChi(w, r, email, "Captcha verification failed", altchaChallenge, http.StatusBadRequest)
		return
	}
	if !ok {
		logger.Info("register handler ALTCHA verification failed")
		controller.renderRegisterErrorChi(w, r, email, "Captcha verification failed", altchaChallenge, http.StatusBadRequest)
		return
	}
	logger.Info("register handler ALTCHA verification successful")

	// Check if user already exists
	logger.Info("register handler checking if user exists", "email", email)
	existingUser, err := controller.Store.FindUser(email)
	if err != nil {
		logger.Error("register handler error finding user", "error", err)
		controller.renderRegisterErrorChi(w, r, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
		return
	}

	if existingUser != nil {
		logger.Info("register handler user exists", "email", email, "verified", existingUser.Verified)

		// If user is already verified, redirect to login
		if existingUser.Verified {
			logger.Info("register handler redirecting verified user to login")
			redirectResponse(w, r, http.StatusFound, "/login")
			return
		}

		// If user exists but is not verified, check if we should resend verification email
		logger.Info("register handler checking if should resend verification for unverified user")
		lastAttempt, err := controller.Store.GetLastRegistrationAttempt(email)
		if err != nil {
			logger.Error("register handler error getting last registration attempt", "error", err)
			controller.renderRegisterErrorChi(w, r, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
			return
		}

		// If last attempt was less than 5 minutes ago, show debounce message
		if time.Now().Unix()-lastAttempt < 300 {
			logger.Info("register handler email debouncing", "last_attempt", lastAttempt, "time_since", time.Now().Unix()-lastAttempt)
			w.WriteHeader(http.StatusTooManyRequests)
			controller.renderRegisterErrorChi(w, r, email, "Please wait a few minutes before trying again", altchaChallenge, http.StatusTooManyRequests)
			return
		}

		// Check for too many failed verification attempts
		failedAttempts, err := controller.Store.GetFailedVerificationAttempts(email)
		if err != nil {
			logger.Error("register handler error getting failed verification attempts", "error", err)
			controller.renderRegisterErrorChi(w, r, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
			return
		}

		// Block after 5 failed attempts
		if failedAttempts >= 5 {
			logger.Info("register handler too many failed verification attempts", "failed_attempts", failedAttempts)
			controller.renderRegisterErrorChi(w, r, email, "Too many failed verification attempts. Please try again later.", altchaChallenge, http.StatusTooManyRequests)
			return
		}

		// Check for too many active tokens
		activeTokens, err := controller.Store.GetActiveVerificationTokensCount(email)
		if err != nil {
			logger.Error("register handler error getting active tokens count", "error", err)
			controller.renderRegisterErrorChi(w, r, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
			return
		}

		// Maximum 3 active tokens per email
		if activeTokens >= 3 {
			logger.Info("register handler too many active tokens", "active_tokens", activeTokens)
			controller.renderRegisterErrorChi(w, r, email, "Too many active verification links. Please check your email or try again later.", altchaChallenge, http.StatusTooManyRequests)
			return
		}

		// OK, we don't need to debounce the user, we can resend the verification email
		logger.Info("register handler resending verification email for unverified user")
		err = controller.sendVerificationEmail(email)
		if err != nil {
			logger.Error("register handler error sending verification email", "error", err)
			controller.renderRegisterErrorChi(w, r, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
			return
		}

		logger.Info("register handler verification email resent successfully")
		controller.renderRegisterSuccessChi(w, r, email, "Verification email sent. Please check your email to verify your account.", altchaChallenge)
		return
	}

	// Create new user
	logger.Info("register handler creating new user", "email", email)
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		logger.Error("register handler error hashing password", "error", err)
		controller.renderRegisterErrorChi(w, r, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
		return
	}

	err = controller.Store.CreateUser(email, hashedPassword)
	if err != nil {
		logger.Error("register handler error creating user", "error", err)
		controller.renderRegisterErrorChi(w, r, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
		return
	}

	// Send verification email
	logger.Info("register handler sending verification email for new user")
	err = controller.sendVerificationEmail(email)
	if err != nil {
		logger.Error("register handler error sending verification email", "error", err)
		controller.renderRegisterErrorChi(w, r, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
		return
	}

	logger.Info("register handler registration successful")
	controller.renderRegisterSuccessChi(w, r, email, "Registration successful! Please check your email to verify your account.", altchaChallenge)
}

// ShowVerificationPageHandler handles the verification page display
func (controller *ChiController) ShowVerificationPageHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Show verification page")

	code := getParamChi(r, "code")
	if code == "" {
		page := VerifyPage{
			Code:  code,
			Error: "Invalid or missing verification code",
		}
		w.WriteHeader(http.StatusBadRequest)
		controller.renderTemplate(w, "verify.html", page)
		return
	}

	controller.verifyWithCodeChi(w, r, code)
}

// VerifyHandler handles email verification
func (controller *ChiController) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Verify endpoint")

	code := getFormValueChi(r, "code")
	// basic validation
	if code == "" {
		logger.Info("verify handler validation failed - code is empty")
		page := VerifyPage{
			Error: "Verification code is required",
		}
		w.WriteHeader(http.StatusBadRequest)
		controller.renderTemplate(w, "verify.html", page)
		return
	}
	logger.Info("verify handler received code", "code", code)

	controller.verifyWithCodeChi(w, r, code)
}

// verifyWithCodeChi handles verification with a specific code
func (controller *ChiController) verifyWithCodeChi(w http.ResponseWriter, r *http.Request, code string) {
	logger.Info("verifyWithCode handler called", "code", code)

	// Find and validate token
	verificationToken, err := controller.Store.FindVerificationToken(code)
	if err != nil {
		logger.Error("verify handler error finding token", "error", err)
		page := VerifyPage{
			Error: "Internal error",
		}
		w.WriteHeader(http.StatusInternalServerError)
		controller.renderTemplate(w, "verify.html", page)
		return
	}

	if verificationToken == nil {
		logger.Info("verify handler token not found", "code", code)
		page := VerifyPage{
			Error: "Invalid or expired verification code",
		}
		w.WriteHeader(http.StatusBadRequest)
		controller.renderTemplate(w, "verify.html", page)
		return
	}

	// Check if token is expired
	if time.Now().Unix() > verificationToken.Expires {
		logger.Info("verify handler token expired", "code", code, "expires_at", verificationToken.Expires)
		err := controller.Store.DeleteVerificationToken(code)
		if err != nil {
			sendInternalErrorChi(w, r, err, nil, "Internal error")
			return
		}
		page := VerifyPage{
			Error: "Verification link has expired",
		}
		w.WriteHeader(http.StatusBadRequest)
		controller.renderTemplate(w, "verify.html", page)
		return
	}

	// Mark user as verified
	err = controller.Store.VerifyUser(verificationToken.Email)
	if err != nil {
		logger.Error("verify handler error verifying user", "error", err)
		page := VerifyPage{
			Error: "Internal error",
		}
		w.WriteHeader(http.StatusInternalServerError)
		controller.renderTemplate(w, "verify.html", page)
		return
	}

	// Delete the verification token
	err = controller.Store.DeleteVerificationToken(code)
	if err != nil {
		logger.Error("verify handler error deleting token", "error", err)
		sendInternalErrorChi(w, r, err, nil, "Internal error")
		return
	}

	logger.Info("verify handler verification successful", "email", verificationToken.Email)
	page := VerifyPage{
		Success: "Verification successful",
	}
	controller.renderTemplate(w, "verify.html", page)
}

// ShowForgotPasswordPageHandler handles the forgot password page display
func (controller *ChiController) ShowForgotPasswordPageHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Show forgot password page")

	page := ForgotPasswordPage{
		Email:   getParamChi(r, "email"),
		Error:   "",
		Success: "",
	}

	controller.renderTemplate(w, "forgot-password.html", page)
}

// ForgotPasswordHandler handles forgot password requests
func (controller *ChiController) ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Forgot password endpoint")

	email := getFormValueChi(r, "email")

	// Basic validation
	if email == "" {
		page := ForgotPasswordPage{
			Email: email,
			Error: "Email is required",
		}
		w.WriteHeader(http.StatusBadRequest)
		controller.renderTemplate(w, "forgot-password.html", page)
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
		controller.renderTemplate(w, "forgot-password.html", page)
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
		logger.Error("Failed to send password reset email", "error", err)
		// Continue with the flow even if email sending fails
	}

	page := ForgotPasswordPage{
		Email:   email,
		Success: "If an account exists with this email, you will receive a password reset link.",
	}
	controller.renderTemplate(w, "forgot-password.html", page)
}

// ShowResetPasswordPageHandler handles the reset password page display
func (controller *ChiController) ShowResetPasswordPageHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Show reset password page")

	token := getParamChi(r, "token")

	page := ResetPasswordPage{
		Token:   token,
		Error:   "",
		Success: "",
	}

	controller.renderTemplate(w, "reset-password.html", page)
}

// ResetPasswordHandler handles password reset
func (controller *ChiController) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Reset password endpoint")

	token := getFormValueChi(r, "token")
	password := getFormValueChi(r, "password")
	confirmPassword := getFormValueChi(r, "confirmPassword")

	// Basic validation
	if token == "" || password == "" || confirmPassword == "" {
		page := ResetPasswordPage{
			Token: token,
			Error: "All fields are required",
		}
		w.WriteHeader(http.StatusBadRequest)
		controller.renderTemplate(w, "reset-password.html", page)
		return
	}

	if password != confirmPassword {
		page := ResetPasswordPage{
			Token: token,
			Error: "Passwords do not match",
		}
		w.WriteHeader(http.StatusBadRequest)
		controller.renderTemplate(w, "reset-password.html", page)
		return
	}

	// Find and validate token
	verificationToken, err := controller.Store.FindVerificationToken(token)
	if err != nil {
		page := ResetPasswordPage{
			Error: "Internal error",
		}
		w.WriteHeader(http.StatusInternalServerError)
		controller.renderTemplate(w, "reset-password.html", page)
		return
	}

	if verificationToken == nil || verificationToken.Type != "password_reset" {
		page := ResetPasswordPage{
			Error: "Invalid or expired reset link",
		}
		w.WriteHeader(http.StatusBadRequest)
		controller.renderTemplate(w, "reset-password.html", page)
		return
	}

	if verificationToken.Expires < time.Now().Unix() {
		err := controller.Store.DeleteVerificationToken(token)
		if err != nil {
			page := ResetPasswordPage{
				Error: "Internal error",
			}
			w.WriteHeader(http.StatusInternalServerError)
			controller.renderTemplate(w, "reset-password.html", page)
			return
		}
		page := ResetPasswordPage{
			Error: "Reset link has expired",
		}
		w.WriteHeader(http.StatusBadRequest)
		controller.renderTemplate(w, "reset-password.html", page)
		return
	}

	// Hash new password
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		page := ResetPasswordPage{
			Error: "Internal error",
		}
		w.WriteHeader(http.StatusInternalServerError)
		controller.renderTemplate(w, "reset-password.html", page)
		return
	}

	// Update password
	err = controller.Store.UpdateUserPassword(verificationToken.Email, hashedPassword)
	if err != nil {
		page := ResetPasswordPage{
			Error: "Internal error",
		}
		w.WriteHeader(http.StatusInternalServerError)
		controller.renderTemplate(w, "reset-password.html", page)
		return
	}

	// Delete used token
	err = controller.Store.DeleteVerificationToken(token)
	if err != nil {
		page := ResetPasswordPage{
			Error: "Internal error",
		}
		w.WriteHeader(http.StatusInternalServerError)
		controller.renderTemplate(w, "reset-password.html", page)
		return
	}

	page := ResetPasswordPage{
		Success: "Password has been reset successfully. You can now log in with your new password.",
	}
	controller.renderTemplate(w, "reset-password.html", page)
}

// ShowDeleteAccountPageHandler handles the delete account page display
func (controller *ChiController) ShowDeleteAccountPageHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Show delete account page")
	controller.renderTemplate(w, "delete-account.html", DeleteAccountPage{})
}

// DeleteAccountHandler handles account deletion requests
func (controller *ChiController) DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Delete account endpoint")

	email := getFormValueChi(r, "email")
	if email == "" {
		page := DeleteAccountPage{
			Error: "Email is required",
		}
		w.WriteHeader(http.StatusBadRequest)
		controller.renderTemplate(w, "delete-account.html", page)
		return
	}

	// Check if user exists and is verified
	user, err := controller.Store.FindUser(email)
	if err != nil {
		page := DeleteAccountPage{
			Error: "Internal error",
		}
		w.WriteHeader(http.StatusInternalServerError)
		controller.renderTemplate(w, "delete-account.html", page)
		return
	}

	if user == nil || !user.Verified {
		// Don't reveal if the email exists or not for security
		page := DeleteAccountPage{
			Success: "If your account exists and is verified, you will receive an email with instructions to delete it.",
		}
		controller.renderTemplate(w, "delete-account.html", page)
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
		w.WriteHeader(http.StatusInternalServerError)
		controller.renderTemplate(w, "delete-account.html", page)
		return
	}

	// Send delete verification email
	deleteLink := fmt.Sprintf("%s/verify-delete?token=%s", controller.Config.BaseUrl, token)
	err = controller.EmailService.SendDeleteAccountEmail(email, deleteLink)
	if err != nil {
		logger.Error("Failed to send delete account email", "error", err)
	}

	page := DeleteAccountPage{
		Success: "If your account exists and is verified, you will receive an email with instructions to delete it.",
	}
	controller.renderTemplate(w, "delete-account.html", page)
}

// TODO: this implementation does not seem right, we just always show the page with an error??
// ShowVerifyDeletePageHandler handles the verify delete page display
func (controller *ChiController) ShowVerifyDeletePageHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Show verify delete page")

	token := getParamChi(r, "token")

	page := VerifyDeletePage{
		Code:    token,
		Error:   "",
		Success: "",
	}

	controller.renderTemplate(w, "verify-delete.html", page)
}

// VerifyDeleteHandler handles delete verification
func (controller *ChiController) VerifyDeleteHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Verify delete endpoint")

	token := getFormValueChi(r, "code")
	if token == "" {
		page := VerifyDeletePage{
			Error: "Verification code is required",
		}
		w.WriteHeader(http.StatusBadRequest)
		controller.renderTemplate(w, "verify-delete.html", page)
		return
	}

	// Find and validate token
	verificationToken, err := controller.Store.FindVerificationToken(token)
	if err != nil {
		page := VerifyDeletePage{
			Error: "Internal error",
		}
		w.WriteHeader(http.StatusInternalServerError)
		controller.renderTemplate(w, "verify-delete.html", page)
		return
	}

	if verificationToken == nil || verificationToken.Type != "delete_account" {
		page := VerifyDeletePage{
			Error: "Invalid or expired verification code",
		}
		w.WriteHeader(http.StatusBadRequest)
		controller.renderTemplate(w, "verify-delete.html", page)
		return
	}

	// Check if token is expired
	if time.Now().Unix() > verificationToken.Expires {
		logger.Info("verify delete handler token expired", "token", token, "expires_at", verificationToken.Expires)
		page := VerifyDeletePage{
			Error: "Verification code has expired",
		}
		w.WriteHeader(http.StatusBadRequest)
		controller.renderTemplate(w, "verify-delete.html", page)
		return
	}

	// Delete the user
	err = controller.Store.DeleteUser(verificationToken.Email)
	if err != nil {
		page := VerifyDeletePage{
			Error: "Internal error",
		}
		w.WriteHeader(http.StatusInternalServerError)
		controller.renderTemplate(w, "verify-delete.html", page)
		return
	}

	// Delete the verification token
	err = controller.Store.DeleteVerificationToken(token)
	if err != nil {
		logger.Error("verify delete handler error deleting token", "error", err)
		// Don't fail the deletion if we can't delete the token
	}

	logger.Info("verify delete handler account deletion successful", "email", verificationToken.Email)
	page := VerifyDeletePage{
		Success: "Your account has been deleted successfully.",
	}
	controller.renderTemplate(w, "verify-delete.html", page)
}

// ResendDeleteVerificationHandler handles resending delete verification
func (controller *ChiController) ResendDeleteVerificationHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Resend delete verification endpoint")

	email := getParamChi(r, "email")
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
		logger.Error("Failed to send delete account email", "error", err)
	}

	redirectResponse(w, r, http.StatusFound, "/delete-account")
}

// Helper methods

func (controller *ChiController) validateCredentials(username, password string) (bool, error) {
	user, err := controller.Store.FindUser(username)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, nil
	}
	return crypto.CheckPasswordHash(password, user.Password), nil
}

func (controller *ChiController) sendVerificationEmail(email string) error {
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

// Chi-specific render helper functions

// renderRegisterErrorChi renders the registration page with an error message
func (controller *ChiController) renderRegisterErrorChi(w http.ResponseWriter, r *http.Request, email, errorMsg, altchaChallenge string, statusCode int) {
	w.WriteHeader(statusCode)
	page := RegisterPage{
		Email:           email,
		Error:           errorMsg,
		AltchaChallenge: altchaChallenge,
	}
	controller.renderTemplate(w, "register.html", page)
}

// renderRegisterSuccessChi renders the registration page with a success message
func (controller *ChiController) renderRegisterSuccessChi(w http.ResponseWriter, r *http.Request, email, successMsg, altchaChallenge string) {
	page := RegisterPage{
		Email:           email,
		Success:         successMsg,
		AltchaChallenge: altchaChallenge,
	}
	controller.renderTemplate(w, "register.html", page)
}

// GenerateIdToken See https://openid.net/specs/openid-connect-basic-1_0.html#IDToken
func GenerateIdToken(jwtConfig domain.JwtConfiguration, clientId string, userName string, claims map[string]interface{}) (string, error) {
	// Start with standard claims
	tokenClaims := jwt.MapClaims{
		"iss": jwtConfig.Issuer,
		"sub": userName,
		"aud": clientId,
		"exp": time.Now().Add(time.Minute * time.Duration(jwtConfig.IdTokenValidityMinutes)).Unix(),
		"iat": time.Now().Unix(),
	}

	// Add any additional claims
	for key, value := range claims {
		tokenClaims[key] = value
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	return t.SignedString(jwtConfig.PrivateKey)
}
