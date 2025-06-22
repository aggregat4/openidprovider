package server

import (
	"aggregat4/openidprovider/internal/cleanup"
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/repository"
	"aggregat4/openidprovider/pkg/email"

	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	baselibmiddleware "github.com/aggregat4/go-baselib-services/v3/middleware"
	"github.com/aggregat4/go-baselib/crypto"
	"github.com/altcha-org/altcha-lib-go"
	"github.com/gorilla/sessions"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var logger = slog.New(slog.NewTextHandler(os.Stdout, nil))

//go:embed public/views/*.html public/styles/*.css
var staticFiles embed.FS

const ContentTypeJson = "application/json;charset=UTF-8"

type Controller struct {
	Store        *repository.Store
	Config       domain.Configuration
	EmailService email.EmailSender
	CleanupJob   *cleanup.CleanupJob
}

func RunServer(controller Controller) {
	e := InitServer(controller)
	e.Logger.Fatal(e.Start(":" + strconv.Itoa(controller.Config.ServerPort)))
	// NO MORE CODE HERE, IT WILL NOT BE EXECUTED
}

func InitServer(controller Controller) *echo.Echo {
	e := echo.New()

	// Set server timeouts based on advice from https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/#1687428081
	e.Server.ReadTimeout = time.Duration(controller.Config.ServerReadTimeoutSeconds) * time.Second
	e.Server.WriteTimeout = time.Duration(controller.Config.ServerWriteTimeoutSeconds) * time.Second

	// Start cleanup job
	controller.CleanupJob = cleanup.NewCleanupJob(controller.Store, controller.Config.CleanupConfig)
	controller.CleanupJob.Start()

	t := &Template{
		templates: template.Must(template.New("").ParseFS(staticFiles, "public/views/*.html")),
	}
	e.Renderer = t

	// Serve static files
	staticHandler := echo.WrapHandler(http.FileServer(http.FS(staticFiles)))
	e.GET("/public/*", staticHandler)
	// Initialize middleware
	e.Use(middleware.Logger())

	// Debug middleware to log all requests
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			logger.Info("Incoming request",
				"method", c.Request().Method,
				"path", c.Request().URL.Path,
				"query", c.Request().URL.RawQuery,
				"user_agent", c.Request().UserAgent(),
				"remote_addr", c.Request().RemoteAddr)

			// Log form data for POST requests
			if c.Request().Method == "POST" {
				if err := c.Request().ParseForm(); err == nil {
					logger.Info("Form data", "form", c.Request().Form)
				}
			}

			err := next(c)

			logger.Info("Request completed",
				"method", c.Request().Method,
				"path", c.Request().URL.Path,
				"status", c.Response().Status,
				"error", err)

			return err
		}
	})

	e.Use(session.Middleware(sessions.NewCookieStore([]byte(uuid.New().String()))))
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{Level: 5}))
	e.Use(middleware.BasicAuthWithConfig(middleware.BasicAuthConfig{
		// we only require basic auth for the token endpoint
		Skipper: func(c echo.Context) bool {
			return c.Path() != "/token"
		},
		Validator: controller.basicAuthValidator,
	}))
	// CSRF protection middleware
	e.Use(baselibmiddleware.CreateCsrfMiddlewareWithSkipper(func(c echo.Context) bool {
		return c.Path() == "/token"
	}))

	e.GET("/status", controller.Status)

	e.GET("/.well-known/openid-configuration", controller.openIdConfiguration)
	e.GET("/.well-known/jwks.json", controller.jwks)

	e.GET("/authorize", controller.authorize)
	e.POST("/authorize", controller.authorize)

	e.GET("/login", controller.login)
	e.POST("/login", controller.login)

	e.POST("/token", controller.token)

	e.GET("/register", controller.showRegisterPage)
	e.POST("/register", controller.register)

	e.GET("/verify", controller.showVerificationPage)
	e.POST("/verify", controller.verify)

	e.GET("/forgot-password", controller.showForgotPasswordPage)
	e.POST("/forgot-password", controller.forgotPassword)
	e.GET("/reset-password", controller.showResetPasswordPage)
	e.POST("/reset-password", controller.resetPassword)

	e.GET("/delete-account", controller.showDeleteAccountPage)
	e.POST("/delete-account", controller.deleteAccount)
	e.GET("/verify-delete", controller.showVerifyDeletePage)
	e.POST("/verify-delete", controller.verifyDelete)
	e.GET("/verify-delete/resend", controller.resendDeleteVerification)

	return e
}

func (controller *Controller) Status(c echo.Context) error {
	logger.Info("Status endpoint")
	return c.String(http.StatusOK, "OK")
}

// This endpoint returns a JWKS document containing the public key
// that can be used by clients to verify the signature of the ID token
// as we are using the RS256 algorithm with public and private keys
func (controller *Controller) jwks(c echo.Context) error {
	logger.Info("jwks handler called")
	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, 1),
	}
	jwks.Keys[0] = jose.JSONWebKey{
		Key:       controller.Config.JwtConfig.PublicKey,
		KeyID:     "id-token-key",
		Use:       "sig",
		Algorithm: "RS256",
	}
	jwksBytes, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create JWKS document")
	} else {
		c.Response().Header().Set("Content-Type", "application/json")
		return c.String(http.StatusOK, string(jwksBytes))
	}
}

// openIdConfiguration returns the OpenID Connect configuration for this
// server. See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
func (controller *Controller) openIdConfiguration(c echo.Context) error {
	logger.Info("openIdConfiguration handler called")
	// Get all scopes from the database
	scopes, err := controller.Store.ListScopes()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get scopes"})
	}

	// Get all claims from the database
	claimsMap := make(map[string]bool)
	for _, scope := range scopes {
		scopeClaims, err := controller.Store.ListScopeClaims(scope.Name)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get scope claims"})
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

	// Convert claims map to slice
	claimsSupported := make([]string, 0, len(claimsMap))
	for claim := range claimsMap {
		claimsSupported = append(claimsSupported, claim)
	}

	c.Response().Header().Set("Content-Type", ContentTypeJson)
	return c.JSON(http.StatusOK, domain.OpenIdConfiguration{
		Issuer:                           controller.Config.BaseUrl,
		AuthorizationEndpoint:            controller.Config.BaseUrl + "/authorize",
		TokenEndpoint:                    controller.Config.BaseUrl + "/token",
		JwksUri:                          controller.Config.BaseUrl + "/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  scopesSupported,
		ClaimsSupported:                  claimsSupported,
	})
}

// basicAuthValidator validates a client ID and client secret provided via
// HTTP Basic Auth. It sets the client ID on the context if valid.
// It use subtle.ConstantTimeCompare to prevent timing attacks.
func (controller *Controller) basicAuthValidator(username, password string, c echo.Context) (bool, error) {
	logger.Info("basicAuthValidator called", "username", username)
	client, clientExists := controller.Config.RegisteredClients[username]
	// apparently the go Oauth2 client library url escapes the username and password
	// This seems weird, and they talk about it here: https://github.com/golang/oauth2/pull/476
	decodedUsername, err := url.QueryUnescape(username)
	if err != nil {
		decodedUsername = ""
	}
	decodedPassword, err := url.QueryUnescape(password)
	if err != nil {
		decodedPassword = ""
	}
	if !clientExists {
		// make sure we nevertheless compare the username and password to make timing attacks harder
		subtle.ConstantTimeCompare([]byte(decodedUsername), []byte("this is not a valid client id"))
		subtle.ConstantTimeCompare([]byte(decodedPassword), []byte("this is not a valid client secret"))
		return false, nil
	}
	c.Set("client_id", client.Id)
	return subtle.ConstantTimeCompare([]byte(decodedUsername), []byte(client.Id)) == 1 &&
		subtle.ConstantTimeCompare([]byte(decodedPassword), []byte(client.BasicAuthSecret)) == 1, nil
}

// OIDC Token Endpoint is described in:
// https://openid.net/specs/openid-connect-basic-1_0.html#ObtainingTokens
// Reference to the OAuth 2 spec:
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
// Error handling as per https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
func (controller *Controller) token(c echo.Context) error {
	logger.Info("token handler called")
	clientId := c.Get("client_id").(string)
	// Validate that the client exists
	client, clientExists := controller.Config.RegisteredClients[clientId]
	if !clientExists {
		return sendOauthAccessTokenError(c, "invalid_client")
	}
	// Validate that the redirect URI is registered for the client
	redirectUri := c.FormValue("redirect_uri")
	if !contains(client.RedirectUris, redirectUri) {
		return sendOauthAccessTokenError(c, "invalid_client")
	}
	// we assume that basic auth has happened and the secret matches, proceed to verify the grant type and code
	grantType := c.FormValue("grant_type")
	if grantType != "authorization_code" {
		return sendOauthAccessTokenError(c, "unsupported_grant_type")
	}
	code := c.FormValue("code")

	// validate that the code exists
	existingCode, err := controller.Store.FindCode(code)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	if existingCode == nil {
		return sendOauthAccessTokenError(c, "invalid_grant")
	}

	// Code was used once, delete it
	err = controller.Store.DeleteCode(code)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	// Validate that the code is for the correct client and redirect URI
	if existingCode.ClientId != clientId || existingCode.RedirectUri != redirectUri {
		return sendOauthAccessTokenError(c, "invalid_grant")
	}

	// Get the user
	user, err := controller.Store.FindUser(existingCode.Email)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	if user == nil {
		return sendOauthAccessTokenError(c, "invalid_grant")
	}

	// Parse requested scopes
	requestedScopes := strings.Split(existingCode.Scopes, " ")

	// Get claims for the requested scopes
	claims, err := controller.Store.GetUserClaimsForScopes(user.Id, requestedScopes)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	// Convert claims to map for ID token
	claimsMap := make(map[string]interface{})
	for _, claim := range claims {
		claimsMap[claim.ClaimName] = claim.Value
	}

	// Finally, generate the access token
	accessToken := uuid.New().String()

	// Respond with the access token
	c.Response().Header().Set("Content-Type", ContentTypeJson)
	c.Response().Header().Set("Cache-Control", "no-store")
	idToken, err := GenerateIdToken(controller.Config.JwtConfig, clientId, user.Email, claimsMap)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	return c.String(http.StatusOK,
		"{\"access_token\":\""+accessToken+"\", \"token_type\":\"Bearer\", \"id_token\":\""+idToken+"\"}")
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

func sendOauthAccessTokenError(c echo.Context, s string) error {
	c.Response().Header().Set("Content-Type", ContentTypeJson)
	return c.String(http.StatusBadRequest, "{\"error\":\""+s+"\"}")
}

// No support for "nonce", "display", "prompt", "max_age", "ui_locales", "id_token_hint", "login_hint", "acr_values" yet
func (controller *Controller) authorize(c echo.Context) error {
	logger.Info("authorize handler called")
	authReqScopes := strings.Split(getParam(c, "scope"), " ")
	authReqResponseType := getParam(c, "response_type")
	authReqClientId := getParam(c, "client_id")
	authReqRedirectUri := getParam(c, "redirect_uri")
	authReqState := getParam(c, "state")

	// First validate the client and redirect URI before using it for error responses
	client, clientExists := controller.Config.RegisteredClients[authReqClientId]
	if !clientExists {
		return c.String(http.StatusBadRequest, "Invalid client")
	}

	// Create redirect URL for error responses
	redirectUrl, err := url.Parse(authReqRedirectUri)
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid redirect URI")
	}

	// Validate that the redirect URI is registered for the client
	if !contains(client.RedirectUris, authReqRedirectUri) {
		return c.String(http.StatusBadRequest, "Invalid redirect URI")
	}

	// Now we can use the redirect URI for error responses
	// Do basic validation whether required parameters are present first
	if len(authReqScopes) == 0 || !contains(authReqScopes, "openid") {
		return sendOauthError(c, redirectUrl, "invalid_scope", "Missing or invalid scope", authReqState)
	}

	if authReqResponseType != "code" {
		return sendOauthError(c, redirectUrl, "unsupported_response_type", "Only code response type is supported", authReqState)
	}

	// Validate requested scopes against database
	for _, scope := range authReqScopes {
		scopeExists, err := controller.Store.ScopeExists(scope)
		if err != nil {
			return sendInternalError(c, err, redirectUrl, authReqState)
		}
		if !scopeExists {
			return sendOauthError(c, redirectUrl, "invalid_scope", "Invalid scope requested: "+scope, authReqState)
		}
	}

	// All is well, redirect to login page with parameters
	loginUrl := fmt.Sprintf("/login?client_id=%s&redirect_uri=%s&state=%s&scope=%s",
		url.QueryEscape(authReqClientId),
		url.QueryEscape(authReqRedirectUri),
		url.QueryEscape(authReqState),
		url.QueryEscape(strings.Join(authReqScopes, " ")))

	return c.Redirect(http.StatusFound, loginUrl)
}

func getParam(c echo.Context, paramName string) string {
	param := c.QueryParam(paramName)
	if param == "" {
		param = c.FormValue(paramName)
	}
	return param
}

type LoginPage struct {
	ClientId    string
	RedirectUri string
	State       string
	Scope       string
}

// Login will return normal BAD REQUEST HTTP status codes for all errors pertaining to client id and redirecturi
// validation.
// This is unclear in the spec as https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1 could be
// interpreted as returning a 302 redirect with an error code in the query string for all these errors
// But since this treats a potential malicious client as a real client, this seems unwise? Or is it better
// to return an OAuth error so the implementor of a buggy client can see what's wrong?
func (controller *Controller) login(c echo.Context) error {
	logger.Info("login handler called")
	clientId := c.FormValue("clientid")
	redirectUri := c.FormValue("redirecturi")
	// Check if this is an OAuth flow by checking if client_id and redirect_uri are present
	isOAuthFlow := clientId != "" && redirectUri != ""

	if isOAuthFlow {
		state := c.FormValue("state")
		scopes := c.FormValue("scope")
		username := c.FormValue("username")
		password := c.FormValue("password")
		return controller.handleOAuthLogin(c, clientId, redirectUri, state, scopes, username, password)
	}

	// if it is NOT an oauth flow, check the method: if it is GET, show the login page
	// if it is POST, handle the login
	method := c.Request().Method
	if method == "GET" {
		return controller.showLoginPage(c)
	}
	username := c.FormValue("username")
	password := c.FormValue("password")
	return controller.handleRegularLogin(c, username, password)
}

func (controller *Controller) handleRegularLogin(c echo.Context, username, password string) error {
	logger.Info("handleRegularLogin called", "username", username)
	// Basic validation
	if username == "" || password == "" {
		return c.String(http.StatusBadRequest, "Missing credentials")
	}

	// Validate credentials
	valid, err := controller.validateCredentials(username, password)
	if err != nil {
		logger.Error("Error validating credentials", "error", err)
		return c.String(http.StatusInternalServerError, "Internal server error")
	}
	if !valid {
		return c.String(http.StatusUnauthorized, "Invalid credentials")
	}

	// TODO: Set session cookie or handle direct web login success
	return c.Redirect(http.StatusFound, "/")
}

func (controller *Controller) handleOAuthLogin(c echo.Context, clientId, redirectUri, state, scopes, username, password string) error {
	logger.Info("handleOAuthLogin called", "clientId", clientId, "username", username)
	// Create redirect URL for error responses
	redirectUrl, err := url.Parse(redirectUri)
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid redirect URI")
	}

	// Basic validation
	if username == "" || password == "" {
		return sendOauthError(c, redirectUrl, "invalid_request", "Missing credentials", state)
	}

	// Validate credentials
	valid, err := controller.validateCredentials(username, password)
	if err != nil {
		logger.Error("Error validating credentials", "error", err)
		return sendInternalError(c, err, redirectUrl, state)
	}
	if !valid {
		return sendOauthError(c, redirectUrl, "access_denied", "Invalid credentials", state)
	}

	// OAuth flow validation
	client, clientExists := controller.Config.RegisteredClients[clientId]
	if !clientExists {
		return sendOauthError(c, redirectUrl, "invalid_client", "Client does not exist", state)
	}

	if !contains(client.RedirectUris, redirectUri) {
		return sendOauthError(c, redirectUrl, "invalid_client", "Invalid redirect URI", state)
	}

	// Get user for OAuth flow
	user, err := controller.Store.FindUser(username)
	if err != nil {
		return sendInternalError(c, err, redirectUrl, state)
	}

	if user == nil {
		logger.Debug("User not found with username")
		// See https://openid.net/specs/openid-connect-core-1_0.html#AuthError
		return sendOauthError(c, redirectUrl, "access_denied", "Invalid username or password", state)
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
		return sendInternalError(c, err, redirectUrl, state)
	}

	query := redirectUrl.Query()
	query.Add("code", code)
	query.Add("state", state)
	redirectUrl.RawQuery = query.Encode()
	logger.Info("login request password ok. redirecting")
	return c.Redirect(http.StatusFound, redirectUrl.String())
}

func sendInternalError(c echo.Context, originalError error, fullRedirectUri *url.URL, state string) error {
	logger.Error("Error processing request", "error", originalError)
	return sendOauthError(c, fullRedirectUri, "server_error", "Internal server error", state)
}

func sendOauthError(c echo.Context, redirectUri *url.URL, errorCode string, description string, state string) error {
	query := redirectUri.Query()
	query.Add("error", errorCode)
	query.Add("error_description", description)
	if state != "" {
		query.Add("state", state)
	}
	redirectUri.RawQuery = query.Encode()
	return c.Redirect(http.StatusFound, redirectUri.String())
}

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, _ echo.Context) error {
	logger.Info("Rendering template", "template", name, "data", data)
	err := t.templates.ExecuteTemplate(w, name, data)
	if err != nil {
		logger.Error("Template rendering error", "template", name, "error", err, "data", data)
	}
	return err
}

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

// renderRegisterError is a helper function to reduce repetitive error handling in the register method
func (controller *Controller) renderRegisterError(c echo.Context, email, errorMsg, altchaChallenge string, statusCode int) error {
	return c.Render(statusCode, "register", RegisterPage{
		Email:           email,
		Error:           errorMsg,
		AltchaChallenge: altchaChallenge,
	})
}

// renderRegisterSuccess is a helper function to reduce repetitive success handling in the register method
func (controller *Controller) renderRegisterSuccess(c echo.Context, email, successMsg, altchaChallenge string) error {
	return c.Render(http.StatusOK, "register", RegisterPage{
		Email:           email,
		Success:         successMsg,
		AltchaChallenge: altchaChallenge,
	})
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

func (controller *Controller) showRegisterPage(c echo.Context) error {
	logger.Info("showRegisterPage handler called")

	// Generate ALTCHA challenge
	challenge, err := altcha.CreateChallenge(altcha.ChallengeOptions{
		HMACKey:    controller.Config.AltchaConfig.HMACKey,
		MaxNumber:  controller.Config.AltchaConfig.MaxNumber,
		SaltLength: controller.Config.AltchaConfig.SaltLength,
	})
	if err != nil {
		return c.Render(http.StatusInternalServerError, "register", RegisterPage{
			Email:           "",
			Error:           "Internal error",
			AltchaChallenge: "",
		})
	} else {
		// Convert challenge to JSON
		challengeJSON, err := json.Marshal(challenge)
		if err != nil {
			logger.Error("Failed to marshal ALTCHA challenge to JSON", "error", err)
			return c.Render(http.StatusInternalServerError, "register", RegisterPage{
				Email:           "",
				Error:           "Internal error",
				AltchaChallenge: "",
			})
		}
		logger.Info("showRegisterPage handler generated ALTCHA challenge", "challenge", string(challengeJSON))
		return c.Render(http.StatusOK, "register", RegisterPage{
			Email:           c.FormValue("email"),
			Error:           "",
			Success:         "",
			AltchaChallenge: string(challengeJSON),
		})
	}
}

func (controller *Controller) register(c echo.Context) error {
	logger.Info("register handler called")
	email := c.FormValue("email")
	password := c.FormValue("password")
	confirmPassword := c.FormValue("confirmPassword")
	altchaSolution := c.FormValue("altcha")

	logger.Info("register handler form values", "email", email, "password_length", len(password), "confirmPassword_length", len(confirmPassword), "altcha_solution", string(altchaSolution))

	// Prepare ALTCHA configuration for all responses
	// Generate ALTCHA challenge
	challenge, err := altcha.CreateChallenge(altcha.ChallengeOptions{
		HMACKey:    controller.Config.AltchaConfig.HMACKey,
		MaxNumber:  controller.Config.AltchaConfig.MaxNumber,
		SaltLength: controller.Config.AltchaConfig.SaltLength,
	})
	if err != nil {
		logger.Error("Failed to create ALTCHA challenge", "error", err)
		return controller.renderRegisterError(c, email, "Internal error", "", http.StatusInternalServerError)
	}
	// Convert challenge to JSON
	challengeJSON, err := json.Marshal(challenge)
	if err != nil {
		logger.Error("Failed to marshal ALTCHA challenge to JSON", "error", err)
		return controller.renderRegisterError(c, email, "Internal error", "", http.StatusInternalServerError)
	}
	altchaChallenge := string(challengeJSON)
	logger.Info("register handler generated ALTCHA challenge", "challenge", string(challengeJSON))

	// Basic validation
	if email == "" || password == "" || confirmPassword == "" {
		logger.Info("register handler validation failed - empty fields")
		return controller.renderRegisterError(c, email, "All fields are required", altchaChallenge, http.StatusBadRequest)
	}

	if password != confirmPassword {
		logger.Info("register handler validation failed - passwords don't match")
		return controller.renderRegisterError(c, email, "Passwords do not match", altchaChallenge, http.StatusBadRequest)
	}

	// verify that the password is at least 8 characters long
	if len(password) < 8 {
		logger.Info("register handler validation failed - password too short")
		return controller.renderRegisterError(c, email, "Password must be at least 8 characters long", altchaChallenge, http.StatusBadRequest)
	}

	// Verify ALTCHA if enabled
	logger.Info("register handler ALTCHA verification enabled")
	if altchaSolution == "" {
		logger.Info("register handler ALTCHA solution missing")
		return controller.renderRegisterError(c, email, "Please complete the captcha", altchaChallenge, http.StatusBadRequest)
	}

	// Verify the ALTCHA solution (the library decodes the base64 encoded solution)
	ok, err := altcha.VerifySolution(altchaSolution, controller.Config.AltchaConfig.HMACKey, true)
	if err != nil {
		logger.Error("register handler ALTCHA verification error", "error", err)
		return controller.renderRegisterError(c, email, "Captcha verification failed", altchaChallenge, http.StatusBadRequest)
	}
	if !ok {
		logger.Info("register handler ALTCHA verification failed")
		return controller.renderRegisterError(c, email, "Captcha verification failed", altchaChallenge, http.StatusBadRequest)
	}
	logger.Info("register handler ALTCHA verification successful")

	// Check if user already exists
	logger.Info("register handler checking if user exists", "email", email)
	existingUser, err := controller.Store.FindUser(email)
	if err != nil {
		logger.Error("register handler error finding user", "error", err)
		return controller.renderRegisterError(c, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
	}

	if existingUser != nil {
		logger.Info("register handler user exists", "email", email, "verified", existingUser.Verified)

		// If user is already verified, redirect to login
		if existingUser.Verified {
			logger.Info("register handler redirecting verified user to login")
			return c.Redirect(http.StatusFound, "/login")
		}

		// If user exists but is not verified, check if we should resend verification email
		logger.Info("register handler checking if should resend verification for unverified user")
		lastAttempt, err := controller.Store.GetLastRegistrationAttempt(email)
		if err != nil {
			logger.Error("register handler error getting last registration attempt", "error", err)
			return controller.renderRegisterError(c, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
		}

		// If last attempt was less than 5 minutes ago, show debounce message
		if time.Now().Unix()-lastAttempt < 300 {
			logger.Info("register handler email debouncing", "last_attempt", lastAttempt, "time_since", time.Now().Unix()-lastAttempt)
			return controller.renderRegisterError(c, email, "Please wait a few minutes before trying again", altchaChallenge, http.StatusTooManyRequests)
		}

		// Check for too many failed verification attempts
		failedAttempts, err := controller.Store.GetFailedVerificationAttempts(email)
		if err != nil {
			logger.Error("register handler error getting failed verification attempts", "error", err)
			return controller.renderRegisterError(c, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
		}

		// Block after 5 failed attempts
		if failedAttempts >= 5 {
			logger.Info("register handler too many failed verification attempts", "failed_attempts", failedAttempts)
			return controller.renderRegisterError(c, email, "Too many failed verification attempts. Please try again later.", altchaChallenge, http.StatusTooManyRequests)
		}

		// Check for too many active tokens
		activeTokens, err := controller.Store.GetActiveVerificationTokensCount(email)
		if err != nil {
			logger.Error("register handler error getting active tokens count", "error", err)
			return controller.renderRegisterError(c, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
		}

		// Maximum 3 active tokens per email
		if activeTokens >= 3 {
			logger.Info("register handler too many active tokens", "active_tokens", activeTokens)
			return controller.renderRegisterError(c, email, "Too many active verification links. Please check your email or try again later.", altchaChallenge, http.StatusTooManyRequests)
		}

		// OK, we don't need to debounce the user, we can resend the verification email
		logger.Info("register handler resending verification email for unverified user")
		err = controller.sendVerificationEmail(email)
		if err != nil {
			logger.Error("register handler error sending verification email", "error", err)
			return controller.renderRegisterError(c, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
		}

		logger.Info("register handler verification email resent successfully")
		return controller.renderRegisterSuccess(c, email, "Verification email sent. Please check your email to verify your account.", altchaChallenge)
	}

	// Create new user
	logger.Info("register handler creating new user", "email", email)
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		logger.Error("register handler error hashing password", "error", err)
		return controller.renderRegisterError(c, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
	}

	err = controller.Store.CreateUser(email, hashedPassword)
	if err != nil {
		logger.Error("register handler error creating user", "error", err)
		return controller.renderRegisterError(c, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
	}

	// Send verification email
	logger.Info("register handler sending verification email for new user")
	err = controller.sendVerificationEmail(email)
	if err != nil {
		logger.Error("register handler error sending verification email", "error", err)
		return controller.renderRegisterError(c, email, "Internal error", altchaChallenge, http.StatusInternalServerError)
	}

	logger.Info("register handler registration successful")
	return controller.renderRegisterSuccess(c, email, "Registration successful! Please check your email to verify your account.", altchaChallenge)
}

func (controller *Controller) showVerificationPage(c echo.Context) error {
	logger.Info("showVerificationPage handler called")
	code := c.QueryParam("code")
	if code == "" {
		return c.Render(http.StatusBadRequest, "verify", VerifyPage{
			Code:  code,
			Error: "Invalid or missing verification code",
		})
	} else {
		return controller.verifyWithCode(c, code)
	}
}

func (controller *Controller) verify(c echo.Context) error {
	logger.Info("verify handler called")
	// get the code from the submitted form parameters
	code := c.FormValue("code")
	// basic validation
	if code == "" {
		logger.Info("verify handler validation failed - code is empty")
		return c.Render(http.StatusBadRequest, "verify", VerifyPage{
			Error: "Verification code is required",
		})
	}
	logger.Info("verify handler received code", "code", code)

	return controller.verifyWithCode(c, code)
}

func (controller *Controller) verifyWithCode(c echo.Context, code string) error {
	logger.Info("verifyWithCode handler called", "code", code)

	// Find and validate token
	verificationToken, err := controller.Store.FindVerificationToken(code)
	if err != nil {
		logger.Error("verify handler error finding token", "error", err)
		return c.Render(http.StatusInternalServerError, "verify", VerifyPage{
			Error: "Internal error",
		})
	}

	if verificationToken == nil {
		logger.Info("verify handler token not found", "code", code)
		return c.Render(http.StatusBadRequest, "verify", VerifyPage{
			Error: "Invalid or expired verification code",
		})
	}

	logger.Info("verify handler found token", "code", code, "email", verificationToken.Email, "type", verificationToken.Type, "expires", verificationToken.Expires)

	if verificationToken.Expires < time.Now().Unix() {
		err := controller.Store.DeleteVerificationToken(code)
		if err != nil {
			return c.Render(http.StatusInternalServerError, "verify", VerifyPage{
				Error: "Internal error",
			})
		}
		return c.Render(http.StatusBadRequest, "verify", VerifyPage{
			Error: "Verification link has expired",
		})
	}

	// Verify user
	err = controller.Store.VerifyUser(verificationToken.Email)
	if err != nil {
		return c.Render(http.StatusInternalServerError, "verify", VerifyPage{
			Error: "Internal error",
		})
	}

	// Delete used token
	err = controller.Store.DeleteVerificationToken(code)
	if err != nil {
		return c.Render(http.StatusInternalServerError, "verify", VerifyPage{
			Error: "Internal error",
		})
	}

	// Show success message
	return c.Render(http.StatusOK, "verify", VerifyPage{
		Error:   "",
		Success: "Verification successful! You can now log in.",
	})
}

func (controller *Controller) showLoginPage(c echo.Context) error {
	logger.Info("showLoginPage handler called")
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.Render(http.StatusOK, "login", LoginPage{
		ClientId:    c.QueryParam("client_id"),
		RedirectUri: c.QueryParam("redirect_uri"),
		State:       c.QueryParam("state"),
		Scope:       c.QueryParam("scope"),
	})
}

func (controller *Controller) showForgotPasswordPage(c echo.Context) error {
	logger.Info("showForgotPasswordPage handler called")
	return c.Render(http.StatusOK, "forgot-password", ForgotPasswordPage{
		Email:   c.FormValue("email"),
		Error:   "",
		Success: "",
	})
}

func (controller *Controller) forgotPassword(c echo.Context) error {
	logger.Info("forgotPassword handler called")
	email := c.FormValue("email")

	// Basic validation
	if email == "" {
		return c.Render(http.StatusBadRequest, "forgot-password", ForgotPasswordPage{
			Email: email,
			Error: "Email is required",
		})
	}

	// Check if user exists and is verified
	user, err := controller.Store.FindUser(email)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	if user == nil || !user.Verified {
		// Don't reveal if the email exists or not for security
		return c.Render(http.StatusOK, "forgot-password", ForgotPasswordPage{
			Email:   email,
			Success: "If an account exists with this email, you will receive a password reset link.",
		})
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
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	// Send reset email
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", controller.Config.BaseUrl, token)
	err = controller.EmailService.SendPasswordResetEmail(email, resetLink)
	if err != nil {
		logger.Error("Failed to send password reset email", "error", err)
		// Continue with the flow even if email sending fails
	}

	return c.Render(http.StatusOK, "forgot-password", ForgotPasswordPage{
		Email:   email,
		Success: "If an account exists with this email, you will receive a password reset link.",
	})
}

func (controller *Controller) showResetPasswordPage(c echo.Context) error {
	logger.Info("showResetPasswordPage handler called")
	token := c.QueryParam("token")
	return c.Render(http.StatusOK, "reset-password", ResetPasswordPage{
		Token: token,
	})
}

func (controller *Controller) resetPassword(c echo.Context) error {
	logger.Info("resetPassword handler called")
	token := c.FormValue("token")
	password := c.FormValue("password")
	confirmPassword := c.FormValue("confirmPassword")

	// Basic validation
	if token == "" || password == "" || confirmPassword == "" {
		return c.Render(http.StatusBadRequest, "reset-password", ResetPasswordPage{
			Token: token,
			Error: "All fields are required",
		})
	}

	if password != confirmPassword {
		return c.Render(http.StatusBadRequest, "reset-password", ResetPasswordPage{
			Token: token,
			Error: "Passwords do not match",
		})
	}

	// Find and validate token
	verificationToken, err := controller.Store.FindVerificationToken(token)
	if err != nil {
		return c.Render(http.StatusInternalServerError, "reset-password", ResetPasswordPage{
			Error: "Internal error",
		})
	}

	if verificationToken == nil || verificationToken.Type != "password_reset" {
		return c.Render(http.StatusBadRequest, "reset-password", ResetPasswordPage{
			Error: "Invalid or expired reset link",
		})
	}

	if verificationToken.Expires < time.Now().Unix() {
		err := controller.Store.DeleteVerificationToken(token)
		if err != nil {
			return c.Render(http.StatusInternalServerError, "reset-password", ResetPasswordPage{
				Error: "Internal error",
			})
		}
		return c.Render(http.StatusBadRequest, "reset-password", ResetPasswordPage{
			Error: "Reset link has expired",
		})
	}

	// Hash new password
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		return c.Render(http.StatusInternalServerError, "reset-password", ResetPasswordPage{
			Error: "Internal error",
		})
	}

	// Update password
	err = controller.Store.UpdateUserPassword(verificationToken.Email, hashedPassword)
	if err != nil {
		return c.Render(http.StatusInternalServerError, "reset-password", ResetPasswordPage{
			Error: "Internal error",
		})
	}

	// Delete used token
	err = controller.Store.DeleteVerificationToken(token)
	if err != nil {
		return c.Render(http.StatusInternalServerError, "reset-password", ResetPasswordPage{
			Error: "Internal error",
		})
	}

	return c.Render(http.StatusOK, "reset-password", ResetPasswordPage{
		Success: "Password has been reset successfully. You can now log in with your new password.",
	})
}

func (controller *Controller) showDeleteAccountPage(c echo.Context) error {
	logger.Info("showDeleteAccountPage handler called")
	return c.Render(http.StatusOK, "delete-account", DeleteAccountPage{})
}

func (controller *Controller) deleteAccount(c echo.Context) error {
	logger.Info("deleteAccount handler called")
	email := c.FormValue("email")
	if email == "" {
		return c.Render(http.StatusBadRequest, "delete-account", DeleteAccountPage{
			Error: "Email is required",
		})
	}

	// Check if user exists and is verified
	user, err := controller.Store.FindUser(email)
	if err != nil {
		return c.Render(http.StatusInternalServerError, "delete-account", DeleteAccountPage{
			Error: "Internal error",
		})
	}

	if user == nil || !user.Verified {
		// Don't reveal if the email exists or not for security
		return c.Render(http.StatusOK, "delete-account", DeleteAccountPage{
			Success: "If your account exists and is verified, you will receive an email with instructions to delete it.",
		})
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
		return c.Render(http.StatusInternalServerError, "delete-account", DeleteAccountPage{
			Error: "Internal error",
		})
	}

	// Send delete verification email
	deleteLink := fmt.Sprintf("%s/verify-delete?token=%s", controller.Config.BaseUrl, token)
	err = controller.EmailService.SendDeleteAccountEmail(email, deleteLink)
	if err != nil {
		logger.Error("Failed to send delete account email", "error", err)
	}

	return c.Render(http.StatusOK, "delete-account", DeleteAccountPage{
		Success: "If your account exists and is verified, you will receive an email with instructions to delete it.",
	})
}

type VerifyDeletePage struct {
	Code    string
	Error   string
	Success string
}

func (controller *Controller) showVerifyDeletePage(c echo.Context) error {
	logger.Info("showVerifyDeletePage handler called")
	token := c.QueryParam("token")
	return c.Render(http.StatusOK, "verify-delete", VerifyDeletePage{
		Code:  token,
		Error: "Invalid or missing verification code",
	})
}

func (controller *Controller) verifyDelete(c echo.Context) error {
	logger.Info("verifyDelete handler called")
	token := c.FormValue("code")
	if token == "" {
		return c.Render(http.StatusBadRequest, "verify-delete", VerifyDeletePage{
			Error: "Invalid or missing verification code",
		})
	}

	// Find and validate token
	verificationToken, err := controller.Store.FindVerificationToken(token)
	if err != nil {
		return c.Render(http.StatusInternalServerError, "verify-delete", VerifyDeletePage{
			Error: "Internal error",
		})
	}

	if verificationToken == nil {
		return c.Render(http.StatusBadRequest, "verify-delete", VerifyDeletePage{
			Error: "Invalid or expired verification code",
		})
	}

	if verificationToken.Type != "delete_account" {
		return c.Render(http.StatusBadRequest, "verify-delete", VerifyDeletePage{
			Error: "Invalid verification code type",
		})
	}

	if verificationToken.Expires < time.Now().Unix() {
		err := controller.Store.DeleteVerificationToken(token)
		if err != nil {
			return c.Render(http.StatusInternalServerError, "verify-delete", VerifyDeletePage{
				Error: "Internal error",
			})
		}
		return c.Render(http.StatusBadRequest, "verify-delete", VerifyDeletePage{
			Error: "Verification code has expired",
		})
	}

	// Delete the user
	err = controller.Store.DeleteUser(verificationToken.Email)
	if err != nil {
		return c.Render(http.StatusInternalServerError, "verify-delete", VerifyDeletePage{
			Error: "Internal error",
		})
	}

	// Delete the used token
	err = controller.Store.DeleteVerificationToken(token)
	if err != nil {
		logger.Error("Failed to delete verification token", "error", err)
	}

	return c.Render(http.StatusOK, "verify-delete", VerifyDeletePage{
		Success: "Your account has been successfully deleted.",
	})
}

func (controller *Controller) resendDeleteVerification(c echo.Context) error {
	logger.Info("resendDeleteVerification handler called")
	email := c.QueryParam("email")
	if email == "" {
		return c.Redirect(http.StatusFound, "/delete-account")
	}

	// Check if user exists and is verified
	user, err := controller.Store.FindUser(email)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	if user == nil || !user.Verified {
		// Don't reveal if the email exists or not for security
		return c.Redirect(http.StatusFound, "/delete-account")
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
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	// Send delete verification email
	deleteLink := fmt.Sprintf("%s/verify-delete?token=%s", controller.Config.BaseUrl, token)
	err = controller.EmailService.SendDeleteAccountEmail(email, deleteLink)
	if err != nil {
		logger.Error("Failed to send delete account email", "error", err)
	}

	return c.Redirect(http.StatusFound, "/verify-delete?token="+token)
}

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
		logger.Error("Failed to create verification token", "error", err)
		return err
	}

	// Send verification email
	verificationLink := fmt.Sprintf("%s/verify?code=%s", controller.Config.BaseUrl, token)
	err = controller.EmailService.SendVerificationEmail(email, verificationLink)
	if err != nil {
		logger.Error("Failed to send verification email", "error", err)
		return err
	}

	return nil
}
