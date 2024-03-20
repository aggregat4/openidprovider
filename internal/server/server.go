package server

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/repository"
	"aggregat4/openidprovider/pkg/crypto"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var logger = slog.New(slog.NewTextHandler(os.Stdout, nil))

//go:embed public/views/*.html
var viewTemplates embed.FS

const ContentTypeJson = "application/json;charset=UTF-8"

type Controller struct {
	Store  *repository.Store
	Config domain.Configuration
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

	t := &Template{
		templates: template.Must(template.New("").ParseFS(viewTemplates, "public/views/*.html")),
	}
	e.Renderer = t

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	// Debug logging
	//e.Use(middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
	//	logger.Info("Request: %s %s", "requestmethod", c.Request().Method, "requesturl", c.Request().URL)
	//	logger.Info("Response: %s", "responsebody", string(resBody))
	//}))
	// Added session middleware just so we can have persistence for CSRF tokens
	e.Use(session.Middleware(sessions.NewCookieStore([]byte(uuid.New().String()))))
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{Level: 5}))
	// TODO: write test to verify whether we need to restrict the CSRF check to POST on the login page?
	// Otherwise the alternative POST on authorize/ will not work
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup: "form:csrf_token",
		Skipper: func(c echo.Context) bool {
			return c.Path() != "/login" && c.Path() != "/authorize"
		},
	}))
	e.Use(middleware.BasicAuthWithConfig(middleware.BasicAuthConfig{
		// we only require basic auth for the token endpoint
		Skipper: func(c echo.Context) bool {
			return c.Path() != "/token"
		},
		Validator: controller.basicAuthValidator,
	}))

	e.GET("/.well-known/openid-configuration", controller.openIdConfiguration)
	e.GET("/.well-known/jwks.json", controller.jwks)

	e.GET("/authorize", controller.authorize)
	e.POST("/authorize", controller.authorize)
	// We don't need to allow showing the login page directly, it will only be used as a response to an
	// authorization request, so no GET on /login
	e.POST("/login", controller.login)
	e.POST("/token", controller.token)
	return e
}

// This endpoint returns a JWKS document containing the public key
// that can be used by clients to verify the signature of the ID token
// as we are using the RS256 algorithm with public and private keys
func (controller *Controller) jwks(c echo.Context) error {
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
	c.Response().Header().Set("Content-Type", ContentTypeJson)
	return c.JSON(http.StatusOK, domain.OpenIdConfiguration{
		Issuer:                controller.Config.BaseUrl,
		AuthorizationEndpoint: controller.Config.BaseUrl + "/authorize",
		TokenEndpoint:         controller.Config.BaseUrl + "/token",
		// UserInfoEndpoint: controller.Config.BaseUrl + "/userinfo",
		JwksUri:                          controller.Config.BaseUrl + "/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"code", "id_token"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
	})
}

// basicAuthValidator validates a client ID and client secret provided via
// HTTP Basic Auth. It sets the client ID on the context if valid.
// It use subtle.ConstantTimeCompare to prevent timing attacks.
func (controller *Controller) basicAuthValidator(username, password string, c echo.Context) (bool, error) {
	client, clientExists := controller.Config.RegisteredClients[username]
	if !clientExists {
		// make sure we nevertheless compare the username and password to make timing attacks harder
		subtle.ConstantTimeCompare([]byte(username), []byte("this is not a valid client id"))
		subtle.ConstantTimeCompare([]byte(password), []byte("this is not a valid client secret"))
		return false, nil
	}
	c.Set("client_id", client.Id)
	return subtle.ConstantTimeCompare([]byte(username), []byte(client.Id)) == 1 &&
		subtle.ConstantTimeCompare([]byte(password), []byte(client.BasicAuthSecret)) == 1, nil
}

// OIDC Token Endpoint is described in:
// https://openid.net/specs/openid-connect-basic-1_0.html#ObtainingTokens
// Reference to the OAuth 2 spec:
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
// Error handling as per https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
func (controller *Controller) token(c echo.Context) error {
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

	// Finally, generate the access token
	accessToken := uuid.New().String()
	// TODO: figure out what I need to store for access tokens so I can fulfill the requirements for the UserInfo Endpoint
	// _, err = db.Exec("INSERT INTO access_tokens (access_token, username, client_id, created) VALUES (?, ?, ?, ?)", accessToken, codeUsername, clientId, time.Now().Unix())
	// if err != nil {
	// 	return c.String(http.StatusInternalServerError, "Internal error")
	// }

	// Respond with the access token
	c.Response().Header().Set("Content-Type", ContentTypeJson)
	c.Response().Header().Set("Cache-Control", "no-store")
	idToken, err := GenerateIdToken(controller.Config.JwtConfig, clientId, existingCode.UserName)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	// TODO: figure out if I want to set the expires_in parameter
	return c.String(http.StatusOK,
		"{\"access_token\":\""+accessToken+"\", \"token_type\":\"Bearer\", \"id_token\":\""+idToken+"\"}")
}

// GenerateIdToken See https://openid.net/specs/openid-connect-basic-1_0.html#IDToken
func GenerateIdToken(jwtConfig domain.JwtConfiguration, clientId string, userName string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": jwtConfig.Issuer,
		"sub": userName,
		"aud": clientId,
		"exp": time.Now().Add(time.Minute * time.Duration(jwtConfig.IdTokenValidityMinutes)).Unix(),
		"iat": time.Now().Unix(),
	})
	return t.SignedString(jwtConfig.PrivateKey)
}

func sendOauthAccessTokenError(c echo.Context, s string) error {
	c.Response().Header().Set("Content-Type", ContentTypeJson)
	return c.String(http.StatusBadRequest, "{\"error\":\""+s+"\"}")
}

// No support for "nonce", "display", "prompt", "max_age", "ui_locales", "id_token_hint", "login_hint", "acr_values" yet
func (controller *Controller) authorize(c echo.Context) error {
	authReqScopes := strings.Split(getParam(c, "scope"), " ")
	authReqResponseType := getParam(c, "response_type")
	authReqClientId := getParam(c, "client_id")
	authReqRedirectUri := getParam(c, "redirect_uri")
	authReqState := getParam(c, "state")
	// Do basic validation whether required parameters are present first and respond with bad request if not
	if len(authReqScopes) == 0 || !contains(authReqScopes, "openid") || authReqResponseType != "code" || authReqClientId == "" || authReqRedirectUri == "" {
		return c.String(http.StatusBadRequest, "Missing required parameters")
	}
	// Validate the client and redirect URI as per https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1 and respond if an error
	// Validate that the client exists
	client, clientExists := controller.Config.RegisteredClients[authReqClientId]
	if !clientExists {
		return c.String(http.StatusBadRequest, "Client does not exist")
	}
	// Validate that the redirect URI is registered for the client
	if !contains(client.RedirectUris, authReqRedirectUri) {
		return c.String(http.StatusBadRequest, "Redirect URI is not registered for client")
	}
	// All is well, show login page
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.Render(http.StatusOK, "login", LoginPage{
		CsrfToken:   c.Get("csrf").(string),
		ClientId:    authReqClientId,
		RedirectUri: authReqRedirectUri,
		State:       authReqState})
}

func getParam(c echo.Context, paramName string) string {
	param := c.QueryParam(paramName)
	if param == "" {
		param = c.FormValue(paramName)
	}
	return param
}

type LoginPage struct {
	CsrfToken   string
	ClientId    string
	RedirectUri string
	State       string
}

// Login will return normal BAD REQUEST HTTP status codes for all errors pertaining to client id and redirecturi
// validation.
// This is unclear in the spec as https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1 could be
// interpreted as returning a 302 redirect with an error code in the query string for all these errors
// But since this treats a potential malicious client as a real client, this seems unwise? Or is it better
// to return an OAuth error so the implementor of a buggy client can see what's wrong?
func (controller *Controller) login(c echo.Context) error {
	logger.Info("login request received")
	clientId := c.FormValue("clientid")
	redirectUri := c.FormValue("redirecturi")
	fullRedirectUri, err := url.Parse(redirectUri)
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid redirect URI")
	}
	state := c.FormValue("state")
	client, clientExists := controller.Config.RegisteredClients[clientId]
	if !clientExists {
		return c.String(http.StatusBadRequest, "Client does not exist")
	}
	// Validate that the redirect URI is registered for the client
	if !contains(client.RedirectUris, redirectUri) {
		return c.String(http.StatusBadRequest, "Redirect URI is not registered for client")
	}
	username := c.FormValue("username")
	password := c.FormValue("password")

	logger.Info("login request validated")

	// find the user and validate password
	user, err := controller.Store.FindUser(username)
	if err != nil {
		return sendInternalError(c, err, fullRedirectUri, state)
	}
	if user == nil {
		logger.Debug("User not found with username %s", username)
		// See https://openid.net/specs/openid-connect-core-1_0.html#AuthError
		return sendOauthError(c, fullRedirectUri, "access_denied", "Invalid username or password", state)
	}
	logger.Info("login request user found")
	if crypto.CheckPasswordHash(password, user.Password) {
		// See OIDC spec https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse

		// Generate a code
		// See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2 for the oauth 2 spec on Authorization responses
		// See also https://www.oauth.com/oauth2-servers/authorization/the-authorization-response/ for implementation hints
		code := uuid.New().String()
		err := controller.Store.SaveCode(repository.Code{Code: code, UserName: user.Username, ClientId: clientId, RedirectUri: redirectUri, Created: time.Now().Unix()})
		if err != nil {
			return sendInternalError(c, err, fullRedirectUri, state)
		}

		query := fullRedirectUri.Query()
		query.Add("code", code)
		query.Add("state", state)
		fullRedirectUri.RawQuery = query.Encode()
		logger.Info("login request password ok. redirecting")
		return c.Redirect(http.StatusFound, fullRedirectUri.String())
	}
	logger.Info("login request password not ok")

	// See https://openid.net/specs/openid-connect-core-1_0.html#AuthError
	return sendOauthError(c, fullRedirectUri, "access_denied", "Invalid username or password", state)
}

func sendInternalError(c echo.Context, originalError error, fullRedirectUri *url.URL, state string) error {
	logger.Error("Error processing request: ", originalError)
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
	return t.templates.ExecuteTemplate(w, name, data)
}

func contains(list []string, item string) bool {
	for _, i := range list {
		if i == item {
			return true
		}
	}
	return false
}
