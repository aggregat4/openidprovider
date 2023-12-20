package server

import (
	"aggregat4/openidprovider/crypto"
	"aggregat4/openidprovider/domain"
	"aggregat4/openidprovider/schema"
	"crypto/subtle"
	"embed"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// var logger = log.Default()

//go:embed public/views/*.html
var viewTemplates embed.FS

type Controller struct {
	Store  *schema.Store
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
	// Added session middleware just so we can have persistence for CSRF tokens
	e.Use(session.Middleware(sessions.NewCookieStore([]byte(uuid.New().String()))))
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{Level: 5}))
	// TODO: write test to verify whether we need to restrict the CSRF chek to POST on the login page?
	// Otherwise the alternative POST on authorize/ will not work
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{TokenLookup: "form:csrf_token"}))
	e.Use(middleware.BasicAuthWithConfig(middleware.BasicAuthConfig{
		// we only require basic auth for the token endpoint
		Skipper: func(c echo.Context) bool {
			return c.Path() != "/token"
		},
		Validator: controller.basicAuthValidator,
	}))

	e.GET("/authorize", controller.authorize)
	e.POST("/authorize", controller.authorize)
	// We don't need to allow showing the login page directly, it will only be used as a response to an
	// authorization request, so no GET on /login
	e.POST("/login", controller.login)
	e.POST("/token", controller.token)
	return e
}

func (controller *Controller) basicAuthValidator(username, password string, c echo.Context) (bool, error) {
	client, clientExists := controller.Config.RegisteredClients[username]
	if !clientExists {
		// make sure we nevertheless compare the username and password to make timing attacks harder
		subtle.ConstantTimeCompare([]byte(username), []byte("this is not a valid client id"))
		subtle.ConstantTimeCompare([]byte(password), []byte("this is not a valid client secret"))
		return false, nil
	}
	c.Set("client_id", client.Id)
	return (subtle.ConstantTimeCompare([]byte(username), []byte(client.Id)) == 1 &&
		subtle.ConstantTimeCompare([]byte(password), []byte(client.Secret)) == 1), nil
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
		sendOauthAccessTokenError(c, "unsupported_grant_type")
	}
	code := c.FormValue("code")

	// validate that the code exists
	existingCode, err := controller.Store.FindCode(code)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	if existingCode == nil {
		sendOauthAccessTokenError(c, "invalid_grant")
	}

	// Code was used once, delete it
	err = controller.Store.DeleteCode(code)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	// Validate that the code is for the correct client and redirect URI
	if existingCode.ClientId != clientId || existingCode.RedirectUri != redirectUri {
		sendOauthAccessTokenError(c, "invalid_grant")
	}

	// Finally, generate the access token
	accessToken := uuid.New().String()
	// TODO: figure out what I need to store for access tokens so I can fulfill the requirements for the UserInfo Endpoint
	// _, err = db.Exec("INSERT INTO access_tokens (access_token, username, client_id, created) VALUES (?, ?, ?, ?)", accessToken, codeUsername, clientId, time.Now().Unix())
	// if err != nil {
	// 	return c.String(http.StatusInternalServerError, "Internal error")
	// }

	// Respond with the access token
	c.Response().Header().Set("Content-Type", "application/json;charset=UTF-8")
	idToken, err := generateIdToken(controller.Config.JwtConfig, clientId, client.Secret, existingCode.UserId)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	// TODO: figure out if I want to set the expires_in parameter
	return c.String(http.StatusOK, "{\"access_token\":\""+accessToken+"\", \"token_type\":\"Bearer\", \"id_token\":\""+idToken+"\"")
}

// See https://openid.net/specs/openid-connect-basic-1_0.html#IDToken
func generateIdToken(jwtConfig domain.JwtConfiguration, clientId string, clientSecret string, userId string) (string, error) {
	key := ([]byte(clientSecret))
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": jwtConfig.Issuer,
		"sub": userId,
		"aud": clientId,
		"exp": time.Now().Add(time.Minute * time.Duration(jwtConfig.IdTokenValidityMinutes)).Unix(),
		"iat": time.Now().Unix(),
	})
	return t.SignedString(key)
}

func sendOauthAccessTokenError(c echo.Context, s string) error {
	c.Response().Header().Set("Content-Type", "application/json;charset=UTF-8")
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
	if len(authReqScopes) == 0 ||
		!contains(authReqScopes, "openid") ||
		authReqResponseType == "" ||
		authReqResponseType != "code" ||
		authReqClientId == "" ||
		authReqRedirectUri == "" {
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
// But since this treat a potential malicious client as a real client, this seems unwise? Or is it better
// to return an OAuth error so the implementor of a buggy client can see what's wrong?
func (controller *Controller) login(c echo.Context) error {
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

	// find the user and validate password
	user, err := controller.Store.FindUser(username)
	if err != nil {
		return sendInternalError(c, fullRedirectUri, state)
	}
	if crypto.CheckPasswordHash(password, user.Password) {
		// See OIDC spec https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse

		// Generate a code
		// See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2 for the oauth 2 spec on Authorization responses
		// See also https://www.oauth.com/oauth2-servers/authorization/the-authorization-response/ for implementation hints
		uuid := uuid.New().String()
		err := controller.Store.SaveCode(schema.Code{Code: uuid, UserId: user.UserId, ClientId: clientId, RedirectUri: redirectUri, Created: time.Now().Unix()})
		if err != nil {
			return sendInternalError(c, fullRedirectUri, state)
		}

		query := fullRedirectUri.Query()
		query.Add("code", uuid)
		query.Add("state", state)
		fullRedirectUri.RawQuery = query.Encode()
		return c.Redirect(http.StatusFound, fullRedirectUri.String())
	}

	// See https://openid.net/specs/openid-connect-core-1_0.html#AuthError
	return sendOauthError(c, fullRedirectUri, "access_denied", "Invalid username or password", state)
}

func sendInternalError(c echo.Context, fullRedirectUri *url.URL, state string) error {
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

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
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
