package server

import (
	"aggregat4/openidprovider/crypto"
	"aggregat4/openidprovider/domain"
	"aggregat4/openidprovider/schema"
	"database/sql"
	"embed"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

//go:embed public/views/*.html
var viewTemplates embed.FS

func RunServer(dbName string, config domain.Configuration) {
	db, err := schema.InitAndVerifyDb(dbName)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	e := echo.New()
	// Set server timeouts based on advice from https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/#1687428081
	e.Server.ReadTimeout = time.Duration(config.ServerReadTimeoutSeconds) * time.Second
	e.Server.WriteTimeout = time.Duration(config.ServerWriteTimeoutSeconds) * time.Second

	t := &Template{
		templates: template.Must(template.New("").ParseFS(viewTemplates, "public/views/*.html")),
	}
	e.Renderer = t

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
	}))
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup: "form:csrf_token",
	}))

	// We don't need to allow showing the login page directly, it will only be used as a response to an
	// authorization request
	// e.GET("/login", func(c echo.Context) error { return showLogin(c) })
	e.POST("/login", func(c echo.Context) error { return login(config.RegisteredClients, db, c) })

	e.GET("/authorize", func(c echo.Context) error { return authorize(config.RegisteredClients, c) })
	e.POST("/authorize", func(c echo.Context) error { return authorize(config.RegisteredClients, c) })

	e.Logger.Fatal(e.Start(":" + strconv.Itoa(config.ServerPort)))
	// NO MORE CODE HERE, IT WILL NOT BE EXECUTED
}

func authorize(clientRegistry map[domain.ClientId][]domain.ClientRedirectUri, c echo.Context) error {
	authenticationRequest := domain.OidcAuthenticationRequest{
		Scopes:       strings.Split(getParam(c, "scope"), " "),
		ResponseType: getParam(c, "response_type"),
		ClientId:     getParam(c, "client_id"),
		RedirectUri:  getParam(c, "redirect_uri"),
		State:        getParam(c, "state"),
	}
	// Do basic validation whether required parameters are present first and respond with bad request if not
	if len(authenticationRequest.Scopes) == 0 ||
		!contains(authenticationRequest.Scopes, "openid") ||
		authenticationRequest.ResponseType == "" ||
		authenticationRequest.ResponseType != "code" ||
		authenticationRequest.ClientId == "" ||
		authenticationRequest.RedirectUri == "" {
		return c.String(http.StatusBadRequest, "Missing required parameters")
	}
	// Validate the client and redirect URI as per https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1 and respond if an error
	// Validate that the client exists
	redirectUris, clientExists := clientRegistry[authenticationRequest.ClientId]
	if !clientExists {
		return c.String(http.StatusBadRequest, "Client does not exist")
	}
	// Validate that the redirect URI is registered for the client
	if !contains(redirectUris, authenticationRequest.RedirectUri) {
		return c.String(http.StatusBadRequest, "Redirect URI is not registered for client")
	}
	// all is well, show login page
	return c.Render(http.StatusOK, "login", LoginPage{
		CsrfToken:   c.Get("csrf").(string),
		ClientId:    authenticationRequest.ClientId,
		RedirectUri: authenticationRequest.RedirectUri,
		State:       authenticationRequest.State})
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
func login(clientRegistry map[domain.ClientId][]domain.ClientRedirectUri, db *sql.DB, c echo.Context) error {
	clientId := c.FormValue("clientid")
	redirectUri := c.FormValue("redirecturi")
	fullRedirectUri, err := url.Parse(redirectUri)
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid redirect URI")
	}
	state := c.FormValue("state")
	redirectUris, clientExists := clientRegistry[clientId]
	if !clientExists {
		return c.String(http.StatusBadRequest, "Client does not exist")
	}
	// Validate that the redirect URI is registered for the client
	if !contains(redirectUris, redirectUri) {
		return c.String(http.StatusBadRequest, "Redirect URI is not registered for client")
	}
	username := c.FormValue("username")
	password := c.FormValue("password")

	rows, err := db.Query("SELECT id, password FROM users WHERE username = ?", username)
	if err != nil {
		return sendInternalError(c, fullRedirectUri, state)
	}
	defer rows.Close()

	if rows.Next() {
		var passwordHash string
		var userid int
		err = rows.Scan(&userid, &passwordHash)

		if err != nil {
			return sendInternalError(c, fullRedirectUri, state)
		}

		if crypto.CheckPasswordHash(password, passwordHash) {
			// See OIDC spec https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
			code, err := generateCode(db, clientId, redirectUri, username)
			if err != nil {
				// generateCode should never fail
				return sendInternalError(c, fullRedirectUri, state)
			}
			query := fullRedirectUri.Query()
			query.Add("code", code)
			query.Add("state", state)
			fullRedirectUri.RawQuery = query.Encode()
			return c.Redirect(http.StatusFound, fullRedirectUri.String())
		}
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

// See OIDC spec https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
// See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2 for the oauth 2 spec on Authorization responses
// See also https://www.oauth.com/oauth2-servers/authorization/the-authorization-response/ for implementation hints
func generateCode(db *sql.DB, clientId, redirectUri, username string) (string, error) {
	uuid := uuid.New().String()
	// insert this new code in the database
	_, err := db.Exec("INSERT INTO codes (code, username, client_id, redirect_uri, created) VALUES (?, ?, ?, ?, ?)", uuid, username, clientId, redirectUri, time.Now().Unix())
	if err != nil {
		return "", err
	}
	return uuid, nil
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
