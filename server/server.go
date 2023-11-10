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
	"strconv"
	"strings"
	"time"

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
	e.POST("/login", func(c echo.Context) error { return login(db, c) })

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
	// TODO: how do we transmit the client id and redirect URI to the login page? and back to us?
	// TODO: remember to also transmit state for CSRF protection
	return c.Render(http.StatusOK, "login", LoginPage{CsrfToken: c.Get("csrf").(string)})
}

func getParam(c echo.Context, paramName string) string {
	param := c.QueryParam(paramName)
	if param == "" {
		param = c.FormValue(paramName)
	}
	return param
}

type LoginPage struct {
	CsrfToken string
}

func showLogin(c echo.Context) error {
	return c.Render(http.StatusOK, "login", LoginPage{CsrfToken: c.Get("csrf").(string)})
}

func login(db *sql.DB, c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	rows, err := db.Query("SELECT id, password FROM users WHERE username = ?", username)
	if err != nil {
		return err
	}
	defer rows.Close()

	if rows.Next() {
		var passwordHash string
		var userid int
		err = rows.Scan(&userid, &passwordHash)

		if err != nil {
			return err
		}

		if crypto.CheckPasswordHash(password, passwordHash) {
			// we have successfully checked the password, create a session cookie and redirect to the bookmarks page
			// sess, _ := session.Get("delicious-bookmarks-session", c)
			// sess.Values["userid"] = userid
			// sess.Save(c.Request(), c.Response())

			// TODO: redirect to client
			return c.Redirect(http.StatusFound, "/bookmarks")
		}
	}

	// TODO: redirect to client with error?
	return c.Redirect(http.StatusFound, "/login")
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
