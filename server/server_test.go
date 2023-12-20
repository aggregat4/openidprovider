package server_test

import (
	"aggregat4/openidprovider/domain"
	"aggregat4/openidprovider/schema"
	"aggregat4/openidprovider/server"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"testing"
	"time"

	"aggregat4/openidprovider/crypto"

	"github.com/labstack/echo/v4"
	_ "github.com/mattn/go-sqlite3"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

const TEST_CLIENTID = "testclientid"
const TEST_USERNAME = "testusername"
const TEST_PASSWORD = "testpassword"
const TEST_STATE = "teststate"
const TEST_SECRET = "testsecret"
const TEST_REDIRECT_URI = "http://localhost:8080"

var serverConfig = domain.Configuration{
	ServerReadTimeoutSeconds:  5,
	ServerWriteTimeoutSeconds: 10,
	ServerPort:                1323,
	RegisteredClients: map[domain.ClientId]domain.Client{
		TEST_CLIENTID: {
			Id:           TEST_CLIENTID,
			RedirectUris: []string{TEST_REDIRECT_URI},
			Secret:       TEST_SECRET,
		},
	},
	JwtConfig: domain.JwtConfiguration{
		Issuer:                 "test",
		IdTokenValidityMinutes: 5,
	},
}

func TestAuthorizeWithoutParameters(t *testing.T) {
	echoServer, controller := waitForServer()
	defer echoServer.Close()
	defer controller.Store.Close()
	res, err := http.Get("http://localhost:1323/authorize")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 400, res.StatusCode)
}

func TestAuthorize(t *testing.T) {
	echoServer, controller := waitForServer()
	defer echoServer.Close()
	defer controller.Store.Close()
	res, err := http.Get("http://localhost:1323/authorize?scope=openid&client_id=test&response_type=code&redirect_uri=http://localhost:8080&state=foobar")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "text/html; charset=UTF-8", res.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
	// check whether our state shows up in the response
	assert.Assert(t, is.Contains(readBody(res), fmt.Sprintf("value=\"%s\"", TEST_STATE)))
}

func TestLoginPageGet(t *testing.T) {
	echoServer, controller := waitForServer()
	defer echoServer.Close()
	defer controller.Store.Close()
	res, err := http.Get("http://localhost:1323/login")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 405, res.StatusCode)
}

func TestLoginWithoutCsrf(t *testing.T) {
	echoServer, controller := waitForServer()
	defer echoServer.Close()
	defer controller.Store.Close()
	data := url.Values{}
	res, err := http.PostForm("http://localhost:1323/login", data)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 400, res.StatusCode)
	assert.Assert(t, is.Contains(readBody(res), "missing csrf token"))
}

func TestRealLogin(t *testing.T) {
	echoServer, controller := waitForServer()
	defer echoServer.Close()
	defer controller.Store.Close()
	hashedPassword, error := crypto.HashPassword(TEST_PASSWORD)
	if error != nil {
		t.Fatal(error)
	}
	controller.Store.CreateUser(TEST_USERNAME, hashedPassword)
	// we need to authorize first so we get a login page with a csrf token
	res, err := http.Get("http://localhost:1323/authorize?scope=openid&client_id=" + TEST_CLIENTID + "&response_type=code&redirect_uri=" + TEST_REDIRECT_URI + "&state=" + TEST_STATE)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 200, res.StatusCode)
	// extract csrf token from response
	body := readBody(res)
	re := regexp.MustCompile(`name="csrf_token" value="(\w+)"`)
	matches := re.FindStringSubmatch(body)
	if len(matches) < 2 {
		t.Fatal("No CSRF token found in body")
	}
	csrfToken := matches[1]
	// perform the login
	data := url.Values{}
	data.Set("clientid", TEST_CLIENTID)
	data.Set("username", TEST_USERNAME)
	data.Set("password", TEST_PASSWORD)
	data.Set("redirecturi", TEST_REDIRECT_URI)
	data.Set("state", TEST_STATE)
	data.Set("csrf_token", csrfToken)
	res, err = http.PostForm("http://localhost:1323/login", data)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Assert(t, is.Contains(locationHeader, TEST_REDIRECT_URI))
	assert.Assert(t, is.Contains(locationHeader, "code="))
	assert.Assert(t, is.Contains(locationHeader, "state="+TEST_STATE))
}

func waitForServer() (*echo.Echo, server.Controller) {
	var store schema.Store
	err := store.InitAndVerifyDb(schema.CreateInMemoryDbUrl())
	if err != nil {
		panic(err)
	}
	controller := server.Controller{&store, serverConfig}
	echoServer := server.InitServer(controller)
	go func() {
		echoServer.Start(":" + strconv.Itoa(serverConfig.ServerPort))
	}()
	time.Sleep(1 * time.Second) // massive hack since there appears to be no way to know when the server is ready
	return echoServer, controller
}

func readBody(res *http.Response) string {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	return string(body)
}
