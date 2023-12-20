package server_test

import (
	"aggregat4/openidprovider/domain"
	"aggregat4/openidprovider/schema"
	"aggregat4/openidprovider/server"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/labstack/echo"
	_ "github.com/mattn/go-sqlite3"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

var serverConfig = domain.Configuration{
	ServerReadTimeoutSeconds:  5,
	ServerWriteTimeoutSeconds: 10,
	ServerPort:                1323,
	RegisteredClients: map[domain.ClientId]domain.Client{
		"test": {
			Id:           "test",
			RedirectUris: []string{"http://localhost:8080"},
			Secret:       "foobar",
		},
	},
	JwtConfig: domain.JwtConfiguration{
		Issuer:                 "test",
		IdTokenValidityMinutes: 5,
	},
}

func TestAuthorizeWithoutParameters(t *testing.T) {
	echoServer, controller := waitForServer()
	defer controller.Store.Close()
	res, err := http.Get("http://localhost:1323/authorize")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 400, res.StatusCode)
	echoServer.Close()
}

// TODO: continue here: try to implement an echo like test as on https://echo.labstack.com/docs/testing

func TestAuthorize(t *testing.T) {
	echoServer, controller := waitForServer()
	defer controller.Store.Close()
	res, err := http.Get("http://localhost:1323/authorize?scope=openid&client_id=test&response_type=code&redirect_uri=http://localhost:8080&state=foobar")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "text/html; charset=UTF-8", res.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
	// check whether our state shows up in the response
	assert.Assert(t, is.Contains(readBody(res), "value=\"foobar\""))
	echoServer.Close()
}

func TestLoginWithoutParameters(t *testing.T) {
	echoServer, controller := waitForServer()
	defer controller.Store.Close()
	res, err := http.Get("http://localhost:1323/login")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 405, res.StatusCode)
	echoServer.Close()
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
