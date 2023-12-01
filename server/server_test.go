package server_test

import (
	"aggregat4/openidprovider/domain"
	"aggregat4/openidprovider/server"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/labstack/echo"
	_ "github.com/mattn/go-sqlite3"
	"gotest.tools/assert"
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
	echoServer := waitForServer()
	res := httpCallMustSucceed(t, http.Get("http://localhost:1323/authorize"))
	assert.Equal(t, 400, res.StatusCode)
	// t.Log(res.StatusCode)
	// t.Log(readBody(res))
	echoServer.Close()
}

func httpCallMustSucceed(t *testing.T, (*res http.Response, err error)) {
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func waitForServer() *echo.Echo {
	echoServer := server.InitServer("test", serverConfig)
	go func() {
		echoServer.Start(":" + strconv.Itoa(serverConfig.ServerPort))
	}()
	time.Sleep(1 * time.Second) // massive hack since there appears to be no way to know when the server is ready
	return echoServer
}

func readBody(res *http.Response) string {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	return string(body)
}
