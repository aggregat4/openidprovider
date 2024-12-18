package server_test

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/repository"
	"aggregat4/openidprovider/internal/server"
	"crypto/rand"
	"crypto/rsa"
	"github.com/aggregat4/go-baselib/crypto"

	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	_ "github.com/mattn/go-sqlite3"

	"github.com/stretchr/testify/assert"
)

const TestClientid = "testclientid"
const TestUsername = "testusername"
const TestPassword = "testpassword"
const TestState = "teststate"
const TestSecret = "testsecret"
const TestRedirectUri = "http://localhost:8080"
const AuthorizeUrl = "http://localhost:1323/authorize"
const LoginUrl = "http://localhost:1323/login"
const TestJwtissuer = "testissuer"

var serverConfig = domain.Configuration{
	ServerReadTimeoutSeconds:  50,
	ServerWriteTimeoutSeconds: 100,
	ServerPort:                1323,
	BaseUrl:                   "http://localhost:1323",
	RegisteredClients: map[domain.ClientId]domain.Client{
		TestClientid: {
			Id:              TestClientid,
			RedirectUris:    []string{TestRedirectUri},
			BasicAuthSecret: TestSecret,
		},
	},
	JwtConfig: domain.JwtConfiguration{
		Issuer:                 TestJwtissuer,
		IdTokenValidityMinutes: 5,
		PrivateKey:             nil,
		PublicKey:              nil,
	},
}

func TestAuthorizeWithoutParameters(t *testing.T) {
	echoServer, controller := waitForServer(t)
	defer echoServer.Close()
	defer controller.Store.Close()
	res, err := http.Get(AuthorizeUrl)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 400, res.StatusCode)
}

func TestAuthorize(t *testing.T) {
	echoServer, controller := waitForServer(t)
	defer echoServer.Close()
	defer controller.Store.Close()
	res, err := http.Get(AuthorizeUrl + "?scope=openid&client_id=" + TestClientid + "&response_type=code&redirect_uri=" + TestRedirectUri + "&state=" + TestState)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "text/html; charset=UTF-8", res.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
	// check whether our state shows up in the response
	assert.Contains(t, readBody(res), fmt.Sprintf("value=\"%s\"", TestState))
}

func TestLoginPageGet(t *testing.T) {
	echoServer, controller := waitForServer(t)
	defer echoServer.Close()
	defer controller.Store.Close()
	res, err := http.Get(LoginUrl)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 405, res.StatusCode)
}

func TestLoginWithoutCsrf(t *testing.T) {
	echoServer, controller := waitForServer(t)
	defer echoServer.Close()
	defer controller.Store.Close()
	data := url.Values{}
	res, err := http.PostForm(LoginUrl, data)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 400, res.StatusCode)
	assert.Contains(t, readBody(res), "missing csrf token")
}

func performAuthorizeAndLogin(t *testing.T, client *http.Client, password string) *http.Response {
	// We need to authorize first so we get a login page with a csrf token
	req, _ := http.NewRequest("GET", AuthorizeUrl+"?scope=openid&client_id="+TestClientid+"&response_type=code&redirect_uri="+TestRedirectUri+"&state="+TestState, nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 200, res.StatusCode)
	csrfToken := extractCsrfToken(readBody(res))
	if csrfToken == "" {
		t.Fatal("csrf token not found")
	}
	// Perform the login
	data := url.Values{}
	data.Set("clientid", TestClientid)
	data.Set("username", TestUsername)
	data.Set("password", password)
	data.Set("redirecturi", TestRedirectUri)
	data.Set("state", TestState)
	data.Set("csrf_token", csrfToken)
	req, err = http.NewRequest("POST", LoginUrl, strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestLoginWithUnknownUser(t *testing.T) {
	echoServer, controller := waitForServer(t)
	defer echoServer.Close()
	defer controller.Store.Close()
	// Don't create a test user so we can assert that we get an error
	client := createTestHttpClient()
	res := performAuthorizeAndLogin(t, client, TestPassword)
	// assert that we redirected to the client with a code
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Contains(t, locationHeader, "error=access_denied")
}

func TestLoginWithWrongPassword(t *testing.T) {
	echoServer, controller := waitForServer(t)
	defer echoServer.Close()
	defer controller.Store.Close()
	createTestUser(t, controller)
	client := createTestHttpClient()
	res := performAuthorizeAndLogin(t, client, "WRONGPASSWORD")
	// assert that we redirected to the client with a code
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Contains(t, locationHeader, "error=access_denied")
}

func TestLoginWithExistingUser(t *testing.T) {
	echoServer, controller := waitForServer(t)
	defer echoServer.Close()
	defer controller.Store.Close()
	createTestUser(t, controller)
	client := createTestHttpClient()
	res := performAuthorizeAndLogin(t, client, TestPassword)
	// assert that we redirected to the client with a code
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Contains(t, locationHeader, TestRedirectUri)
	assert.NotContains(t, locationHeader, "error=")
	assert.Contains(t, locationHeader, "code=")
	assert.Contains(t, locationHeader, "state="+TestState)
}

func TestLoginAndFetchToken(t *testing.T) {
	echoServer, controller := waitForServer(t)
	defer echoServer.Close()
	defer controller.Store.Close()
	createTestUser(t, controller)
	client := createTestHttpClient()
	res := performAuthorizeAndLogin(t, client, TestPassword)
	// assert that we redirected to the client with a code and no error
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Contains(t, locationHeader, TestRedirectUri)
	assert.NotContains(t, locationHeader, "error=")
	assert.Contains(t, locationHeader, "code=")
	assert.Contains(t, locationHeader, "state="+TestState)
	// Now fetch the token
	parsedUrl, err := url.Parse(locationHeader)
	if err != nil {
		t.Fatal(err)
	}
	// Extract the query parameters
	params, err := url.ParseQuery(parsedUrl.RawQuery)
	if err != nil {
		t.Fatal(err)
	}
	// Get a specific parameter
	code := params.Get("code")
	// Prepare the token request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", TestRedirectUri)
	req, _ := http.NewRequest("POST", "http://localhost:1323/token", strings.NewReader(data.Encode()))
	req.SetBasicAuth(TestClientid, TestSecret)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "application/json;charset=UTF-8", res.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
	// TODO: do we need to set no-cache?
	// assert.Equal(t, "no-cache", res.Header.Get("Pragma"))
	// assert that we got an id token
	body := readBody(res)
	assert.Contains(t, body, "id_token")
}

func TestGenerateValidIdToken(t *testing.T) {
	loadKeys(t)
	token, err := server.GenerateIdToken(serverConfig.JwtConfig, TestClientid, TestUsername)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := decodeIdTokenClaims(token, serverConfig.JwtConfig.PublicKey)
	assert.NoError(t, err)
	assert.Equal(t, serverConfig.JwtConfig.Issuer, claims["iss"])
	assert.Equal(t, TestUsername, claims["sub"])
	assert.Equal(t, TestClientid, claims["aud"])
	assert.WithinDuration(t, time.Now().Add(time.Minute*time.Duration(serverConfig.JwtConfig.IdTokenValidityMinutes)), time.Unix(int64(claims["exp"].(float64)), 0), time.Second)
}

func TestGenerateIdTokenWithWrongSecret(t *testing.T) {
	loadKeys(t)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	token, err := server.GenerateIdToken(domain.JwtConfiguration{
		Issuer:                 TestJwtissuer,
		IdTokenValidityMinutes: 5,
		PrivateKey:             wrongKey,
		PublicKey:              nil,
	}, TestClientid, TestUsername)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	_, err = decodeIdTokenClaims(token, serverConfig.JwtConfig.PublicKey)
	assert.Error(t, err)
}

func decodeIdTokenClaims(token string, publicKey *rsa.PublicKey) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	return claims, err
}

func createTestUser(t *testing.T, controller server.Controller) {
	hashedPassword, err := crypto.HashPassword(TestPassword)
	if err != nil {
		t.Fatal(err)
	}
	err = controller.Store.CreateUser(TestUsername, hashedPassword)
	if err != nil {
		t.Fatal(err)
	}
}

// construct a test HTTP client with cookie support so we can transport the CSRF token
// and suppressed redirects so we can assert against the location header
// createTestHttpClient returns an HTTP client with cookie support and disabled redirects.
// This is useful for testing scenarios where you need to assert against the location header.
func createTestHttpClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		// we need to prevent the client from redirecting automatically since we may need to assert
		// against the location header
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		//Transport: &http.Transport{DisableKeepAlives: true},
	}
}

// extract csrf token from the login HTML page
func extractCsrfToken(body string) string {
	re := regexp.MustCompile(`name="csrf_token" value="(\w+)"`)
	matches := re.FindStringSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func waitForServer(t *testing.T) (*echo.Echo, server.Controller) {
	loadKeys(t)
	var store repository.Store
	err := store.InitAndVerifyDb(repository.CreateInMemoryDbUrl())
	if err != nil {
		panic(err)
	}
	controller := server.Controller{&store, serverConfig}
	echoServer := server.InitServer(controller)
	go func() {
		_ = echoServer.Start(":" + strconv.Itoa(serverConfig.ServerPort))
	}()
	waitForServerStart(t, "http://localhost:"+strconv.Itoa(serverConfig.ServerPort))
	return echoServer, controller
}

func waitForServerStart(t *testing.T, url string) {
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("Server did not start after %d retries", maxRetries)
}

func readBody(res *http.Response) string {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	return string(body)
}

func loadKeys(t *testing.T) {
	if serverConfig.JwtConfig.PrivateKey == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		serverConfig.JwtConfig.PrivateKey = key
		serverConfig.JwtConfig.PublicKey = &key.PublicKey
	}
}
