package server_test

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/repository"
	"aggregat4/openidprovider/internal/server"
	tokenutil "aggregat4/openidprovider/internal/tokens"
	"aggregat4/openidprovider/pkg/email"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"

	"github.com/aggregat4/go-baselib/crypto"

	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const TestClientid = "testclientid"
const TestUsername = "testusername"
const TestPassword = "testpassword"
const TestState = "teststate"
const TestSecret = "testsecret"
const TestRedirectUri = "http://localhost:8080"
const OtherClientid = "otherclientid"
const OtherSecret = "othersecret"
const OtherRedirectUri = "http://localhost:8081/callback"
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
		OtherClientid: {
			Id:              OtherClientid,
			RedirectUris:    []string{OtherRedirectUri},
			BasicAuthSecret: OtherSecret,
		},
	},
	JwtConfig: domain.JwtConfiguration{
		Issuer:                 TestJwtissuer,
		IdTokenValidityMinutes: 5,
		PrivateKey:             nil,
		PublicKey:              nil,
	},
	TokenConfig: domain.TokenConfiguration{
		AccessTokenValidityMinutes:          5,
		RefreshTokenInactivityValidityHours: 7 * 24,
	},
	CleanupConfig: domain.CleanupConfiguration{
		UnverifiedUserMaxAge: 24 * time.Hour,
		CleanupInterval:      1 * time.Second,
	},
	AltchaConfig: domain.AltchaConfiguration{
		HMACKey:    "test-hmac-key",
		MaxNumber:  100000,
		SaltLength: 12,
	},
}

type oauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	IdToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

// Test functions start here
func TestAuthorizeWithoutParameters(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)
	client := createTestHttpClient()
	res := makeGetRequest(t, client, AuthorizeUrl)
	assert.Equal(t, 400, res.StatusCode)
}

func TestStatusEndpoint(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	res := makeGetRequest(t, client, "http://localhost:1323/status")
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "OK", readBody(res))
}

func TestJwksEndpoint(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	res := makeGetRequest(t, client, "http://localhost:1323/.well-known/jwks.json")
	assert.Equal(t, http.StatusOK, res.StatusCode)

	body := readBody(res)
	assert.Contains(t, body, "\"keys\"")
	assert.Contains(t, body, "\"kid\": \"id-token-key\"")
	assert.Contains(t, body, "\"alg\": \"RS256\"")
}

func TestAuthorize(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)
	client := createTestHttpClient()
	authorizeUrl := createAuthorizeUrl(t, "openid")
	res := makeGetRequest(t, client, authorizeUrl.String())
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Contains(t, locationHeader, "/login")
	assert.Contains(t, locationHeader, "client_id="+TestClientid)
	assert.Contains(t, locationHeader, "redirect_uri="+url.QueryEscape(TestRedirectUri))
	assert.Contains(t, locationHeader, "state="+TestState)
}

func TestAuthorizeWithInvalidScope(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)
	client := createTestHttpClient()
	authorizeUrl := createAuthorizeUrl(t, "openid invalid_scope")
	res := makeGetRequest(t, client, authorizeUrl.String())
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Contains(t, locationHeader, "error=invalid_scope")
}

func TestAuthorizeWithValidScopes(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)
	client := createTestHttpClient()
	authorizeUrl := createAuthorizeUrl(t, "openid profile")
	res := makeGetRequest(t, client, authorizeUrl.String())
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Contains(t, locationHeader, "/login")
}

func TestAuthorizeWithUnsupportedResponseType(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	authorizeURL := createAuthorizeUrl(t, "openid")
	query := authorizeURL.Query()
	query.Set("response_type", "token")
	authorizeURL.RawQuery = query.Encode()

	res := makeGetRequest(t, client, authorizeURL.String())
	assert.Equal(t, http.StatusFound, res.StatusCode)
	assert.Contains(t, res.Header.Get("Location"), "error=unsupported_response_type")
}

func TestLoginPageGet(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	res := makeGetRequest(t, client, LoginUrl)
	assert.Equal(t, 200, res.StatusCode)
	body := readBody(res)
	assert.Contains(t, strings.ToLower(body), "method=\"post\"")
	assert.Contains(t, body, "action=\"/login\"")
}

func TestLoginWithUnknownUser(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)
	// Don't create a test user so we can assert that we get an error
	client := createTestHttpClient()
	res := performAuthorizeAndLogin(t, client, TestPassword)
	// assert that we redirected to the client with an error
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Contains(t, locationHeader, "error=access_denied")
}

func TestLoginWithWrongPassword(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)
	createTestUser(t, controller)
	client := createTestHttpClient()
	res := performAuthorizeAndLogin(t, client, "WRONGPASSWORD")
	// assert that we redirected to the client with an error
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Contains(t, locationHeader, "error=access_denied")
}

func TestLoginWithExistingUser(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)
	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
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
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)
	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
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

	tokenUrl, err := createEndpointUrl("/token")
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", tokenUrl.String(), strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(TestClientid, TestSecret)
	setRequiredFormPostHeaders(req)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "application/json;charset=UTF-8", res.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
	// assert that we got an id token
	body := readBody(res)
	assert.Contains(t, body, "id_token")
}

func TestAuthorizationCodeExchangeReturnsRefreshToken(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()

	tokenResponse := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")
	assert.NotEmpty(t, tokenResponse.AccessToken)
	assert.Equal(t, "Bearer", tokenResponse.TokenType)
	assert.NotEmpty(t, tokenResponse.IdToken)
	assert.NotEmpty(t, tokenResponse.RefreshToken)
	assert.Equal(t, 300, tokenResponse.ExpiresIn)
}

func TestTokenEndpointRequiresBasicAuth(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	endpoint, err := createEndpointUrl("/token")
	require.NoError(t, err)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", "irrelevant")
	data.Set("redirect_uri", TestRedirectUri)

	req, err := http.NewRequest("POST", endpoint.String(), strings.NewReader(data.Encode()))
	require.NoError(t, err)
	setRequiredFormPostHeaders(req)

	res, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	assert.Contains(t, res.Header.Get("WWW-Authenticate"), "Basic")
}

func TestTokenEndpointRejectsWrongBasicAuthSecret(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", "irrelevant")
	data.Set("redirect_uri", TestRedirectUri)

	endpoint, err := createEndpointUrl("/token")
	require.NoError(t, err)
	req, err := http.NewRequest("POST", endpoint.String(), strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.SetBasicAuth(TestClientid, "wrong-secret")
	setRequiredFormPostHeaders(req)

	res, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	assert.Contains(t, res.Header.Get("WWW-Authenticate"), "Basic")
}

func TestRevokeEndpointRequiresBasicAuth(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	endpoint, err := createEndpointUrl("/revoke")
	require.NoError(t, err)

	data := url.Values{}
	data.Set("token", "irrelevant")

	req, err := http.NewRequest("POST", endpoint.String(), strings.NewReader(data.Encode()))
	require.NoError(t, err)
	setRequiredFormPostHeaders(req)

	res, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	assert.Contains(t, res.Header.Get("WWW-Authenticate"), "Basic")
}

func TestMiddlewareDoesNotProtectStatusEndpoint(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	res := makeGetRequest(t, client, "http://localhost:1323/status")
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestTokenEndpointRejectsUnsupportedGrantType(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	response, tokenResponse, err := doTokenRequest(client, TestClientid, TestSecret, data)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	assert.Equal(t, "unsupported_grant_type", tokenResponse.Error)
}

func TestAuthorizationCodeGrantRequiresCode(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", TestRedirectUri)

	response, tokenResponse, err := doTokenRequest(client, TestClientid, TestSecret, data)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	assert.Equal(t, "invalid_request", tokenResponse.Error)
}

func TestAuthorizationCodeGrantRequiresRedirectURI(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", "some-code")

	response, tokenResponse, err := doTokenRequest(client, TestClientid, TestSecret, data)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	assert.Equal(t, "invalid_request", tokenResponse.Error)
}

func TestAuthorizationCodeGrantRejectsInvalidRedirectURI(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", "some-code")
	data.Set("redirect_uri", "http://localhost:9999/not-registered")

	response, tokenResponse, err := doTokenRequest(client, TestClientid, TestSecret, data)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	assert.Equal(t, "invalid_client", tokenResponse.Error)
}

func TestAuthorizationCodeGrantRejectsUnknownCode(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", "unknown-code")
	data.Set("redirect_uri", TestRedirectUri)

	response, tokenResponse, err := doTokenRequest(client, TestClientid, TestSecret, data)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	assert.Equal(t, "invalid_grant", tokenResponse.Error)
}

func TestAuthorizationCodeGrantCannotReuseCode(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()
	loginResponse := performAuthorizeAndLogin(t, client, TestPassword)
	code := authorizationCodeFromRedirect(t, loginResponse.Header.Get("Location"))

	firstTokens, firstResponse := exchangeAuthorizationCodeForTokens(t, client, TestClientid, TestSecret, TestRedirectUri, code)
	assert.Equal(t, http.StatusOK, firstResponse.StatusCode)
	assert.NotEmpty(t, firstTokens.RefreshToken)

	secondTokens, secondResponse := exchangeAuthorizationCodeForTokens(t, client, TestClientid, TestSecret, TestRedirectUri, code)
	assert.Equal(t, http.StatusBadRequest, secondResponse.StatusCode)
	assert.Equal(t, "invalid_grant", secondTokens.Error)
}

func TestAuthorizationCodeGrantRejectsCodeRedeemedByWrongClient(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()
	loginResponse := performAuthorizeAndLoginForClient(t, client, TestClientid, TestRedirectUri, TestUsername, TestPassword, "openid profile")
	code := authorizationCodeFromRedirect(t, loginResponse.Header.Get("Location"))

	tokenResponse, tokenExchangeResponse := exchangeAuthorizationCodeForTokens(t, client, OtherClientid, OtherSecret, OtherRedirectUri, code)
	assert.Equal(t, http.StatusBadRequest, tokenExchangeResponse.StatusCode)
	assert.Equal(t, "invalid_grant", tokenResponse.Error)
}

func TestRefreshTokenGrantReturnsRotatedRefreshToken(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()

	initialTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")
	refreshedTokens, response := refreshTokensForClient(t, client, TestClientid, TestSecret, initialTokens.RefreshToken)

	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.NotEmpty(t, refreshedTokens.AccessToken)
	assert.NotEmpty(t, refreshedTokens.IdToken)
	assert.NotEmpty(t, refreshedTokens.RefreshToken)
	assert.NotEqual(t, initialTokens.RefreshToken, refreshedTokens.RefreshToken)
	assert.Equal(t, 300, refreshedTokens.ExpiresIn)
}

func TestRotatedRefreshTokenCannotBeReused(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()

	initialTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")
	_, refreshedResponse := refreshTokensForClient(t, client, TestClientid, TestSecret, initialTokens.RefreshToken)
	assert.Equal(t, http.StatusOK, refreshedResponse.StatusCode)

	replayedTokens, replayResponse := refreshTokensForClient(t, client, TestClientid, TestSecret, initialTokens.RefreshToken)
	assert.Equal(t, http.StatusBadRequest, replayResponse.StatusCode)
	assert.Equal(t, "invalid_grant", replayedTokens.Error)
}

func TestRefreshTokenReplayRevokesActiveFamilyMember(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()

	initialTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")
	refreshedTokens, refreshedResponse := refreshTokensForClient(t, client, TestClientid, TestSecret, initialTokens.RefreshToken)
	assert.Equal(t, http.StatusOK, refreshedResponse.StatusCode)

	_, replayResponse := refreshTokensForClient(t, client, TestClientid, TestSecret, initialTokens.RefreshToken)
	assert.Equal(t, http.StatusBadRequest, replayResponse.StatusCode)

	revokedTokens, revokedResponse := refreshTokensForClient(t, client, TestClientid, TestSecret, refreshedTokens.RefreshToken)
	assert.Equal(t, http.StatusBadRequest, revokedResponse.StatusCode)
	assert.Equal(t, "invalid_grant", revokedTokens.Error)
}

func TestRevokedRefreshTokenReturnsInvalidGrant(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()

	initialTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")
	revokeResponse := revokeRefreshTokenForClient(t, client, TestClientid, TestSecret, initialTokens.RefreshToken)
	assert.Equal(t, http.StatusOK, revokeResponse.StatusCode)

	refreshedTokens, refreshedResponse := refreshTokensForClient(t, client, TestClientid, TestSecret, initialTokens.RefreshToken)
	assert.Equal(t, http.StatusBadRequest, refreshedResponse.StatusCode)
	assert.Equal(t, "invalid_grant", refreshedTokens.Error)
}

func TestRefreshTokenGrantRequiresRefreshToken(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("grant_type", "refresh_token")

	response, tokenResponse, err := doTokenRequest(client, TestClientid, TestSecret, data)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	assert.Equal(t, "invalid_request", tokenResponse.Error)
}

func TestRefreshTokenGrantRejectsUnknownRefreshToken(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	tokenResponse, response := refreshTokensForClient(t, client, TestClientid, TestSecret, "unknown-refresh-token")
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	assert.Equal(t, "invalid_grant", tokenResponse.Error)
}

func TestExpiredRefreshTokenReturnsInvalidGrant(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	expiredRefreshToken := createStoredRefreshToken(t, controller, TestUsername, TestClientid, "openid profile", "family-expired", time.Now().Add(-2*time.Hour), time.Now().Add(-1*time.Hour))
	client := createTestHttpClient()

	refreshedTokens, refreshedResponse := refreshTokensForClient(t, client, TestClientid, TestSecret, expiredRefreshToken)
	assert.Equal(t, http.StatusBadRequest, refreshedResponse.StatusCode)
	assert.Equal(t, "invalid_grant", refreshedTokens.Error)
}

func TestRefreshTokenGrantRejectsWhenGrantedScopeNoLongerExists(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()

	initialTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")
	scopeClaims, err := controller.Store.ListScopeClaims("profile")
	require.NoError(t, err)
	for _, claim := range scopeClaims {
		err = controller.Store.RemoveClaimFromScope("profile", claim.ClaimName)
		require.NoError(t, err)
	}
	err = controller.Store.DeleteScope("profile")
	require.NoError(t, err)

	refreshedTokens, refreshedResponse := refreshTokensForClient(t, client, TestClientid, TestSecret, initialTokens.RefreshToken)
	assert.Equal(t, http.StatusBadRequest, refreshedResponse.StatusCode)
	assert.Equal(t, "invalid_grant", refreshedTokens.Error)
}

func TestRefreshTokenBoundToClientA(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()

	initialTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")
	refreshedTokens, refreshedResponse := refreshTokensForClient(t, client, OtherClientid, OtherSecret, initialTokens.RefreshToken)
	assert.Equal(t, http.StatusBadRequest, refreshedResponse.StatusCode)
	assert.Equal(t, "invalid_grant", refreshedTokens.Error)
}

func TestRevokeWrongClientReturnsSuccessAndDoesNothing(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()

	initialTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")
	revokeResponse := revokeRefreshTokenForClient(t, client, OtherClientid, OtherSecret, initialTokens.RefreshToken)
	assert.Equal(t, http.StatusOK, revokeResponse.StatusCode)

	refreshedTokens, refreshedResponse := refreshTokensForClient(t, client, TestClientid, TestSecret, initialTokens.RefreshToken)
	assert.Equal(t, http.StatusOK, refreshedResponse.StatusCode)
	assert.NotEmpty(t, refreshedTokens.RefreshToken)
}

func TestConcurrentRefreshAttemptsProduceOneSuccessfulRotation(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()

	initialTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")

	type concurrentResult struct {
		response     oauthTokenResponse
		statusCode   int
		requestErr   error
		refreshToken string
	}

	results := make(chan concurrentResult, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, tokenResponse, err := refreshTokensForClientRequest(client, TestClientid, TestSecret, initialTokens.RefreshToken)
			if err != nil {
				results <- concurrentResult{requestErr: err}
				return
			}
			results <- concurrentResult{
				response:     tokenResponse,
				statusCode:   res.StatusCode,
				refreshToken: tokenResponse.RefreshToken,
			}
		}()
	}
	wg.Wait()
	close(results)

	successCount := 0
	invalidGrantCount := 0
	var activeRefreshToken string
	for result := range results {
		if result.requestErr != nil {
			t.Fatal(result.requestErr)
		}
		switch result.statusCode {
		case http.StatusOK:
			successCount++
			activeRefreshToken = result.refreshToken
		case http.StatusBadRequest:
			assert.Equal(t, "invalid_grant", result.response.Error)
			invalidGrantCount++
		default:
			t.Fatalf("unexpected status code: %d", result.statusCode)
		}
	}

	assert.Equal(t, 1, successCount)
	assert.Equal(t, 1, invalidGrantCount)
	assert.NotEmpty(t, activeRefreshToken)
}

func TestRevokeRequiresToken(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	endpoint, err := createEndpointUrl("/revoke")
	require.NoError(t, err)

	req, err := http.NewRequest("POST", endpoint.String(), strings.NewReader(url.Values{}.Encode()))
	require.NoError(t, err)
	req.SetBasicAuth(TestClientid, TestSecret)
	setRequiredFormPostHeaders(req)

	res, err := client.Do(req)
	require.NoError(t, err)

	body := readBody(res)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Contains(t, body, "invalid_request")
}

func TestRevokeUnknownRefreshTokenIsIdempotent(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	response := revokeRefreshTokenForClient(t, client, TestClientid, TestSecret, "unknown-refresh-token")
	assert.Equal(t, http.StatusOK, response.StatusCode)
}

func TestRevokeAlreadyRevokedRefreshTokenIsIdempotent(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()

	initialTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")
	firstResponse := revokeRefreshTokenForClient(t, client, TestClientid, TestSecret, initialTokens.RefreshToken)
	secondResponse := revokeRefreshTokenForClient(t, client, TestClientid, TestSecret, initialTokens.RefreshToken)

	assert.Equal(t, http.StatusOK, firstResponse.StatusCode)
	assert.Equal(t, http.StatusOK, secondResponse.StatusCode)
}

func TestRevokeIgnoresTokenTypeHint(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()

	initialTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")

	endpoint, err := createEndpointUrl("/revoke")
	require.NoError(t, err)
	data := url.Values{}
	data.Set("token", initialTokens.RefreshToken)
	data.Set("token_type_hint", "access_token")

	req, err := http.NewRequest("POST", endpoint.String(), strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.SetBasicAuth(TestClientid, TestSecret)
	setRequiredFormPostHeaders(req)

	res, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestPasswordResetRevokesAllRefreshTokensForUser(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()

	firstTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")
	secondTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")
	createPasswordResetToken(t, controller, "reset-refresh-tokens", TestUsername, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix())

	data := url.Values{}
	data.Set("token", "reset-refresh-tokens")
	data.Set("password", "newpassword123")
	data.Set("confirmPassword", "newpassword123")
	resetResponse := makePostRequest(t, client, "http://localhost:1323/reset-password", data)
	assert.Equal(t, http.StatusOK, resetResponse.StatusCode)

	firstRefresh, firstRefreshResponse := refreshTokensForClient(t, client, TestClientid, TestSecret, firstTokens.RefreshToken)
	assert.Equal(t, http.StatusBadRequest, firstRefreshResponse.StatusCode)
	assert.Equal(t, "invalid_grant", firstRefresh.Error)

	secondRefresh, secondRefreshResponse := refreshTokensForClient(t, client, TestClientid, TestSecret, secondTokens.RefreshToken)
	assert.Equal(t, http.StatusBadRequest, secondRefreshResponse.StatusCode)
	assert.Equal(t, "invalid_grant", secondRefresh.Error)
}

func TestVerifyDeleteSuccessRemovesRefreshTokens(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()

	issuedTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")
	token := uuid.New().String()
	createDeleteAccountToken(t, controller, token, TestUsername, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix())

	data := url.Values{}
	data.Set("code", token)

	res := makePostRequest(t, client, "http://localhost:1323/verify-delete", data)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	refreshTokens, err := controller.Store.ListRefreshTokensByEmail(TestUsername)
	require.NoError(t, err)
	assert.Len(t, refreshTokens, 0)

	refreshedTokens, refreshedResponse := refreshTokensForClient(t, client, TestClientid, TestSecret, issuedTokens.RefreshToken)
	assert.Equal(t, http.StatusBadRequest, refreshedResponse.StatusCode)
	assert.Equal(t, "invalid_grant", refreshedTokens.Error)
}

func TestCleanupDeletesExpiredAndOldRevokedRefreshTokens(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)

	expiredToken := createStoredRefreshTokenRecord(t, controller, TestUsername, TestClientid, "openid profile", "family-expired-cleanup", time.Now().Add(-4*time.Hour), time.Now().Add(-2*time.Hour), sql.NullInt64{}, sql.NullInt64{})
	oldRevokedToken := createStoredRefreshTokenRecord(t, controller, TestUsername, TestClientid, "openid profile", "family-old-revoked", time.Now().Add(-48*time.Hour), time.Now().Add(24*time.Hour), sql.NullInt64{}, sql.NullInt64{Int64: time.Now().Add(-31 * 24 * time.Hour).Unix(), Valid: true})
	activeToken := createStoredRefreshTokenRecord(t, controller, TestUsername, TestClientid, "openid profile", "family-active-cleanup", time.Now(), time.Now().Add(24*time.Hour), sql.NullInt64{}, sql.NullInt64{})

	time.Sleep(2 * time.Second)

	foundExpired, err := controller.Store.FindRefreshToken(expiredToken)
	require.NoError(t, err)
	assert.Nil(t, foundExpired)

	foundRevoked, err := controller.Store.FindRefreshToken(oldRevokedToken)
	require.NoError(t, err)
	assert.Nil(t, foundRevoked)

	foundActive, err := controller.Store.FindRefreshToken(activeToken)
	require.NoError(t, err)
	assert.NotNil(t, foundActive)
}

func TestRefreshIdTokenKeepsOriginalAuthTime(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	client := createTestHttpClient()

	initialTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")
	initialClaims, err := decodeIdTokenClaims(initialTokens.IdToken, serverConfig.JwtConfig.PublicKey)
	require.NoError(t, err)

	time.Sleep(1 * time.Second)
	refreshedTokens, refreshedResponse := refreshTokensForClient(t, client, TestClientid, TestSecret, initialTokens.RefreshToken)
	assert.Equal(t, http.StatusOK, refreshedResponse.StatusCode)

	refreshedClaims, err := decodeIdTokenClaims(refreshedTokens.IdToken, serverConfig.JwtConfig.PublicKey)
	require.NoError(t, err)

	assert.Equal(t, initialClaims["auth_time"], refreshedClaims["auth_time"])
	assert.NotEqual(t, initialClaims["iat"], refreshedClaims["iat"])
}

func TestRefreshIdTokenUsesUpdatedClaimValues(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)
	user, err := controller.Store.FindUser(TestUsername)
	require.NoError(t, err)
	require.NotNil(t, user)

	err = controller.Store.SetUserClaim(repository.UserClaim{
		UserId:    user.Id,
		ClaimName: "name",
		Value:     "Original Name",
		CreatedAt: time.Now().Unix(),
	})
	require.NoError(t, err)

	client := createTestHttpClient()
	initialTokens := authorizeAndExchangeTokensForClient(t, client, TestClientid, TestSecret, TestRedirectUri, "openid profile")
	initialClaims, err := decodeIdTokenClaims(initialTokens.IdToken, serverConfig.JwtConfig.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, "Original Name", initialClaims["name"])

	err = controller.Store.SetUserClaim(repository.UserClaim{
		UserId:    user.Id,
		ClaimName: "name",
		Value:     "Updated Name",
		CreatedAt: time.Now().Unix(),
	})
	require.NoError(t, err)

	refreshedTokens, refreshedResponse := refreshTokensForClient(t, client, TestClientid, TestSecret, initialTokens.RefreshToken)
	assert.Equal(t, http.StatusOK, refreshedResponse.StatusCode)

	refreshedClaims, err := decodeIdTokenClaims(refreshedTokens.IdToken, serverConfig.JwtConfig.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", refreshedClaims["name"])
}

func TestOpenIDConfigurationAdvertisesRefreshSupport(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	res, err := client.Get("http://localhost:1323/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	assert.Equal(t, http.StatusOK, res.StatusCode)

	var config domain.OpenIdConfiguration
	err = json.NewDecoder(res.Body).Decode(&config)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "http://localhost:1323/revoke", config.RevocationEndpoint)
	assert.Contains(t, config.GrantTypesSupported, "authorization_code")
	assert.Contains(t, config.GrantTypesSupported, "refresh_token")
	assert.Equal(t, []string{"client_secret_basic"}, config.RevocationEndpointAuthMethods)
}

func TestGenerateValidIdToken(t *testing.T) {
	loadKeys(t)
	token, err := server.GenerateIdToken(serverConfig.JwtConfig, TestClientid, TestUsername, map[string]any{})
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
	}, TestClientid, TestUsername, map[string]any{})
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	_, err = decodeIdTokenClaims(token, serverConfig.JwtConfig.PublicKey)
	assert.Error(t, err)
}

func TestForgotPasswordWithNonExistentUser(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("email", "nonexistent@example.com")

	res := makePostRequest(t, client, "http://localhost:1323/forgot-password", data)
	assert.Equal(t, 200, res.StatusCode)
	body := readBody(res)
	assert.Contains(t, body, "If an account exists with this email")
}

func TestForgotPasswordWithUnverifiedUser(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createTestUserWithPassword(t, controller, TestUsername, TestPassword)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("email", TestUsername)

	res := makePostRequest(t, client, "http://localhost:1323/forgot-password", data)
	assert.Equal(t, 200, res.StatusCode)
	body := readBody(res)
	assert.Contains(t, body, "If an account exists with this email")
}

func TestForgotPasswordWithVerifiedUser(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("email", TestUsername)

	res := makePostRequest(t, client, "http://localhost:1323/forgot-password", data)
	assert.Equal(t, 200, res.StatusCode)
	body := readBody(res)
	assert.Contains(t, body, "If an account exists with this email")

	// Verify that a reset token was created
	tokens, err := controller.Store.FindVerificationTokenByEmail(TestUsername)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(tokens))
	assert.Equal(t, "password_reset", tokens[0].Type)
}

func TestResetPasswordWithInvalidToken(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("token", "invalid-token")
	data.Set("password", "newpassword")
	data.Set("confirmPassword", "newpassword")

	res := makePostRequest(t, client, "http://localhost:1323/reset-password", data)
	assert.Equal(t, 400, res.StatusCode)
	body := readBody(res)
	assert.Contains(t, body, "Invalid or expired reset link")
}

func TestResetPasswordWithExpiredToken(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)

	// Create an expired reset token
	createPasswordResetToken(t, controller, "expired-token", TestUsername,
		time.Now().Add(-25*time.Hour).Unix(),
		time.Now().Add(-1*time.Hour).Unix())

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("token", "expired-token")
	data.Set("password", "newpassword")
	data.Set("confirmPassword", "newpassword")

	res := makePostRequest(t, client, "http://localhost:1323/reset-password", data)
	assert.Equal(t, 400, res.StatusCode)
	body := readBody(res)
	assert.Contains(t, body, "Reset link has expired")
}

func TestResetPasswordSuccess(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)

	// Create a valid reset token
	createPasswordResetToken(t, controller, "valid-token", TestUsername,
		time.Now().Unix(),
		time.Now().Add(24*time.Hour).Unix())

	// Reset password
	newPassword := "newpassword123"
	client := createTestHttpClient()
	data := url.Values{}
	data.Set("token", "valid-token")
	data.Set("password", newPassword)
	data.Set("confirmPassword", newPassword)

	res := makePostRequest(t, client, "http://localhost:1323/reset-password", data)
	assert.Equal(t, 200, res.StatusCode)
	body := readBody(res)
	assert.Contains(t, body, "Password has been reset successfully")

	// Verify the password was changed by trying to log in
	res = performAuthorizeAndLogin(t, client, newPassword)
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Contains(t, locationHeader, TestRedirectUri)
	assert.NotContains(t, locationHeader, "error=")
	assert.Contains(t, locationHeader, "code=")
}

func TestCleanupJob(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	// Create test data
	// Create an unverified user that's older than max age
	oldUser := "old@example.com"
	hashedPassword, err := crypto.HashPassword("password")
	if err != nil {
		t.Fatal(err)
	}
	err = controller.Store.CreateUser(oldUser, hashedPassword)
	if err != nil {
		t.Fatal(err)
	}
	err = controller.Store.UpdateLastUpdated(oldUser, time.Now().Add(-25*time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}

	// Create an unverified user that's within max age
	newUser := "new@example.com"
	err = controller.Store.CreateUser(newUser, hashedPassword)
	if err != nil {
		t.Fatal(err)
	}

	// Create a verified user
	verifiedUser := "verified@example.com"
	err = controller.Store.CreateUser(verifiedUser, hashedPassword)
	if err != nil {
		t.Fatal(err)
	}
	err = controller.Store.VerifyUser(verifiedUser)
	if err != nil {
		t.Fatal(err)
	}

	// Create expired verification token
	expiredToken := repository.VerificationToken{
		Token:   "expired_token",
		Email:   oldUser,
		Type:    "registration",
		Created: time.Now().Add(-25 * time.Hour).Unix(),
		Expires: time.Now().Add(-1 * time.Hour).Unix(),
	}
	err = controller.Store.CreateVerificationToken(expiredToken)
	if err != nil {
		t.Fatal(err)
	}

	// Create valid verification token
	validToken := repository.VerificationToken{
		Token:   "valid_token",
		Email:   newUser,
		Type:    "registration",
		Created: time.Now().Unix(),
		Expires: time.Now().Add(24 * time.Hour).Unix(),
	}
	err = controller.Store.CreateVerificationToken(validToken)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for cleanup to run
	time.Sleep(2 * time.Second)

	// Verify results
	// Old unverified user should be deleted
	user, err := controller.Store.FindUser(oldUser)
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, user, "Old unverified user should be deleted")

	// New unverified user should still exist
	user, err = controller.Store.FindUser(newUser)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, user, "New unverified user should not be deleted")
	assert.False(t, user.Verified, "New user should still be unverified")

	// Verified user should still exist
	user, err = controller.Store.FindUser(verifiedUser)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, user, "Verified user should not be deleted")
	assert.True(t, user.Verified, "User should still be verified")

	// Expired token should be deleted
	token, err := controller.Store.FindVerificationToken("expired_token")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, token, "Expired verification token should be deleted")

	// Valid token should still exist
	token, err = controller.Store.FindVerificationToken("valid_token")
	if err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, token, "Valid verification token should not be deleted")
}

func TestDeleteAccountWithNonExistentUser(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	data := url.Values{}
	data.Set("email", "nonexistent@example.com")

	client := createTestHttpClient()
	res := makePostRequest(t, client, "http://localhost:1323/delete-account", data)
	assert.Equal(t, 200, res.StatusCode)
}

func TestDeleteAccountWithUnverifiedUser(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)
	createTestUserWithPassword(t, controller, TestUsername, TestPassword)

	data := url.Values{}
	data.Set("email", TestUsername)

	client := createTestHttpClient()
	res := makePostRequest(t, client, "http://localhost:1323/delete-account", data)
	assert.Equal(t, 200, res.StatusCode)
}

func TestDeleteAccountWithVerifiedUser(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)
	createVerifiedTestUser(t, controller, TestUsername, TestPassword)

	data := url.Values{}
	data.Set("email", TestUsername)

	client := createTestHttpClient()
	res := makePostRequest(t, client, "http://localhost:1323/delete-account", data)
	assert.Equal(t, 200, res.StatusCode)

	// Verify that a delete account email was sent
	mockEmailService := controller.EmailService.(*MockEmailService)
	found := false
	for _, email := range mockEmailService.SentEmails {
		if email.Subject == "Delete your account" && email.ToEmail == TestUsername {
			found = true
			break
		}
	}
	assert.True(t, found, "Delete account email should have been sent")
}

func TestVerifyDeleteWithInvalidToken(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	data := url.Values{}
	data.Set("code", "invalid-token")

	client := createTestHttpClient()
	res := makePostRequest(t, client, "http://localhost:1323/verify-delete", data)
	assert.Equal(t, 400, res.StatusCode)
}

func TestVerifyDeleteWithExpiredToken(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)
	createVerifiedTestUser(t, controller, TestUsername, TestPassword)

	// Create an expired token
	token := uuid.New().String()
	createDeleteAccountToken(t, controller, token, TestUsername,
		time.Now().Add(-48*time.Hour).Unix(),
		time.Now().Add(-24*time.Hour).Unix())

	data := url.Values{}
	data.Set("code", token)

	client := createTestHttpClient()
	res := makePostRequest(t, client, "http://localhost:1323/verify-delete", data)
	assert.Equal(t, 400, res.StatusCode)
}

func TestVerifyDeleteSuccess(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)
	createVerifiedTestUser(t, controller, TestUsername, TestPassword)

	// Create a valid token
	token := uuid.New().String()
	createDeleteAccountToken(t, controller, token, TestUsername,
		time.Now().Unix(),
		time.Now().Add(24*time.Hour).Unix())

	data := url.Values{}
	data.Set("code", token)

	client := createTestHttpClient()
	res := makePostRequest(t, client, "http://localhost:1323/verify-delete", data)
	assert.Equal(t, 200, res.StatusCode)

	// Verify that the user was deleted
	user, err := controller.Store.FindUser(TestUsername)
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, user, "User should have been deleted")
}

func TestResendDeleteVerificationRedirectsWithoutEmail(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	res := makeGetRequest(t, client, "http://localhost:1323/verify-delete/resend")
	assert.Equal(t, http.StatusFound, res.StatusCode)
	assert.Equal(t, "/delete-account", res.Header.Get("Location"))
}

func TestResendDeleteVerificationIgnoresUnknownUser(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	res := makeGetRequest(t, client, "http://localhost:1323/verify-delete/resend?email=missing@example.com")
	assert.Equal(t, http.StatusFound, res.StatusCode)
	assert.Equal(t, "/delete-account", res.Header.Get("Location"))
}

func TestResendDeleteVerificationSendsNewTokenForVerifiedUser(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	createVerifiedTestUser(t, controller, TestUsername, TestPassword)

	client := createTestHttpClient()
	res := makeGetRequest(t, client, "http://localhost:1323/verify-delete/resend?email="+url.QueryEscape(TestUsername))
	assert.Equal(t, http.StatusFound, res.StatusCode)
	assert.Equal(t, "/delete-account", res.Header.Get("Location"))

	tokens, err := controller.Store.FindVerificationTokenByEmail(TestUsername)
	require.NoError(t, err)

	foundDeleteToken := false
	for _, token := range tokens {
		if token.Type == "delete_account" {
			foundDeleteToken = true
			break
		}
	}
	assert.True(t, foundDeleteToken)
}

func TestIdTokenWithClaims(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	// Create and verify a test user
	createVerifiedTestUser(t, controller, TestUsername, TestPassword)

	// Set some test claims for the user
	user, err := controller.Store.FindUser(TestUsername)
	if err != nil {
		t.Fatal(err)
	}
	err = controller.Store.SetUserClaim(repository.UserClaim{
		UserId:    user.Id,
		ClaimName: "name",
		Value:     "Test User",
		CreatedAt: time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Perform authorization and login
	client := createTestHttpClient()
	res := performAuthorizeAndLogin(t, client, TestPassword)
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Contains(t, locationHeader, TestRedirectUri)
	assert.NotContains(t, locationHeader, "error=")
	assert.Contains(t, locationHeader, "code=")

	// Extract the code
	parsedUrl, err := url.Parse(locationHeader)
	if err != nil {
		t.Fatal(err)
	}
	params, err := url.ParseQuery(parsedUrl.RawQuery)
	if err != nil {
		t.Fatal(err)
	}
	code := params.Get("code")

	// Exchange code for token
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", TestRedirectUri)

	tokenUrl, err := url.Parse("http://localhost:1323/token")
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", tokenUrl.String(), strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(TestClientid, TestSecret)
	setRequiredFormPostHeaders(req)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 200, res.StatusCode)

	// Parse the response
	var tokenResponse struct {
		IdToken string `json:"id_token"`
	}
	err = json.NewDecoder(res.Body).Decode(&tokenResponse)
	if err != nil {
		t.Fatal(err)
	}

	// Decode and verify the ID token
	claims, err := decodeIdTokenClaims(tokenResponse.IdToken, serverConfig.JwtConfig.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Verify standard claims
	assert.Equal(t, serverConfig.JwtConfig.Issuer, claims["iss"])
	assert.Equal(t, TestUsername, claims["sub"])
	assert.Equal(t, TestClientid, claims["aud"])

	// Verify custom claims
	assert.Equal(t, "Test User", claims["name"])
}

func TestOpenIdConfiguration(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	res, err := client.Get("http://localhost:1323/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 200, res.StatusCode)

	var config domain.OpenIdConfiguration
	err = json.NewDecoder(res.Body).Decode(&config)
	if err != nil {
		t.Fatal(err)
	}

	// Verify standard endpoints
	assert.Equal(t, "http://localhost:1323", config.Issuer)
	assert.Equal(t, "http://localhost:1323/authorize", config.AuthorizationEndpoint)
	assert.Equal(t, "http://localhost:1323/token", config.TokenEndpoint)
	assert.Equal(t, "http://localhost:1323/.well-known/jwks.json", config.JwksUri)

	// Verify response types
	assert.Contains(t, config.ResponseTypesSupported, "code")

	// Verify subject types
	assert.Contains(t, config.SubjectTypesSupported, "public")

	// Verify signing algorithms
	assert.Contains(t, config.IdTokenSigningAlgValuesSupported, "RS256")

	// Verify scopes
	assert.Contains(t, config.ScopesSupported, "openid")
	assert.Contains(t, config.ScopesSupported, "profile")
	assert.Contains(t, config.ScopesSupported, "email")

	// Verify claims
	assert.Contains(t, config.ClaimsSupported, "sub")
	assert.Contains(t, config.ClaimsSupported, "name")
	assert.Contains(t, config.ClaimsSupported, "email")
}

func TestRegistrationWithNewUser(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("email", "newuser@example.com")
	data.Set("password", "newpassword")
	data.Set("confirmPassword", "newpassword")
	data.Set("altcha", "mock-solution")

	res := makePostRequest(t, client, "http://localhost:1323/register", data)
	assert.Equal(t, 200, res.StatusCode)
	body := readBody(res)
	assert.Contains(t, body, "Please check your email to verify your account")

	// Verify that a verification email was sent
	mockEmailService := controller.EmailService.(*MockEmailService)
	found := false
	for _, email := range mockEmailService.SentEmails {
		if email.Subject == "Verify your email address" && email.ToEmail == "newuser@example.com" {
			found = true
			break
		}
	}
	assert.True(t, found, "Verification email should have been sent")

	// Verify that a verification token was created
	tokens, err := controller.Store.FindVerificationTokenByEmail("newuser@example.com")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(tokens))
	assert.Equal(t, "registration", tokens[0].Type)
}

func TestRegistrationWithExistingVerifiedUser(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	// Create a verified user first
	createVerifiedTestUser(t, controller, "existing@example.com", "password")

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("email", "existing@example.com")
	data.Set("password", "newpassword")
	data.Set("confirmPassword", "newpassword")
	data.Set("altcha", "mock-solution")

	res := makePostRequest(t, client, "http://localhost:1323/register", data)
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Contains(t, locationHeader, "/login")

	// Verify that no verification email was sent
	mockEmailService := controller.EmailService.(*MockEmailService)
	for _, email := range mockEmailService.SentEmails {
		if email.Subject == "Verify your email address" && email.ToEmail == "existing@example.com" {
			t.Fatal("Verification email should not have been sent for existing verified user")
		}
	}
}

func TestRegistrationWithExistingUnverifiedUser(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	// Create an unverified user first
	createTestUserWithPassword(t, controller, "unverified@example.com", "password")

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("email", "unverified@example.com")
	data.Set("password", "newpassword")
	data.Set("confirmPassword", "newpassword")
	data.Set("altcha", "mock-solution")

	res := makePostRequest(t, client, "http://localhost:1323/register", data)
	assert.Equal(t, 200, res.StatusCode)
	body := readBody(res)
	assert.Contains(t, body, "Please check your email to verify your account")

	// Verify that a verification email was sent
	mockEmailService := controller.EmailService.(*MockEmailService)
	found := false
	for _, email := range mockEmailService.SentEmails {
		if email.Subject == "Verify your email address" && email.ToEmail == "unverified@example.com" {
			found = true
			break
		}
	}
	assert.True(t, found, "Verification email should have been sent for unverified user")
}

func TestRegistrationRequiresCaptcha(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("email", "newuser@example.com")
	data.Set("password", "newpassword")
	data.Set("confirmPassword", "newpassword")

	res := makePostRequest(t, client, "http://localhost:1323/register", data)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Contains(t, readBody(res), "Please complete the captcha")
}

func TestRegistrationRejectsFailedCaptcha(t *testing.T) {
	httpServer, controller := waitForServerWithDependencies(t, serverConfig, &MockEmailService{}, &MockCaptchaVerifier{
		VerifyResultConfigured: true,
		VerifyResult:           false,
	})
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("email", "newuser@example.com")
	data.Set("password", "newpassword")
	data.Set("confirmPassword", "newpassword")
	data.Set("altcha", "bad-solution")

	res := makePostRequest(t, client, "http://localhost:1323/register", data)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Contains(t, readBody(res), "Captcha verification failed")
}

func TestRegistrationHandlesCaptchaVerifierError(t *testing.T) {
	httpServer, controller := waitForServerWithDependencies(t, serverConfig, &MockEmailService{}, &MockCaptchaVerifier{
		VerifyErr: fmt.Errorf("captcha backend unavailable"),
	})
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("email", "newuser@example.com")
	data.Set("password", "newpassword")
	data.Set("confirmPassword", "newpassword")
	data.Set("altcha", "error-solution")

	res := makePostRequest(t, client, "http://localhost:1323/register", data)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Contains(t, readBody(res), "Captcha verification failed")
}

func TestRegistrationEmailDebouncing(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	email := "debounce@example.com"

	// First registration attempt
	data := url.Values{}
	data.Set("email", email)
	data.Set("password", "password")
	data.Set("confirmPassword", "password")
	data.Set("altcha", "mock-solution")

	res := makePostRequest(t, client, "http://localhost:1323/register", data)
	assert.Equal(t, 200, res.StatusCode)

	// Second registration attempt immediately after
	res = makePostRequest(t, client, "http://localhost:1323/register", data)
	// should be 429 (too many requests) because the email is debounced
	assert.Equal(t, 429, res.StatusCode)

	// Verify that only one verification email was sent
	mockEmailService := controller.EmailService.(*MockEmailService)
	count := 0
	for _, email := range mockEmailService.SentEmails {
		if email.Subject == "Verify your email address" && email.ToEmail == "debounce@example.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "Only one verification email should have been sent")
}

func TestRegistrationBlocksAfterTooManyFailedVerificationAttempts(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	emailAddress := "failed-verification@example.com"
	createTestUserWithPassword(t, controller, emailAddress, "password123")
	for i := 0; i < 5; i++ {
		createVerificationToken(t, controller, fmt.Sprintf("expired-%d", i), emailAddress, "registration", time.Now().Add(-48*time.Hour).Unix(), time.Now().Add(-24*time.Hour).Unix())
	}

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("email", emailAddress)
	data.Set("password", "newpassword")
	data.Set("confirmPassword", "newpassword")
	data.Set("altcha", "mock-solution")

	res := makePostRequest(t, client, "http://localhost:1323/register", data)
	assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
	assert.Contains(t, readBody(res), "Too many failed verification attempts")
}

func TestRegistrationBlocksWhenTooManyActiveVerificationLinksExist(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	emailAddress := "too-many-links@example.com"
	createTestUserWithPassword(t, controller, emailAddress, "password123")
	for i := 0; i < 3; i++ {
		createVerificationToken(t, controller, fmt.Sprintf("active-%d", i), emailAddress, "registration", time.Now().Add(-10*time.Minute).Unix(), time.Now().Add(24*time.Hour).Unix())
	}

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("email", emailAddress)
	data.Set("password", "newpassword")
	data.Set("confirmPassword", "newpassword")
	data.Set("altcha", "mock-solution")

	res := makePostRequest(t, client, "http://localhost:1323/register", data)
	assert.Equal(t, http.StatusTooManyRequests, res.StatusCode)
	assert.Contains(t, readBody(res), "Too many active verification links")
}

func TestRegistrationWithInvalidData(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()

	// Test cases
	testCases := []struct {
		name            string
		email           string
		password        string
		confirmPassword string
		expectedError   string
	}{
		{
			name:            "Empty email",
			email:           "",
			password:        "password",
			confirmPassword: "password",
			expectedError:   "All fields are required",
		},
		{
			name:            "Empty password",
			email:           "test@example.com",
			password:        "",
			confirmPassword: "",
			expectedError:   "All fields are required",
		},
		{
			name:            "Password too short",
			email:           "test@example.com",
			password:        "short",
			confirmPassword: "short",
			expectedError:   "Password must be at least 8 characters long",
		},
		{
			name:            "Passwords don't match",
			email:           "test@example.com",
			password:        "password1",
			confirmPassword: "password2",
			expectedError:   "Passwords do not match",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := url.Values{}
			data.Set("email", tc.email)
			data.Set("password", tc.password)
			data.Set("confirmPassword", tc.confirmPassword)
			data.Set("altcha", "mock-solution")

			res := makePostRequest(t, client, "http://localhost:1323/register", data)
			assert.Equal(t, 400, res.StatusCode)
			body := readBody(res)
			assert.Contains(t, body, tc.expectedError)

			// Verify that no verification email was sent
			mockEmailService := controller.EmailService.(*MockEmailService)
			for _, email := range mockEmailService.SentEmails {
				if email.Subject == "Verify your email address" && email.ToEmail == tc.email {
					t.Fatal("Verification email should not have been sent for invalid data")
				}
			}
		})
	}
}

func TestRegistrationVerification(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	// Create an unverified user and verification token
	email := "verify@example.com"
	createTestUserWithPassword(t, controller, email, "password")
	code := uuid.New().String()
	createVerificationToken(t, controller, code, email, "registration",
		time.Now().Unix(),
		time.Now().Add(24*time.Hour).Unix())

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("code", code)

	res := makePostRequest(t, client, "http://localhost:1323/verify", data)
	assert.Equal(t, 200, res.StatusCode)
	body := readBody(res)
	assert.Contains(t, body, "Verification successful")

	// Verify that the user is now verified
	user, err := controller.Store.FindUser(email)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, user.Verified, "User should be verified after verification")
}

func TestRegistrationVerificationWithInvalidToken(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("code", "invalid-token")

	res := makePostRequest(t, client, "http://localhost:1323/verify", data)
	assert.Equal(t, 400, res.StatusCode)
	body := readBody(res)
	assert.Contains(t, body, "Invalid or expired verification code")
}

func TestRegistrationVerificationWithExpiredToken(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	// Create an unverified user and expired verification token
	email := "expired@example.com"
	createTestUserWithPassword(t, controller, email, "password")
	token := uuid.New().String()
	createVerificationToken(t, controller, token, email, "registration",
		time.Now().Add(-48*time.Hour).Unix(),
		time.Now().Add(-24*time.Hour).Unix())

	client := createTestHttpClient()
	data := url.Values{}
	data.Set("code", token)

	res := makePostRequest(t, client, "http://localhost:1323/verify", data)
	assert.Equal(t, 400, res.StatusCode)
	body := readBody(res)
	assert.Contains(t, body, "Verification link has expired")

	// Verify that the user is still unverified
	user, err := controller.Store.FindUser(email)
	if err != nil {
		t.Fatal(err)
	}
	assert.False(t, user.Verified, "User should still be unverified after expired verification")
}

func TestLandingPage(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := createTestHttpClient()
	res := makeGetRequest(t, client, "http://localhost:1323/")
	assert.Equal(t, 200, res.StatusCode)
	body := readBody(res)

	// Verify landing page content
	assert.Contains(t, body, "Welcome to the OpenID Provider")
	assert.Contains(t, body, "href=\"/register\"")
	assert.Contains(t, body, "href=\"/forgot-password\"")
	assert.Contains(t, body, "href=\"/delete-account\"")
}

// Helper functions start here
type MockEmailService struct {
	SentEmails []struct {
		ToEmail string
		Subject string
		Content string
	}
}

var _ email.EmailSender = (*MockEmailService)(nil)

func (m *MockEmailService) SendVerificationEmail(toEmail, verificationLink string) error {
	m.SentEmails = append(m.SentEmails, struct {
		ToEmail string
		Subject string
		Content string
	}{
		ToEmail: toEmail,
		Subject: "Verify your email address",
		Content: verificationLink,
	})
	return nil
}

func (m *MockEmailService) SendPasswordResetEmail(toEmail, resetLink string) error {
	m.SentEmails = append(m.SentEmails, struct {
		ToEmail string
		Subject string
		Content string
	}{
		ToEmail: toEmail,
		Subject: "Reset your password",
		Content: resetLink,
	})
	return nil
}

func (m *MockEmailService) SendDeleteAccountEmail(toEmail, deleteLink string) error {
	m.SentEmails = append(m.SentEmails, struct {
		ToEmail string
		Subject string
		Content string
	}{
		ToEmail: toEmail,
		Subject: "Delete your account",
		Content: deleteLink,
	})
	return nil
}

// MockCaptchaVerifier implements CaptchaVerifier for testing
type MockCaptchaVerifier struct {
	Challenge              string
	ChallengeErr           error
	VerifyResult           bool
	VerifyResultConfigured bool
	VerifyErr              error
}

var _ server.CaptchaVerifier = (*MockCaptchaVerifier)(nil)

func (m *MockCaptchaVerifier) CreateChallenge() (string, error) {
	if m.ChallengeErr != nil {
		return "", m.ChallengeErr
	}
	if m.Challenge != "" {
		return m.Challenge, nil
	}
	// Return a mock challenge JSON for testing
	return `{"algorithm":"SHA-256","challenge":"mock-challenge","salt":"mock-salt","signature":"mock-signature"}`, nil
}

func (m *MockCaptchaVerifier) VerifySolution(solution string) (bool, error) {
	if m.VerifyErr != nil {
		return false, m.VerifyErr
	}
	if m.VerifyResultConfigured {
		return m.VerifyResult, nil
	}
	// Always return true for testing - this allows tests to pass without solving captcha
	return true, nil
}

var activeHandler http.Handler

func waitForServer(t *testing.T) (*http.Server, server.Controller) {
	loadKeys(t)
	return waitForServerWithDependencies(t, serverConfig, &MockEmailService{}, &MockCaptchaVerifier{})
}

func waitForServerWithDependencies(t *testing.T, config domain.Configuration, emailService email.EmailSender, captchaVerifier server.CaptchaVerifier) (*http.Server, server.Controller) {
	fmt.Printf("DEBUG: Starting waitForServer\n")
	loadKeys(t)
	if config.JwtConfig.PrivateKey == nil || config.JwtConfig.PublicKey == nil {
		config.JwtConfig.PrivateKey = serverConfig.JwtConfig.PrivateKey
		config.JwtConfig.PublicKey = serverConfig.JwtConfig.PublicKey
	}
	var store repository.Store
	fmt.Printf("DEBUG: Initializing database\n")
	err := store.InitAndVerifyDb(repository.CreateInMemoryDbUrl())
	if err != nil {
		fmt.Printf("DEBUG: Error initializing database: %v\n", err)
		panic(err)
	}
	fmt.Printf("DEBUG: Database initialized successfully\n")
	controller := server.Controller{
		Store:           &store,
		Config:          config,
		EmailService:    emailService,
		CaptchaVerifier: captchaVerifier,
	}
	fmt.Printf("DEBUG: Creating handler\n")
	activeHandler = server.InitServer(controller)
	fmt.Printf("DEBUG: Server handler ready\n")
	return nil, controller
}

func cleanupTest(t *testing.T, httpServer *http.Server, controller server.Controller) {
	// First stop the cleanup job if it exists
	if controller.CleanupJob != nil {
		controller.CleanupJob.Stop()
		// Give it a moment to finish any ongoing operations
		time.Sleep(100 * time.Millisecond)
	}
	// Then close the HTTP server
	if httpServer != nil {
		if err := httpServer.Close(); err != nil {
			t.Errorf("Error closing server: %v", err)
		}
	}
	// Finally close the database
	if err := controller.Store.Close(); err != nil {
		t.Errorf("Error closing database: %v", err)
	}
	activeHandler = nil
}

func createAuthorizeUrl(t *testing.T, scopes string) *url.URL {
	return createAuthorizeUrlForClient(t, TestClientid, TestRedirectUri, scopes)
}

func createAuthorizeUrlForClient(t *testing.T, clientId, redirectUri, scopes string) *url.URL {
	authorizeUrl, err := url.Parse(AuthorizeUrl)
	if err != nil {
		t.Fatal(err)
	}
	query := authorizeUrl.Query()
	query.Set("scope", scopes)
	query.Set("client_id", clientId)
	query.Set("response_type", "code")
	query.Set("redirect_uri", redirectUri)
	query.Set("state", TestState)
	authorizeUrl.RawQuery = query.Encode()
	return authorizeUrl
}

func makeGetRequest(t *testing.T, client *http.Client, url string) *http.Response {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func makePostRequest(t *testing.T, client *http.Client, url string, data url.Values) *http.Response {
	req, err := http.NewRequest("POST", url, strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	setRequiredFormPostHeaders(req)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func setRequiredFormPostHeaders(req *http.Request) {
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", "http://"+req.Host)
}

func performAuthorizeAndLogin(t *testing.T, client *http.Client, password string) *http.Response {
	return performAuthorizeAndLoginForClient(t, client, TestClientid, TestRedirectUri, TestUsername, password, "openid profile")
}

func performAuthorizeAndLoginForClient(t *testing.T, client *http.Client, clientId, redirectUri, username, password, scopes string) *http.Response {
	authorizeUrl := createAuthorizeUrlForClient(t, clientId, redirectUri, scopes)
	res := makeGetRequest(t, client, authorizeUrl.String())
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Contains(t, locationHeader, "/login")
	assert.Contains(t, locationHeader, "client_id="+clientId)
	assert.Contains(t, locationHeader, "redirect_uri="+url.QueryEscape(redirectUri))
	assert.Contains(t, locationHeader, "state="+TestState)

	// Perform the login
	data := url.Values{}
	data.Set("clientid", clientId)
	data.Set("username", username)
	data.Set("password", password)
	data.Set("redirecturi", redirectUri)
	data.Set("state", TestState)
	data.Set("scope", scopes)
	return makePostRequest(t, client, LoginUrl, data)
}

func createTestHttpClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	if activeHandler == nil {
		panic("active handler is not initialized")
	}
	return &http.Client{
		Jar: jar,
		// we need to prevent the client from redirecting automatically since we may need to assert
		// against the location header
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &handlerTransport{handler: activeHandler},
	}
}

type handlerTransport struct {
	handler http.Handler
}

// Simulate the client/server interaction entirely in memory by cloning the
// outgoing request, replaying its body into the test handler, and returning
// the recorder's response as if it came over the network.
func (t *handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.handler == nil {
		return nil, fmt.Errorf("handler not initialized")
	}
	var bodyBytes []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
	}
	if req.Body != nil {
		req.Body.Close()
	}
	clone := req.Clone(req.Context())
	if len(bodyBytes) > 0 {
		clone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		clone.ContentLength = int64(len(bodyBytes))
	} else {
		clone.Body = http.NoBody
		clone.ContentLength = 0
	}
	clone.RemoteAddr = "127.0.0.1:0"
	clone.RequestURI = req.URL.RequestURI()

	if len(bodyBytes) > 0 {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	} else {
		req.Body = http.NoBody
	}

	recorder := httptest.NewRecorder()
	t.handler.ServeHTTP(recorder, clone)
	resp := recorder.Result()
	resp.Request = req
	return resp, nil
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

func createEndpointUrl(endpoint string) (*url.URL, error) {
	return url.Parse("http://localhost:1323" + endpoint)
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

func createTestUserWithPassword(t *testing.T, controller server.Controller, username, password string) {
	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	err = controller.Store.CreateUser(username, hashedPassword)
	if err != nil {
		t.Fatal(err)
	}
}

func createVerifiedTestUser(t *testing.T, controller server.Controller, username, password string) {
	createTestUserWithPassword(t, controller, username, password)
	err := controller.Store.VerifyUser(username)
	if err != nil {
		t.Fatal(err)
	}
}

func createVerificationToken(t *testing.T, controller server.Controller, token, email, tokenType string, created, expires int64) {
	verificationToken := repository.VerificationToken{
		Token:   token,
		Email:   email,
		Type:    tokenType,
		Created: created,
		Expires: expires,
	}
	err := controller.Store.CreateVerificationToken(verificationToken)
	if err != nil {
		t.Fatal(err)
	}
}

func createPasswordResetToken(t *testing.T, controller server.Controller, token, email string, created, expires int64) {
	createVerificationToken(t, controller, token, email, "password_reset", created, expires)
}

func createDeleteAccountToken(t *testing.T, controller server.Controller, token, email string, created, expires int64) {
	createVerificationToken(t, controller, token, email, "delete_account", created, expires)
}

func authorizeAndExchangeTokensForClient(t *testing.T, client *http.Client, clientId, secret, redirectUri, scopes string) oauthTokenResponse {
	loginResponse := performAuthorizeAndLoginForClient(t, client, clientId, redirectUri, TestUsername, TestPassword, scopes)
	assert.Equal(t, http.StatusFound, loginResponse.StatusCode)

	locationHeader := loginResponse.Header.Get("Location")
	assert.NotEmpty(t, locationHeader)

	code := authorizationCodeFromRedirect(t, locationHeader)
	tokenResponse, response := exchangeAuthorizationCodeForTokens(t, client, clientId, secret, redirectUri, code)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	return tokenResponse
}

func authorizationCodeFromRedirect(t *testing.T, locationHeader string) string {
	parsedURL, err := url.Parse(locationHeader)
	if err != nil {
		t.Fatal(err)
	}
	params, err := url.ParseQuery(parsedURL.RawQuery)
	if err != nil {
		t.Fatal(err)
	}
	return params.Get("code")
}

func exchangeAuthorizationCodeForTokens(t *testing.T, client *http.Client, clientId, secret, redirectUri, code string) (oauthTokenResponse, *http.Response) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectUri)

	response, tokenResponse, err := doTokenRequest(client, clientId, secret, data)
	if err != nil {
		t.Fatal(err)
	}
	return tokenResponse, response
}

func refreshTokensForClient(t *testing.T, client *http.Client, clientId, secret, refreshToken string) (oauthTokenResponse, *http.Response) {
	response, tokenResponse, err := refreshTokensForClientRequest(client, clientId, secret, refreshToken)
	if err != nil {
		t.Fatal(err)
	}
	return tokenResponse, response
}

func refreshTokensForClientRequest(client *http.Client, clientId, secret, refreshToken string) (*http.Response, oauthTokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	return doTokenRequest(client, clientId, secret, data)
}

func revokeRefreshTokenForClient(t *testing.T, client *http.Client, clientId, secret, refreshToken string) *http.Response {
	endpoint, err := createEndpointUrl("/revoke")
	if err != nil {
		t.Fatal(err)
	}

	data := url.Values{}
	data.Set("token", refreshToken)

	req, err := http.NewRequest("POST", endpoint.String(), strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(clientId, secret)
	setRequiredFormPostHeaders(req)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func doTokenRequest(client *http.Client, clientId, secret string, data url.Values) (*http.Response, oauthTokenResponse, error) {
	tokenURL, err := createEndpointUrl("/token")
	if err != nil {
		return nil, oauthTokenResponse{}, err
	}

	req, err := http.NewRequest("POST", tokenURL.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, oauthTokenResponse{}, err
	}
	req.SetBasicAuth(clientId, secret)
	setRequiredFormPostHeaders(req)

	response, err := client.Do(req)
	if err != nil {
		return nil, oauthTokenResponse{}, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, oauthTokenResponse{}, err
	}

	var tokenResponse oauthTokenResponse
	if len(body) > 0 {
		if err := json.Unmarshal(body, &tokenResponse); err != nil {
			return nil, oauthTokenResponse{}, err
		}
	}

	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, tokenResponse, nil
}

func createStoredRefreshToken(t *testing.T, controller server.Controller, email, clientId, scopes, familyId string, createdAt, expiresAt time.Time) string {
	return createStoredRefreshTokenRecord(t, controller, email, clientId, scopes, familyId, createdAt, expiresAt, sql.NullInt64{}, sql.NullInt64{})
}

func createStoredRefreshTokenRecord(t *testing.T, controller server.Controller, email, clientId, scopes, familyId string, createdAt, expiresAt time.Time, rotatedAt, revokedAt sql.NullInt64) string {
	rawToken, err := tokenutil.GenerateOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}

	err = controller.Store.CreateRefreshToken(repository.RefreshToken{
		TokenHash:       tokenutil.HashOpaqueToken(rawToken),
		TokenHintPrefix: tokenutil.TokenHintPrefix(rawToken),
		FamilyId:        familyId,
		ClientId:        clientId,
		Email:           email,
		Scopes:          scopes,
		AuthTime:        createdAt.Unix(),
		CreatedAt:       createdAt.Unix(),
		ExpiresAt:       expiresAt.Unix(),
		RotatedAt:       rotatedAt,
		RevokedAt:       revokedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rawToken
}

func decodeIdTokenClaims(token string, publicKey *rsa.PublicKey) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return publicKey, nil
	})
	return claims, err
}
