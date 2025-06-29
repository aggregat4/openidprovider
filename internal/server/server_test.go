package server_test

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/repository"
	"aggregat4/openidprovider/internal/server"
	"aggregat4/openidprovider/pkg/email"
	"crypto/rand"
	"crypto/rsa"

	"github.com/aggregat4/go-baselib/crypto"

	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"

	"github.com/google/uuid"
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

// Test functions start here
func TestAuthorizeWithoutParameters(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)
	client := createTestHttpClient()
	res := makeGetRequest(t, client, AuthorizeUrl)
	assert.Equal(t, 400, res.StatusCode)
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

func TestLoginPageGet(t *testing.T) {
	httpServer, controller := waitForServer(t)
	defer cleanupTest(t, httpServer, controller)

	client := &http.Client{}
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

func TestGenerateValidIdToken(t *testing.T) {
	loadKeys(t)
	token, err := server.GenerateIdToken(serverConfig.JwtConfig, TestClientid, TestUsername, map[string]interface{}{})
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
	}, TestClientid, TestUsername, map[string]interface{}{})
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

	client := &http.Client{}
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
type MockCaptchaVerifier struct{}

var _ server.CaptchaVerifier = (*MockCaptchaVerifier)(nil)

func (m *MockCaptchaVerifier) CreateChallenge() (string, error) {
	// Return a mock challenge JSON for testing
	return `{"algorithm":"SHA-256","challenge":"mock-challenge","salt":"mock-salt","signature":"mock-signature"}`, nil
}

func (m *MockCaptchaVerifier) VerifySolution(solution string) (bool, error) {
	// Always return true for testing - this allows tests to pass without solving captcha
	return true, nil
}

func waitForServer(t *testing.T) (*http.Server, server.Controller) {
	fmt.Printf("DEBUG: Starting waitForServer\n")
	loadKeys(t)
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
		Config:          serverConfig,
		EmailService:    &MockEmailService{},
		CaptchaVerifier: &MockCaptchaVerifier{},
	}
	fmt.Printf("DEBUG: Creating server\n")
	chiController := server.NewChiController(&controller)
	chiServer := server.InitChiServer(chiController)

	httpServer := &http.Server{
		Addr:         ":" + strconv.Itoa(serverConfig.ServerPort),
		Handler:      chiServer,
		ReadTimeout:  time.Duration(serverConfig.ServerReadTimeoutSeconds) * time.Second,
		WriteTimeout: time.Duration(serverConfig.ServerWriteTimeoutSeconds) * time.Second,
	}

	fmt.Printf("DEBUG: Starting server\n")
	go func() {
		_ = httpServer.ListenAndServe()
	}()
	fmt.Printf("DEBUG: Waiting for server to start\n")
	waitForServerStart(t, "http://localhost:"+strconv.Itoa(serverConfig.ServerPort)+"/status")
	fmt.Printf("DEBUG: Server started successfully\n")
	return httpServer, controller
}

func cleanupTest(t *testing.T, httpServer *http.Server, controller server.Controller) {
	// First stop the cleanup job if it exists
	if controller.CleanupJob != nil {
		controller.CleanupJob.Stop()
		// Give it a moment to finish any ongoing operations
		time.Sleep(100 * time.Millisecond)
	}
	// Then close the HTTP server
	if err := httpServer.Close(); err != nil {
		t.Errorf("Error closing server: %v", err)
	}
	// Finally close the database
	if err := controller.Store.Close(); err != nil {
		t.Errorf("Error closing database: %v", err)
	}
}

func createAuthorizeUrl(t *testing.T, scopes string) *url.URL {
	authorizeUrl, err := url.Parse(AuthorizeUrl)
	if err != nil {
		t.Fatal(err)
	}
	query := authorizeUrl.Query()
	query.Set("scope", scopes)
	query.Set("client_id", TestClientid)
	query.Set("response_type", "code")
	query.Set("redirect_uri", TestRedirectUri)
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
	authorizeUrl := createAuthorizeUrl(t, "openid profile")
	res := makeGetRequest(t, client, authorizeUrl.String())
	assert.Equal(t, 302, res.StatusCode)
	locationHeader := res.Header.Get("Location")
	assert.Contains(t, locationHeader, "/login")
	assert.Contains(t, locationHeader, "client_id="+TestClientid)
	assert.Contains(t, locationHeader, "redirect_uri="+url.QueryEscape(TestRedirectUri))
	assert.Contains(t, locationHeader, "state="+TestState)

	// Perform the login
	data := url.Values{}
	data.Set("clientid", TestClientid)
	data.Set("username", TestUsername)
	data.Set("password", password)
	data.Set("redirecturi", TestRedirectUri)
	data.Set("state", TestState)
	data.Set("scope", "openid profile")
	return makePostRequest(t, client, LoginUrl, data)
}

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

func decodeIdTokenClaims(token string, publicKey *rsa.PublicKey) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	return claims, err
}
