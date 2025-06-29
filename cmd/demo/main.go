package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	publicHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Demo App - Welcome</title>
</head>
<body>
    <header>
        <h1>Demo App</h1>
        <nav>
            <a href="/">Home</a> |
            <a href="/protected">Dashboard</a> |
			<a href="/emails">Mock Emails</a>
        </nav>
    </header>

    <main>
        <h2>Welcome to the Demo App</h2>
        <p>This is a simple demo application that demonstrates OpenID Connect authentication.</p>
        <p>The "Log In" link will navigate to a page that requires authentication and will trigger the OIDC authorization code flow if you are not already logged in.</p>
        <a href="/protected">Log In</a>
    </main>
</body>
</html>`

	protectedHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Demo App - Protected Page</title>
</head>
<body>
    <header>
        <h1>Demo App</h1>
        <nav>
            <a href="/">Home</a> |
            <a href="/protected">Protected Page</a> |
			<a href="/emails">Mock Emails</a> |
            <a href="/logout">Log Out</a>
        </nav>
    </header>

    <main>
        <h2>Protected Page</h2>
        
        <section>
            <h3>User Information</h3>
            <div>{{.Email}}</div>
        </section>

        <section>
            <h3>ID Token Claims</h3>
            <pre>{{.ClaimsJSON}}</pre>
        </section>
    </main>
</body>
</html>`

	protectedPath = "/protected"

	emailDisplayHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Demo App - Mock Emails</title>
</head>
<body>
    <header>
        <h1>Demo App</h1>
        <nav>
            <a href="/">Home</a> |
            <a href="/protected">Protected Page</a> |
			<a href="/emails">Mock Emails</a>
        </nav>
    </header>

    <main>
        <h2>Mock Emails</h2>
        {{range .Emails}}
        <div class="email-card">
            <div class="email-header">
                <div class="email-subject">{{.Subject}}</div>
                <div class="email-meta">
                    To: {{.To}}<br>
                    Time: {{.Time}}
                </div>
            </div>
            <div class="email-body">{{.Body}}</div>
        </div>
        {{end}}
    </main>
</body>
</html>`
)

type Config struct {
	Port           int    `json:"port"`
	OpenIDProvider string `json:"openid_provider"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	RedirectURI    string `json:"redirect_uri"`
}

type OpenIDProviderConfig struct {
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	UserInfoEndpoint         string   `json:"userinfo_endpoint"`
	JwksURI                  string   `json:"jwks_uri"`
	ResponseTypes            []string `json:"response_types_supported"`
	SubjectTypes             []string `json:"subject_types_supported"`
	IDTokenSigningAlgs       []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported          []string `json:"scopes_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
}

type PageData struct {
	Email      string
	ClaimsJSON string
}

type Email struct {
	To      string    `json:"to"`
	Subject string    `json:"subject"`
	Body    string    `json:"body"`
	Time    time.Time `json:"time"`
}

type EmailPageData struct {
	Emails []Email
}

var (
	publicTemplate    = template.Must(template.New("public").Parse(publicHTML))
	protectedTemplate = template.Must(template.New("protected").Parse(protectedHTML))
	emailTemplate     = template.Must(template.New("emails").Parse(emailDisplayHTML))
	mockEmails        = make([]Email, 0)
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	slog.Info("Starting demo server")

	configFile := flag.String("config", "demo-config.json", "Path to configuration file")
	flag.Parse()

	// Read configuration
	config := readConfig(*configFile)
	slog.Info("Loaded configuration from ", "configFile", *configFile)

	// Get OpenID Provider configuration
	providerConfig, err := getOpenIDProviderConfig(config.OpenIDProvider)
	if err != nil {
		log.Fatalf("Error getting OpenID Provider configuration: %v", err)
	}
	slog.Info("Successfully retrieved OpenID Provider configuration from ", "provider", config.OpenIDProvider)

	// Routes
	http.HandleFunc("/", handlePublic)
	http.HandleFunc(protectedPath, handleProtected)
	http.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		handleLogin(w, r, config, providerConfig)
	})
	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		handleCallback(w, r, config, providerConfig)
	})
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/emails", handleEmails)

	slog.Info("Starting demo server on port ", "port", config.Port)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func getOpenIDProviderConfig(providerURL string) (*OpenIDProviderConfig, error) {
	// Construct the discovery URL
	discoveryURL := strings.TrimRight(providerURL, "/") + "/.well-known/openid-configuration"
	slog.Info("Fetching OpenID Provider configuration from: ", "discoveryURL", discoveryURL)

	// Fetch the configuration
	resp, err := http.Get(discoveryURL)
	if err != nil {
		slog.Error("Error fetching provider configuration: ", "error", err)
		return nil, fmt.Errorf("error fetching provider configuration: %v", err)
	}
	defer resp.Body.Close()

	slog.Info("Provider configuration response status: ", "status", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider returned status code %d", resp.StatusCode)
	}

	var config OpenIDProviderConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		slog.Error("Error parsing provider configuration: ", "error", err)
		return nil, fmt.Errorf("error parsing provider configuration: %v", err)
	}

	slog.Info("Successfully parsed provider configuration")
	return &config, nil
}

func readConfig(path string) Config {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(file, &config); err != nil {
		log.Fatalf("Error parsing config file: %v", err)
	}

	return config
}

func handlePublic(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handling public request: ", "method", r.Method, "path", r.URL.Path)
	publicTemplate.Execute(w, nil)
}

func handleProtected(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handling protected request: ", "method", r.Method, "path", r.URL.Path)

	// Check if user is authenticated
	session, err := r.Cookie("session")
	if err != nil || session.Value == "" {
		slog.Error("No valid session found, redirecting to login")
		http.Redirect(w, r, "/auth/login", http.StatusTemporaryRedirect)
		return
	}

	// Parse the ID token
	claims, err := parseToken(session.Value)
	if err != nil {
		slog.Error("Error parsing token: ", "error", err)
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	// Format claims as pretty JSON
	claimsJSON, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		slog.Error("Error formatting claims: ", "error", err)
		http.Error(w, "Error formatting claims", http.StatusInternalServerError)
		return
	}

	// Get email from claims, defaulting to subject if email is not present
	email := claims["sub"].(string) // sub is always present in ID tokens
	if emailClaim, ok := claims["email"].(string); ok {
		email = emailClaim
	}

	// Prepare template data
	data := PageData{
		Email:      email,
		ClaimsJSON: string(claimsJSON),
	}

	slog.Info("Rendering protected page for user: ", "email", data.Email)
	protectedTemplate.Execute(w, data)
}

func handleLogin(w http.ResponseWriter, r *http.Request, config Config, providerConfig *OpenIDProviderConfig) {
	slog.Info("Handling login request: ", "method", r.Method, "path", r.URL.Path)

	// Construct the authorization URL
	params := url.Values{}
	params.Add("client_id", config.ClientID)
	params.Add("redirect_uri", config.RedirectURI)
	params.Add("response_type", "code")
	params.Add("scope", "openid email profile")

	authURL := providerConfig.AuthorizationEndpoint + "?" + params.Encode()
	slog.Info("Redirecting to authorization endpoint: ", "authURL", authURL)

	// Redirect to the OpenID Provider
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request, config Config, providerConfig *OpenIDProviderConfig) {
	slog.Info("Handling callback request: ", "method", r.Method, "path", r.URL.Path)

	// Handle OAuth callback
	code := r.URL.Query().Get("code")
	if code == "" {
		slog.Error("No authorization code provided in callback")
		http.Error(w, "No code provided", http.StatusBadRequest)
		return
	}
	slog.Info("Received authorization code")

	// Exchange code for token
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", config.RedirectURI)

	// Create request with Basic Auth
	req, err := http.NewRequest("POST", providerConfig.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		slog.Error("Error creating token request: ", "error", err)
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	// Set Basic Auth header
	auth := base64.StdEncoding.EncodeToString([]byte(config.ClientID + ":" + config.ClientSecret))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	slog.Info("Making token request to: ", "tokenEndpoint", providerConfig.TokenEndpoint)

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Error making token request: ", "error", err)
		http.Error(w, "Error exchanging code for token", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	slog.Info("Token endpoint response status: ", "status", resp.StatusCode)

	var tokenResponse struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		slog.Error("Error parsing token response: ", "error", err)
		http.Error(w, "Error parsing token response", http.StatusInternalServerError)
		return
	}

	slog.Info("Successfully received ID token")

	// Store the ID token in a session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    tokenResponse.IDToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	slog.Info("Setting session cookie and redirecting to protected page")
	http.Redirect(w, r, "/protected", http.StatusTemporaryRedirect)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handling logout request: ", "method", r.Method, "path", r.URL.Path)

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	slog.Info("Cleared session cookie and redirecting to home page")
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func parseToken(token string) (map[string]interface{}, error) {
	slog.Info("Parsing ID token")

	// Split the token into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		slog.Error("Invalid token format: expected 3 parts, got ", "parts", len(parts))
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode the claims (second part of the JWT)
	claimsJSON, err := base64Decode(parts[1])
	if err != nil {
		slog.Error("Error decoding token: ", "error", err)
		return nil, fmt.Errorf("error decoding token: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		slog.Error("Error parsing claims: ", "error", err)
		return nil, fmt.Errorf("error parsing claims: %v", err)
	}

	slog.Info("Successfully parsed token claims")
	return claims, nil
}

func base64Decode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	// Replace URL-safe characters
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	return base64.StdEncoding.DecodeString(s)
}

func handleEmails(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handling emails request: ", "method", r.Method, "path", r.URL.Path)

	switch r.Method {
	case http.MethodGet:
		// Sort emails by time in reverse chronological order
		sortedEmails := make([]Email, len(mockEmails))
		copy(sortedEmails, mockEmails)
		sort.Slice(sortedEmails, func(i, j int) bool {
			return sortedEmails[i].Time.After(sortedEmails[j].Time)
		})

		data := EmailPageData{
			Emails: sortedEmails,
		}

		emailTemplate.Execute(w, data)

	case http.MethodPost:
		var email Email
		if err := json.NewDecoder(r.Body).Decode(&email); err != nil {
			slog.Error("Error decoding email: ", "error", err)
			http.Error(w, "Invalid email data", http.StatusBadRequest)
			return
		}

		email.Time = time.Now()
		mockEmails = append(mockEmails, email)

		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
