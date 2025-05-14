package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
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
            <a href="/protected">Dashboard</a>
        </nav>
    </header>

    <main>
        <h2>Welcome to the Demo App</h2>
        <p>This is a simple demo application that demonstrates OpenID Connect authentication.</p>
        <p>Click the button below to log in using the OpenID Provider.</p>
        <a href="/auth/login">Log In</a>
    </main>
</body>
</html>`

	protectedHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Demo App - Dashboard</title>
</head>
<body>
    <header>
        <h1>Demo App</h1>
        <nav>
            <a href="/">Home</a> |
            <a href="/protected">Dashboard</a> |
            <a href="/logout">Log Out</a>
        </nav>
    </header>

    <main>
        <h2>Dashboard</h2>
        
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

var (
	publicTemplate    = template.Must(template.New("public").Parse(publicHTML))
	protectedTemplate = template.Must(template.New("protected").Parse(protectedHTML))
)

func main() {
	configFile := flag.String("config", "demo-config.json", "Path to configuration file")
	flag.Parse()

	// Read configuration
	config := readConfig(*configFile)

	// Get OpenID Provider configuration
	providerConfig, err := getOpenIDProviderConfig(config.OpenIDProvider)
	if err != nil {
		log.Fatalf("Error getting OpenID Provider configuration: %v", err)
	}

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

	log.Printf("Starting demo server on port %d", config.Port)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func getOpenIDProviderConfig(providerURL string) (*OpenIDProviderConfig, error) {
	// Construct the discovery URL
	discoveryURL := strings.TrimRight(providerURL, "/") + "/.well-known/openid-configuration"

	// Fetch the configuration
	resp, err := http.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("error fetching provider configuration: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider returned status code %d", resp.StatusCode)
	}

	var config OpenIDProviderConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("error parsing provider configuration: %v", err)
	}

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
	publicTemplate.Execute(w, nil)
}

func handleProtected(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated
	session, err := r.Cookie("session")
	if err != nil || session.Value == "" {
		// Redirect to login
		http.Redirect(w, r, "/auth/login", http.StatusTemporaryRedirect)
		return
	}

	// Parse the ID token
	claims, err := parseToken(session.Value)
	if err != nil {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	// Format claims as pretty JSON
	claimsJSON, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		http.Error(w, "Error formatting claims", http.StatusInternalServerError)
		return
	}

	// Prepare template data
	data := PageData{
		Email:      claims["email"].(string),
		ClaimsJSON: string(claimsJSON),
	}

	// Render template
	protectedTemplate.Execute(w, data)
}

func handleLogin(w http.ResponseWriter, r *http.Request, config Config, providerConfig *OpenIDProviderConfig) {
	// Construct the authorization URL
	params := url.Values{}
	params.Add("client_id", config.ClientID)
	params.Add("redirect_uri", config.RedirectURI)
	params.Add("response_type", "code")
	params.Add("scope", "openid email profile")

	// Redirect to the OpenID Provider
	http.Redirect(w, r, providerConfig.AuthorizationEndpoint+"?"+params.Encode(), http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request, config Config, providerConfig *OpenIDProviderConfig) {
	// Handle OAuth callback
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code provided", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", config.RedirectURI)
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)

	resp, err := http.PostForm(providerConfig.TokenEndpoint, data)
	if err != nil {
		http.Error(w, "Error exchanging code for token", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var tokenResponse struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		http.Error(w, "Error parsing token response", http.StatusInternalServerError)
		return
	}

	// Store the ID token in a session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    tokenResponse.IDToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/protected", http.StatusTemporaryRedirect)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func parseToken(token string) (map[string]interface{}, error) {
	// Split the token into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode the claims (second part of the JWT)
	claimsJSON, err := base64Decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("error decoding token: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("error parsing claims: %v", err)
	}

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
