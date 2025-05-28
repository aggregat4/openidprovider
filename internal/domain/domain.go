package domain

import (
	"crypto/rsa"
	"time"
)

type ClientId = string

type Client struct {
	Id              ClientId
	RedirectUris    []string
	BasicAuthSecret string
}

type JwtConfiguration struct {
	Issuer                 string
	IdTokenValidityMinutes int
	PrivateKey             *rsa.PrivateKey
	PublicKey              *rsa.PublicKey
}

type Configuration struct {
	DatabaseFilename          string
	ServerReadTimeoutSeconds  int
	ServerWriteTimeoutSeconds int
	ServerPort                int
	BaseUrl                   string
	RegisteredClients         map[ClientId]Client
	JwtConfig                 JwtConfiguration
	SendgridConfig            SendgridConfiguration
	CleanupConfig             CleanupConfiguration
	MockEmailDemoServerURL    string
}

type SendgridConfiguration struct {
	APIKey    string
	FromEmail string
	FromName  string
	RateLimit struct {
		MaxEmailsPerDay     int           `json:"maxEmailsPerDay"`
		MaxEmailsPerAddress int           `json:"maxEmailsPerAddress"`
		BackoffPeriod       time.Duration `json:"backoffPeriod"`
		BlockPeriod         time.Duration `json:"blockPeriod"`
	} `json:"rateLimit"`
}

type CleanupConfiguration struct {
	UnverifiedUserMaxAge time.Duration
	CleanupInterval      time.Duration
}

// OpenIdConfiguration This represents the document served at /.well-known/openid-configuration
type OpenIdConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JwksUri                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

// ScopeConfiguration represents a scope and its associated claims
type ScopeConfiguration struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Claims      []string `json:"claims"`
}
