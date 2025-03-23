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
}

type SendgridConfiguration struct {
	APIKey    string
	FromEmail string
	FromName  string
}

type CleanupConfiguration struct {
	UnverifiedUserMaxAge time.Duration
	CleanupInterval      time.Duration
}

// OpenIdConfiguration This represents the document served at /.well-known/openid-configuration
type OpenIdConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	// UserInfoEndpoint string `json:"userinfo_endpoint"`
	JwksUri                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}
