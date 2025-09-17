package config

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/logging"
	"fmt"
	"time"

	"github.com/aggregat4/go-baselib/crypto"
	"github.com/kirsle/configdir"
	"github.com/knadh/koanf/parsers/hjson"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

var logger = logging.ForComponent("internal.config")

func GetDefaultConfigPath() string {
	return configdir.LocalConfig("openidprovider") + "/openidprovider.json"
}

func ReadConfig(configFileLocation string) domain.Configuration {
	k := koanf.New(".")
	if err := k.Load(file.Provider(configFileLocation), hjson.Parser()); err != nil {
		logging.Fatal(logger, "Error logging config file from {configFileLocation}")
	}

	databaseFilename := k.String("databasefilename")
	if databaseFilename == "" {
		logging.Fatal(logger, "Database filename is required in the configuration")
	}
	serverReadTimeoutSeconds := k.Int("serverreadtimeoutseconds")
	if serverReadTimeoutSeconds == 0 {
		serverReadTimeoutSeconds = 5
	}
	serverWriteTimeoutSeconds := k.Int("serverwritetimeoutseconds")
	if serverWriteTimeoutSeconds == 0 {
		serverWriteTimeoutSeconds = 10
	}
	serverPort := k.Int("serverport")
	if serverPort == 0 {
		serverPort = 1323
	}
	baseUrl := k.String("baseurl")
	if baseUrl == "" {
		logging.Fatal(logger, "Base URL is required in the configuration")
	}
	privateKeyPemFilename := k.String("privatekeypemfilename")
	if privateKeyPemFilename == "" {
		logging.Fatal(logger, "Private key filename is required in the configuration")
	}
	privateKey, err := crypto.ReadRSAPrivateKey(privateKeyPemFilename)
	if err != nil {
		logging.Fatal(logger, "Error reading private key file: {Error}", err)
	}

	publicKeyPemFilename := k.String("publickeypemfilename")
	if publicKeyPemFilename == "" {
		logging.Fatal(logger, "Public key filename is required in the configuration")
	}
	publicKey, err := crypto.ReadRSAPublicKey(publicKeyPemFilename)
	if err != nil {
		logging.Fatal(logger, "Error reading public key file: {Error}", err)
	}

	configuredClients := k.Get("registeredclients")
	// NOTE: I tried casting to `[]map[string]any` but that did not work, even though that is the type
	// Apparently go does not have that information yet. Instead, this is a generic object here and later in the
	// loop we cast the objects to a `map[string]any`
	clients, ok := configuredClients.([]any)
	if !ok {
		logging.Fatal(logger, "registeredclients is not an array of objects")
	}
	registeredClients := make(map[domain.ClientId]domain.Client)
	for _, client := range clients {
		client, ok := client.(map[string]any)
		if !ok {
			logging.Fatal(logger, "client is not an object")
		}
		clientId := client["id"].(string)
		if !ok {
			logging.Fatal(logger, "client id is not a string")
		}
		// NOTE: again we can not cast to `[]string` yet, we do that later for each individual redirect uri
		redirectUris, ok := client["redirecturis"].([]any)
		if !ok {
			logging.Fatal(logger, "redirect uris is not an array")
		}
		redirectUrisString := make([]string, len(redirectUris))
		for i, uri := range redirectUris {
			uri, ok := uri.(string)
			if !ok {
				logging.Fatal(logger, "redirect uri is not a string")
			}
			redirectUrisString[i] = uri
		}
		basicAuthSecret, ok := client["basicauthsecret"].(string)
		if !ok {
			logging.Fatal(logger, "basic auth secret is not a string")
		}
		registeredClients[clientId] = domain.Client{
			Id:              clientId,
			RedirectUris:    redirectUrisString,
			BasicAuthSecret: basicAuthSecret,
		}
	}
	idTokenValidityMinutes := k.MustInt("jwt.idtokenvalidityminutes")

	// Set default cleanup configuration
	cleanupConfig := domain.CleanupConfiguration{
		UnverifiedUserMaxAge: 24 * time.Hour, // Default: 24 hours
		CleanupInterval:      1 * time.Hour,  // Default: 1 hour
	}

	// Override with config file values if present
	if k.Exists("cleanup.unverifiedusermaxage") {
		cleanupConfig.UnverifiedUserMaxAge = time.Duration(k.MustInt("cleanup.unverifiedusermaxage")) * time.Hour
	}
	if k.Exists("cleanup.cleanupinterval") {
		cleanupConfig.CleanupInterval = time.Duration(k.MustInt("cleanup.cleanupinterval")) * time.Hour
	}

	// Get mock email demo server URL if configured
	mockEmailDemoServerURL := k.String("mock_email_demo_server_url")

	// Set default email rate limit configuration
	emailRateLimitConfig := domain.EmailRateLimitConfiguration{
		MaxEmailsPerDay:     1000,
		MaxEmailsPerAddress: 5,
		BackoffPeriod:       5 * time.Minute,
		BlockPeriod:         24 * time.Hour,
	}

	// Override rate limit configuration with config file values if present
	if k.Exists("emailratelimit.maxemailsperday") {
		emailRateLimitConfig.MaxEmailsPerDay = k.Int("emailratelimit.maxemailsperday")
	}
	if k.Exists("emailratelimit.maxemailsperaddress") {
		emailRateLimitConfig.MaxEmailsPerAddress = k.Int("emailratelimit.maxemailsperaddress")
	}
	if k.Exists("emailratelimit.backoffperiod") {
		emailRateLimitConfig.BackoffPeriod = time.Duration(k.MustInt("emailratelimit.backoffperiod")) * time.Minute
	}
	if k.Exists("emailratelimit.blockperiod") {
		emailRateLimitConfig.BlockPeriod = time.Duration(k.MustInt("emailratelimit.blockperiod")) * time.Hour
	}

	// Set default ALTCHA configuration
	altchaConfig := domain.AltchaConfiguration{
		HMACKey:    "",
		MaxNumber:  100000, // Default: 100,000
		SaltLength: 12,     // Default: 12 bytes
	}

	// Override with config file values if present
	if k.Exists("altcha.hmacKey") {
		altchaConfig.HMACKey = k.String("altcha.hmacKey")
	}
	if k.Exists("altcha.maxNumber") {
		altchaConfig.MaxNumber = k.Int64("altcha.maxNumber")
	}
	if k.Exists("altcha.saltLength") {
		altchaConfig.SaltLength = k.Int("altcha.saltLength")
	}

	// Read SMTP configuration using shared utility
	smtpConfig, err := ReadSMTPConfig(k)
	if err != nil {
		logging.Fatal(logger, "Error reading SMTP config: {Error}", err)
	}

	return domain.Configuration{
		DatabaseFilename:          databaseFilename,
		ServerReadTimeoutSeconds:  serverReadTimeoutSeconds,
		ServerWriteTimeoutSeconds: serverWriteTimeoutSeconds,
		ServerPort:                serverPort,
		BaseUrl:                   baseUrl,
		RegisteredClients:         registeredClients,
		JwtConfig: domain.JwtConfiguration{
			Issuer:                 baseUrl,
			IdTokenValidityMinutes: idTokenValidityMinutes,
			PrivateKey:             privateKey,
			PublicKey:              publicKey,
		},
		SMTPConfig:             *smtpConfig,
		EmailRateLimitConfig:   emailRateLimitConfig,
		CleanupConfig:          cleanupConfig,
		MockEmailDemoServerURL: mockEmailDemoServerURL,
		AltchaConfig:           altchaConfig,
	}
}

func ReadSMTPConfig(k *koanf.Koanf) (*domain.SMTPConfiguration, error) {
	smtpConfig := domain.SMTPConfiguration{}

	if !k.Exists("smtp.host") {
		return nil, fmt.Errorf("SMTP host is not configured")
	}
	smtpConfig.Host = k.String("smtp.host")

	if !k.Exists("smtp.port") {
		return nil, fmt.Errorf("SMTP port is not configured")
	}
	smtpConfig.Port = k.Int("smtp.port")

	if !k.Exists("smtp.username") {
		return nil, fmt.Errorf("SMTP username is not configured")
	}
	smtpConfig.Username = k.String("smtp.username")

	if !k.Exists("smtp.password") {
		return nil, fmt.Errorf("SMTP password is not configured")
	}
	smtpConfig.Password = k.String("smtp.password")

	if !k.Exists("smtp.fromEmail") {
		return nil, fmt.Errorf("SMTP from email is not configured")
	}
	smtpConfig.FromEmail = k.String("smtp.fromEmail")

	if !k.Exists("smtp.fromName") {
		return nil, fmt.Errorf("SMTP from name is not configured")
	}
	smtpConfig.FromName = k.String("smtp.fromName")

	if !k.Exists("smtp.useTls") {
		return nil, fmt.Errorf("SMTP useTls is not configured")
	}
	smtpConfig.UseTLS = k.Bool("smtp.useTls")

	return &smtpConfig, nil
}
