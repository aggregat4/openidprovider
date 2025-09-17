package main

import (
	"aggregat4/openidprovider/internal/config"
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/logging"
	"aggregat4/openidprovider/internal/repository"
	"aggregat4/openidprovider/internal/server"
	"aggregat4/openidprovider/pkg/email"
	"flag"
	"time"

	"github.com/aggregat4/go-baselib/crypto"
	"github.com/aggregat4/go-baselib/lang"

	_ "github.com/mattn/go-sqlite3"
)

var logger = logging.ForComponent("cmd.server")

func main() {

	var configFileLocation string
	flag.StringVar(&configFileLocation, "config", "", "The location of the configuration file if you do not want to default to the standard location")
	flag.Parse()

	config := readConfig(lang.IfElse(configFileLocation == "", config.GetDefaultConfigPath(), configFileLocation))

	var store repository.Store
	err := store.InitAndVerifyDb(repository.CreateFileDbUrl(config.DatabaseFilename))
	if err != nil {
		logging.Fatal(logger, "Error initializing database: %s", err)
	}
	defer store.Close()

	// Initialize email sender
	var emailSender email.EmailSender
	if config.MockEmailDemoServerURL != "" {
		logging.Info(logger, "Using mock email sender with demo server URL %s", config.MockEmailDemoServerURL)
		emailSender = email.NewMockEmailSender(config.MockEmailDemoServerURL)
	} else {
		logging.Info(logger, "Using SMTP email sender")
		emailSender = email.NewEmailService(config.SMTPConfig, config.EmailRateLimitConfig, &store)
	}

	server.RunServer(server.Controller{
		Store:           &store,
		Config:          config,
		EmailService:    emailSender,
		CaptchaVerifier: server.NewAltchaVerifier(config.AltchaConfig),
	})
}

func readConfig(configFileLocation string) domain.Configuration {
	k, err := config.LoadConfigFile(configFileLocation)
	if err != nil {
		logging.Fatal(logger, "error loading config: %v", err)
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
		logging.Fatal(logger, "Error reading private key file: %s", err)
	}

	publicKeyPemFilename := k.String("publickeypemfilename")
	if publicKeyPemFilename == "" {
		logging.Fatal(logger, "Public key filename is required in the configuration")
	}
	publicKey, err := crypto.ReadRSAPublicKey(publicKeyPemFilename)
	if err != nil {
		logging.Fatal(logger, "Error reading public key file: %s", err)
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
	smtpConfig, err := config.ReadSMTPConfig(k)
	if err != nil {
		logging.Fatal(logger, "error reading SMTP config: %v", err)
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
