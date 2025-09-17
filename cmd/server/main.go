package main

import (
	"aggregat4/openidprovider/internal/config"
	"aggregat4/openidprovider/internal/logging"
	"aggregat4/openidprovider/internal/repository"
	"aggregat4/openidprovider/internal/server"
	"aggregat4/openidprovider/pkg/email"
	"flag"

	"github.com/aggregat4/go-baselib/lang"

	_ "github.com/mattn/go-sqlite3"
)

var logger = logging.ForComponent("cmd.server")

func main() {

	var configFileLocation string
	flag.StringVar(&configFileLocation, "config", "", "The location of the configuration file if you do not want to default to the standard location")
	flag.Parse()

	config := config.ReadConfig(lang.IfElse(configFileLocation == "", config.GetDefaultConfigPath(), configFileLocation))

	var store repository.Store
	err := store.InitAndVerifyDb(repository.CreateFileDbUrl(config.DatabaseFilename))
	if err != nil {
		logging.Fatal(logger, "Error initializing database: {Error}", err)
	}
	defer store.Close()

	// Initialize email sender
	var emailSender email.EmailSender
	if config.MockEmailDemoServerURL != "" {
		logging.Info(logger, "Using mock email sender with demo server URL {DemoServerURL}", config.MockEmailDemoServerURL)
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
