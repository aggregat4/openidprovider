package main

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/logging"
	"aggregat4/openidprovider/internal/repository"
	"encoding/json"
	"flag"
	"os"
	"time"
)

func main() {
	logger := logging.ForComponent("cmd.cleanup")

	// Parse command line flags
	configFile := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	// Read configuration
	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		logging.Error(logger, "Failed to read configuration file", "error", err)
		os.Exit(1)
	}

	var config domain.Configuration
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		logging.Error(logger, "Failed to parse configuration file", "error", err)
		os.Exit(1)
	}

	// Initialize database
	store := &repository.Store{}
	err = store.InitAndVerifyDb(repository.CreateFileDbUrl(config.DatabaseFilename))
	if err != nil {
		logging.Error(logger, "Failed to initialize database", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	// Delete expired verification tokens
	err = store.DeleteExpiredVerificationTokens()
	if err != nil {
		logging.Error(logger, "Failed to delete expired verification tokens", "error", err)
		os.Exit(1)
	}

	logging.Info(logger, "Successfully cleaned up expired verification tokens", "timestamp", time.Now().Unix())
}
