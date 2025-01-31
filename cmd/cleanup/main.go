package main

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/repository"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"time"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Parse command line flags
	configFile := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	// Read configuration
	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		logger.Error("Failed to read configuration file", "error", err)
		os.Exit(1)
	}

	var config domain.Configuration
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		logger.Error("Failed to parse configuration file", "error", err)
		os.Exit(1)
	}

	// Initialize database
	store := &repository.Store{}
	err = store.InitAndVerifyDb(repository.CreateFileDbUrl(config.DatabaseFilename))
	if err != nil {
		logger.Error("Failed to initialize database", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	// Delete expired verification tokens
	err = store.DeleteExpiredVerificationTokens()
	if err != nil {
		logger.Error("Failed to delete expired verification tokens", "error", err)
		os.Exit(1)
	}

	logger.Info("Successfully cleaned up expired verification tokens", "timestamp", time.Now().Unix())
}
