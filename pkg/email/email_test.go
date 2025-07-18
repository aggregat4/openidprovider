package email

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/repository"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestNewEmailService(t *testing.T) {
	smtpConfig := domain.SMTPConfiguration{
		Host:      "smtp.example.com",
		Port:      587,
		Username:  "test@example.com",
		Password:  "password",
		FromEmail: "noreply@example.com",
		FromName:  "Test Service",
		UseTLS:    true,
	}

	rateConfig := domain.EmailRateLimitConfiguration{
		MaxEmailsPerDay:     100,
		MaxEmailsPerAddress: 5,
		BackoffPeriod:       5 * time.Minute,
		BlockPeriod:         24 * time.Hour,
	}

	store := &repository.Store{}

	service := NewEmailService(smtpConfig, rateConfig, store)

	if service == nil {
		t.Fatal("Expected EmailService to be created, got nil")
	}

	if service.smtpConfig.Host != smtpConfig.Host {
		t.Errorf("Expected SMTP host to be %s, got %s", smtpConfig.Host, service.smtpConfig.Host)
	}

	if service.rateConfig.MaxEmailsPerDay != rateConfig.MaxEmailsPerDay {
		t.Errorf("Expected max emails per day to be %d, got %d", rateConfig.MaxEmailsPerDay, service.rateConfig.MaxEmailsPerDay)
	}
}

func TestEmailTrackingWithNullBlockedAt(t *testing.T) {
	smtpConfig := domain.SMTPConfiguration{
		Host:      "smtp.example.com",
		Port:      587,
		Username:  "test@example.com",
		Password:  "password",
		FromEmail: "noreply@example.com",
		FromName:  "Test Service",
		UseTLS:    true,
	}

	rateConfig := domain.EmailRateLimitConfiguration{
		MaxEmailsPerDay:     100,
		MaxEmailsPerAddress: 5,
		BackoffPeriod:       5 * time.Minute,
		BlockPeriod:         24 * time.Hour,
	}

	// Create an in-memory database for testing
	store := &repository.Store{}
	err := store.InitAndVerifyDb(repository.CreateInMemoryDbUrl())
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer store.Close()

	service := NewEmailService(smtpConfig, rateConfig, store)

	// Test that we can check rate limits without errors
	err = service.checkRateLimits("test@example.com", "verification")
	if err != nil {
		t.Errorf("Expected no error when checking rate limits, got: %v", err)
	}

	// Test that we can track email attempts without errors
	err = service.store.TrackEmailAttempt("test@example.com", "verification")
	if err != nil {
		t.Errorf("Expected no error when tracking email attempt, got: %v", err)
	}

	// Test that we can retrieve email tracking without errors
	tracking, err := service.store.GetEmailTracking("test@example.com", "verification")
	if err != nil {
		t.Errorf("Expected no error when getting email tracking, got: %v", err)
	}

	if tracking == nil {
		t.Fatal("Expected email tracking to be returned, got nil")
	}

	// Verify that the tracking has the expected values
	if tracking.Email != "test@example.com" {
		t.Errorf("Expected email to be 'test@example.com', got %s", tracking.Email)
	}

	if tracking.Type != "verification" {
		t.Errorf("Expected type to be 'verification', got %s", tracking.Type)
	}

	if tracking.Attempts != 1 {
		t.Errorf("Expected attempts to be 1, got %d", tracking.Attempts)
	}

	if tracking.Blocked {
		t.Error("Expected blocked to be false for new tracking")
	}

	// Verify that BlockedAt is not valid (NULL in database)
	if tracking.BlockedAt.Valid {
		t.Error("Expected BlockedAt to be invalid (NULL) for new tracking")
	}
}
