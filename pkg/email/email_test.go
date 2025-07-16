package email

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/repository"
	"testing"
	"time"
)

func TestNewEmailService(t *testing.T) {
	smtpConfig := domain.SMTPConfiguration{
		Host:      "localhost",
		Port:      587,
		Username:  "test",
		Password:  "test",
		FromEmail: "test@example.com",
		FromName:  "Test Sender",
		UseTLS:    true,
	}

	rateConfig := domain.EmailRateLimitConfiguration{
		MaxEmailsPerDay:     1000,
		MaxEmailsPerAddress: 5,
		BackoffPeriod:       5 * time.Minute,
		BlockPeriod:         24 * time.Hour,
	}

	store := &repository.Store{}
	service := NewEmailService(smtpConfig, rateConfig, store)

	if service == nil {
		t.Fatal("Expected email service to be created")
	}

	if service.smtpConfig.Host != "localhost" {
		t.Errorf("Expected host to be 'localhost', got '%s'", service.smtpConfig.Host)
	}

	if service.smtpConfig.Port != 587 {
		t.Errorf("Expected port to be 587, got %d", service.smtpConfig.Port)
	}
}
