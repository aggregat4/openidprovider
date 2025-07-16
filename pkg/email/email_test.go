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

func TestCreateEmailMessage(t *testing.T) {
	config := domain.SMTPConfiguration{
		FromEmail: "test@example.com",
		FromName:  "Test Sender",
	}

	service := &EmailService{smtpConfig: config}

	toEmail := "recipient@example.com"
	subject := "Test Subject"
	plainText := "This is a test email"
	htmlContent := "<p>This is a test email</p>"

	message := service.createEmailMessage(toEmail, subject, plainText, htmlContent)

	messageStr := string(message)

	// Check that the message contains expected headers
	if !contains(messageStr, "From: \"Test Sender\" <test@example.com>") {
		t.Error("Message should contain From header")
	}

	if !contains(messageStr, "To: <recipient@example.com>") {
		t.Error("Message should contain To header")
	}

	if !contains(messageStr, "Subject: Test Subject") {
		t.Error("Message should contain Subject header")
	}

	if !contains(messageStr, "Content-Type: multipart/alternative") {
		t.Error("Message should contain multipart content type")
	}

	if !contains(messageStr, "This is a test email") {
		t.Error("Message should contain plain text content")
	}

	if !contains(messageStr, "<p>This is a test email</p>") {
		t.Error("Message should contain HTML content")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
