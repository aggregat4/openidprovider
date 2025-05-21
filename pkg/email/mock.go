package email

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type MockEmailSender struct {
	DemoServerURL string
}

func NewMockEmailSender(demoServerURL string) *MockEmailSender {
	return &MockEmailSender{
		DemoServerURL: demoServerURL,
	}
}

func (s *MockEmailSender) SendVerificationEmail(to, verificationLink string) error {
	return s.sendEmail(to, "Verify your email", fmt.Sprintf("Please click the following link to verify your email: %s", verificationLink))
}

func (s *MockEmailSender) SendPasswordResetEmail(to, resetLink string) error {
	return s.sendEmail(to, "Reset your password", fmt.Sprintf("Please click the following link to reset your password: %s", resetLink))
}

func (s *MockEmailSender) SendDeleteAccountEmail(to, deleteLink string) error {
	return s.sendEmail(to, "Delete your account", fmt.Sprintf("Please click the following link to delete your account: %s", deleteLink))
}

func (s *MockEmailSender) sendEmail(to, subject, body string) error {
	email := struct {
		To      string `json:"to"`
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}{
		To:      to,
		Subject: subject,
		Body:    body,
	}

	jsonData, err := json.Marshal(email)
	if err != nil {
		return fmt.Errorf("error marshaling email data: %w", err)
	}

	resp, err := http.Post(s.DemoServerURL+"/emails", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error sending mock email: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code from mock email endpoint: %d", resp.StatusCode)
	}

	return nil
}
