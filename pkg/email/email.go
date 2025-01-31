package email

import (
	"aggregat4/openidprovider/internal/domain"
	"fmt"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type EmailService struct {
	config domain.SendgridConfiguration
	client *sendgrid.Client
}

func NewEmailService(config domain.SendgridConfiguration) *EmailService {
	return &EmailService{
		config: config,
		client: sendgrid.NewSendClient(config.APIKey),
	}
}

func (s *EmailService) SendVerificationEmail(toEmail, verificationLink string) error {
	from := mail.NewEmail(s.config.FromName, s.config.FromEmail)
	to := mail.NewEmail("", toEmail)
	subject := "Verify your email address"

	plainTextContent := fmt.Sprintf(`Please verify your email address by clicking the following link:
%s

If you did not request this verification, please ignore this email.

Best regards,
%s`, verificationLink, s.config.FromName)

	htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<body>
    <p>Please verify your email address by clicking the following link:</p>
    <p><a href="%s">Verify Email Address</a></p>
    <p>If you did not request this verification, please ignore this email.</p>
    <br>
    <p>Best regards,<br>%s</p>
</body>
</html>`, verificationLink, s.config.FromName)

	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
	response, err := s.client.Send(message)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	if response.StatusCode >= 400 {
		return fmt.Errorf("failed to send email: status code %d", response.StatusCode)
	}

	return nil
}
