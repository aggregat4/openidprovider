package email

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/repository"
	"context"
	"fmt"
	"time"

	"github.com/wneessen/go-mail"
)

type EmailSender interface {
	SendVerificationEmail(toEmail, verificationLink string) error
	SendPasswordResetEmail(toEmail, resetLink string) error
	SendDeleteAccountEmail(toEmail, deleteLink string) error
}

type EmailService struct {
	smtpConfig domain.SMTPConfiguration
	rateConfig domain.EmailRateLimitConfiguration
	store      *repository.Store
}

func NewEmailService(smtpConfig domain.SMTPConfiguration, rateConfig domain.EmailRateLimitConfiguration, store *repository.Store) *EmailService {
	return &EmailService{
		smtpConfig: smtpConfig,
		rateConfig: rateConfig,
		store:      store,
	}
}

func (s *EmailService) checkRateLimits(email, emailType string) error {
	// Check if email is blocked
	tracking, err := s.store.GetEmailTracking(email, emailType)
	if err != nil {
		return fmt.Errorf("failed to check email tracking: %w", err)
	}

	if tracking != nil && tracking.Blocked {
		// Calculate if block period has expired
		blockExpiresAt := time.Unix(tracking.BlockedAt, 0).Add(s.rateConfig.BlockPeriod)
		if time.Now().Before(blockExpiresAt) {
			return fmt.Errorf("email address is temporarily blocked")
		}
		// Block period has passed, tracking record will be cleaned up by the cleanup job
	}

	// Check global daily limit
	dailyCounts, err := s.store.GetEmailCounts(time.Now().Add(-24 * time.Hour))
	if err != nil {
		return fmt.Errorf("failed to get daily email counts: %w", err)
	}

	totalDaily := 0
	for _, count := range dailyCounts {
		totalDaily += count
	}
	if totalDaily >= s.rateConfig.MaxEmailsPerDay {
		return fmt.Errorf("daily email limit reached")
	}

	// Check per-address limit and backoff
	if tracking != nil {
		// Check if we've exceeded the maximum attempts in the last 24 hours
		if tracking.Attempts >= s.rateConfig.MaxEmailsPerAddress {
			// Block the address
			err = s.store.BlockEmailAddress(email, emailType, time.Now().Add(s.rateConfig.BlockPeriod))
			if err != nil {
				return fmt.Errorf("failed to block email address: %w", err)
			}
			return fmt.Errorf("email address has been blocked due to too many attempts")
		}

		// Calculate exponential backoff
		lastAttempt := time.Unix(tracking.LastAttempt, 0)
		backoffDuration := s.rateConfig.BackoffPeriod * time.Duration(1<<uint(tracking.Attempts-1)) // 2^(attempts-1) * base period
		if time.Since(lastAttempt) < backoffDuration {
			return fmt.Errorf("please wait before requesting another email")
		}
	}

	return nil
}

func (s *EmailService) sendEmail(toEmail, subject, plainTextContent, htmlContent string, emailType string) error {
	// Check rate limits
	err := s.checkRateLimits(toEmail, emailType)
	if err != nil {
		return err
	}

	// Track the attempt
	err = s.store.TrackEmailAttempt(toEmail, emailType)
	if err != nil {
		return fmt.Errorf("failed to track email attempt: %w", err)
	}

	// Create email message using go-mail
	msg := mail.NewMsg()
	msg.From(s.smtpConfig.FromEmail)
	msg.To(toEmail)
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextPlain, plainTextContent)
	msg.AddAlternativeString(mail.TypeTextHTML, htmlContent)

	// Send email via SMTP
	err = s.sendViaSMTP(msg)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func (s *EmailService) sendViaSMTP(msg *mail.Msg) error {
	// Create client with SMTP configuration
	client, err := mail.NewClient(s.smtpConfig.Host,
		mail.WithPort(s.smtpConfig.Port),
		mail.WithUsername(s.smtpConfig.Username),
		mail.WithPassword(s.smtpConfig.Password),
	)
	if err != nil {
		return fmt.Errorf("failed to create mail client: %w", err)
	}

	// Configure TLS if required
	if s.smtpConfig.UseTLS {
		client.SetTLSPolicy(mail.TLSMandatory)
	}

	// Send the email
	if err := client.DialAndSendWithContext(context.Background(), msg); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func (s *EmailService) SendVerificationEmail(toEmail, verificationLink string) error {
	subject := "Verify your email address"
	plainTextContent := fmt.Sprintf(`Please verify your email address by clicking the following link:
%s

If you did not request this verification, please ignore this email.

Best regards,
%s`, verificationLink, s.smtpConfig.FromName)

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
</html>`, verificationLink, s.smtpConfig.FromName)

	return s.sendEmail(toEmail, subject, plainTextContent, htmlContent, "verification")
}

func (s *EmailService) SendPasswordResetEmail(toEmail, resetLink string) error {
	subject := "Reset your password"
	plainTextContent := fmt.Sprintf(`You have requested to reset your password. Click the following link to set a new password:
%s

If you did not request this password reset, please ignore this email.

Best regards,
%s`, resetLink, s.smtpConfig.FromName)

	htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<body>
    <p>You have requested to reset your password. Click the following link to set a new password:</p>
    <p><a href="%s">Reset Password</a></p>
    <p>If you did not request this password reset, please ignore this email.</p>
    <br>
    <p>Best regards,<br>%s</p>
</body>
</html>`, resetLink, s.smtpConfig.FromName)

	return s.sendEmail(toEmail, subject, plainTextContent, htmlContent, "password_reset")
}

func (s *EmailService) SendDeleteAccountEmail(toEmail, deleteLink string) error {
	subject := "Delete your account"
	plainTextContent := fmt.Sprintf(`You have requested to delete your account. Click the following link to confirm:
%s

If you did not request to delete your account, please ignore this email.

Best regards,
%s`, deleteLink, s.smtpConfig.FromName)

	htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<body>
    <p>You have requested to delete your account. Click the following link to confirm:</p>
    <p><a href="%s">Delete Account</a></p>
    <p>If you did not request to delete your account, please ignore this email.</p>
    <br>
    <p>Best regards,<br>%s</p>
</body>
</html>`, deleteLink, s.smtpConfig.FromName)

	return s.sendEmail(toEmail, subject, plainTextContent, htmlContent, "delete_account")
}
