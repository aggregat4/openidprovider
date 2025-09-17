package main

import (
	"aggregat4/openidprovider/internal/config"
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/logging"
	"context"
	"flag"
	"fmt"

	"github.com/aggregat4/go-baselib/lang"
	"github.com/wneessen/go-mail"
)

func main() {
	logger := logging.ForComponent("cmd.testemail")

	var (
		configFileLocation string
		recipientEmail     string
		help               bool
	)

	flag.StringVar(&configFileLocation, "config", "", "The location of the configuration file (defaults to standard location)")
	flag.StringVar(&recipientEmail, "to", "", "Recipient email address (required)")
	flag.BoolVar(&help, "help", false, "Show this help message")
	flag.Parse()

	if help {
		fmt.Println("Email Testing Tool for OpenID Provider")
		fmt.Println("")
		fmt.Println("Usage:")
		fmt.Println("  testemail -to recipient@example.com [options]")
		fmt.Println("")
		fmt.Println("Options:")
		flag.PrintDefaults()
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  testemail -to test@example.com")
		fmt.Println("  testemail -to test@example.com -config /path/to/config.json")
		return
	}

	if recipientEmail == "" {
		logging.Fatal(logger, "Recipient email address is required. Use -to flag or -help for usage information.")
	}

	// Read configuration
	configFile := lang.IfElse(configFileLocation == "", config.GetDefaultConfigPath(), configFileLocation)

	k, err := config.LoadConfigFile(configFile)
	if err != nil {
		logging.Fatal(logger, "Error loading configuration: {Error}", err)
	}

	smtpConfig, err := config.ReadSMTPConfig(k)
	if err != nil {
		logging.Fatal(logger, "Error reading SMTP configuration: {Error}", err)
	}

	fmt.Printf("Configuration loaded from: %s\n", configFile)
	fmt.Printf("SMTP Host: %s:%d\n", smtpConfig.Host, smtpConfig.Port)
	fmt.Printf("SMTP Username: %s\n", smtpConfig.Username)
	fmt.Printf("SMTP From: %s <%s>\n", smtpConfig.FromName, smtpConfig.FromEmail)
	fmt.Printf("SMTP TLS: %t\n", smtpConfig.UseTLS)
	fmt.Printf("Recipient: %s\n", recipientEmail)
	fmt.Println("")

	// Send test email directly using go-mail
	fmt.Println("Sending test email...")
	err = sendTestEmail(smtpConfig, recipientEmail)
	if err != nil {
		logging.Fatal(logger, "Error sending email: {Error}", err)
	}

	fmt.Printf("✅ Test email sent successfully to %s\n", recipientEmail)
}

func sendTestEmail(smtpConfig *domain.SMTPConfiguration, recipientEmail string) error {
	// Create email message
	msg := mail.NewMsg()
	msg.From(smtpConfig.FromEmail)
	msg.To(recipientEmail)
	msg.Subject("OpenID Provider - Email Configuration Test")

	plainTextContent := `This is a test email from your OpenID Provider service.

If you received this email, your SMTP configuration is working correctly.

This email was sent by the testemail tool to verify your email configuration.

Best regards,
Your OpenID Provider Service`

	htmlContent := `
<!DOCTYPE html>
<html>
<body>
    <h2>OpenID Provider - Email Configuration Test</h2>
    <p>This is a test email from your OpenID Provider service.</p>
    <p>If you received this email, your SMTP configuration is working correctly.</p>
    <p>This email was sent by the testemail tool to verify your email configuration.</p>
    <br>
    <p>Best regards,<br>Your OpenID Provider Service</p>
</body>
</html>`

	msg.SetBodyString(mail.TypeTextPlain, plainTextContent)
	msg.AddAlternativeString(mail.TypeTextHTML, htmlContent)

	// Create SMTP client
	client, err := mail.NewClient(
		smtpConfig.Host,
		mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
		mail.WithPort(smtpConfig.Port),
		mail.WithUsername(smtpConfig.Username),
		mail.WithPassword(smtpConfig.Password),
	)
	if err != nil {
		return fmt.Errorf("failed to create mail client: %w", err)
	}

	// Configure TLS
	if !smtpConfig.UseTLS {
		client.SetTLSPolicy(mail.NoTLS)
	} else {
		client.SetTLSPolicy(mail.TLSMandatory)
	}

	// Send email
	if err := client.DialAndSendWithContext(context.Background(), msg); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
