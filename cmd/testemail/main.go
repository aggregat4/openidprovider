package main

import (
	"aggregat4/openidprovider/internal/domain"
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/aggregat4/go-baselib/lang"
	"github.com/kirsle/configdir"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"

	"github.com/wneessen/go-mail"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

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
		log.Fatal("Recipient email address is required. Use -to flag or -help for usage information.")
	}

	// Read configuration
	defaultConfigLocation := configdir.LocalConfig("openidprovider") + "/openidprovider.json"
	configFile := lang.IfElse(configFileLocation == "", defaultConfigLocation, configFileLocation)

	smtpConfig, err := readSMTPConfig(configFile)
	if err != nil {
		log.Fatalf("Error reading configuration: %v", err)
	}

	// Validate SMTP configuration
	if smtpConfig.Host == "" {
		log.Fatal("SMTP host is not configured. Please check your configuration file.")
	}
	if smtpConfig.Username == "" {
		log.Fatal("SMTP username is not configured. Please check your configuration file.")
	}
	if smtpConfig.Password == "" {
		log.Fatal("SMTP password is not configured. Please check your configuration file.")
	}
	if smtpConfig.FromEmail == "" {
		log.Fatal("SMTP from email is not configured. Please check your configuration file.")
	}
	if smtpConfig.FromName == "" {
		log.Fatal("SMTP from name is not configured. Please check your configuration file.")
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
		log.Fatalf("Error sending email: %v", err)
	}

	fmt.Printf("✅ Test email sent successfully to %s\n", recipientEmail)
}

func readSMTPConfig(configFile string) (*domain.SMTPConfiguration, error) {
	k := koanf.New(".")

	// Load configuration file
	if err := k.Load(file.Provider(configFile), json.Parser()); err != nil {
		return nil, fmt.Errorf("error loading config file %s: %w", configFile, err)
	}

	// Read SMTP configuration
	smtpConfig := domain.SMTPConfiguration{}
	if k.Exists("smtp.host") {
		smtpConfig.Host = k.String("smtp.host")
	} else {
		log.Fatal("Missing mandatory SMTP setting: smtp.host")
	}
	if k.Exists("smtp.port") {
		smtpConfig.Port = k.Int("smtp.port")
	} else {
		log.Fatal("Missing mandatory SMTP setting: smtp.port")
	}
	if k.Exists("smtp.username") {
		smtpConfig.Username = k.String("smtp.username")
	} else {
		log.Fatal("Missing mandatory SMTP setting: smtp.username")
	}
	if k.Exists("smtp.password") {
		smtpConfig.Password = k.String("smtp.password")
	} else {
		log.Fatal("Missing mandatory SMTP setting: smtp.password")
	}
	if k.Exists("smtp.fromEmail") {
		smtpConfig.FromEmail = k.String("smtp.fromEmail")
	} else {
		log.Fatal("Missing mandatory SMTP setting: smtp.fromEmail")
	}
	if k.Exists("smtp.fromName") {
		smtpConfig.FromName = k.String("smtp.fromName")
	} else {
		log.Fatal("Missing mandatory SMTP setting: smtp.fromName")
	}
	if k.Exists("smtp.useTls") {
		smtpConfig.UseTLS = k.Bool("smtp.useTls")
	} else {
		log.Fatal("Missing mandatory SMTP setting: smtp.useTls")
	}

	return &smtpConfig, nil
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
