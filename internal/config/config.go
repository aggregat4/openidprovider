package config

import (
	"aggregat4/openidprovider/internal/domain"
	"fmt"

	"github.com/kirsle/configdir"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// GetDefaultConfigPath returns the default configuration file path
func GetDefaultConfigPath() string {
	return configdir.LocalConfig("openidprovider") + "/openidprovider.json"
}

// LoadConfigFile loads a koanf configuration from the specified file
func LoadConfigFile(configFile string) (*koanf.Koanf, error) {
	k := koanf.New(".")
	if err := k.Load(file.Provider(configFile), json.Parser()); err != nil {
		return nil, fmt.Errorf("error loading config file %s: %w", configFile, err)
	}
	return k, nil
}

// ReadSMTPConfig reads SMTP configuration from koanf and validates all required fields
func ReadSMTPConfig(k *koanf.Koanf) (*domain.SMTPConfiguration, error) {
	smtpConfig := domain.SMTPConfiguration{}

	if !k.Exists("smtp.host") {
		return nil, fmt.Errorf("SMTP host is not configured")
	}
	smtpConfig.Host = k.String("smtp.host")

	if !k.Exists("smtp.port") {
		return nil, fmt.Errorf("SMTP port is not configured")
	}
	smtpConfig.Port = k.Int("smtp.port")

	if !k.Exists("smtp.username") {
		return nil, fmt.Errorf("SMTP username is not configured")
	}
	smtpConfig.Username = k.String("smtp.username")

	if !k.Exists("smtp.password") {
		return nil, fmt.Errorf("SMTP password is not configured")
	}
	smtpConfig.Password = k.String("smtp.password")

	if !k.Exists("smtp.fromEmail") {
		return nil, fmt.Errorf("SMTP from email is not configured")
	}
	smtpConfig.FromEmail = k.String("smtp.fromEmail")

	if !k.Exists("smtp.fromName") {
		return nil, fmt.Errorf("SMTP from name is not configured")
	}
	smtpConfig.FromName = k.String("smtp.fromName")

	if !k.Exists("smtp.useTls") {
		return nil, fmt.Errorf("SMTP useTls is not configured")
	}
	smtpConfig.UseTLS = k.Bool("smtp.useTls")

	return &smtpConfig, nil
}
