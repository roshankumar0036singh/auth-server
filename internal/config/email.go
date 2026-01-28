package config

import "os"

type EmailConfig struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	FromEmail    string
	UseTLS       bool
}

func LoadEmailConfig() EmailConfig {
	return EmailConfig{
		SMTPHost:     os.Getenv("SMTP_HOST"),
		SMTPPort:     getEnvAsInt("SMTP_PORT", 587),
		SMTPUser:     os.Getenv("SMTP_USER"),
		SMTPPassword: os.Getenv("SMTP_PASSWORD"),
		FromEmail:    os.Getenv("SMTP_FROM_EMAIL"),
		UseTLS:       getEnvAsBool("SMTP_USE_TLS", true),
	}
}
