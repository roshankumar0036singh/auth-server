package service

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/smtp"
	"os"
	"path/filepath"

	"github.com/roshankumar0036singh/auth-server/internal/config"
)

type EmailSender interface {
	SendVerificationEmail(email, token, appURL string) error
	SendPasswordResetEmail(email, token, appURL string) error
}

// ErrTemplateNotFound is returned when a requested email template is not in the cache.
type ErrTemplateNotFound struct {
	Name string
}

func (e *ErrTemplateNotFound) Error() string {
	return fmt.Sprintf("email template %q not found", e.Name)
}

type EmailService struct {
	config    config.EmailConfig
	templates map[string]*template.Template
}

// NewEmailService initializes EmailService and pre-parses all templates from
// the templates/ directory at startup. Missing or invalid templates log a
// warning but do NOT crash the server — errors are returned only when that
// specific template is actually used in SendEmail.
func NewEmailService(cfg *config.Config) (*EmailService, error) {
	templates, err := loadTemplates("templates")
	if err != nil {
		return nil, fmt.Errorf("failed to load email templates: %w", err)
	}

	return &EmailService{
		config:    cfg.Email,
		templates: templates,
	}, nil
}

// loadTemplates reads all files in dir and parses each as an HTML template.
// Files that fail to parse are skipped with a warning — they do not abort startup.
// Returns an error only if the directory itself cannot be read.
func loadTemplates(dir string) (map[string]*template.Template, error) {
	cache := make(map[string]*template.Template)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("could not read templates directory %q: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		tmplPath := filepath.Join(dir, name)

		t, err := template.ParseFiles(tmplPath)
		if err != nil {
			// Log warning but skip — server keeps running.
			// SendEmail will return ErrTemplateNotFound if this template is requested.
			log.Printf("WARNING: failed to parse email template %q: %v (skipping)", name, err)
			continue
		}

		cache[name] = t
		log.Printf("INFO: loaded email template %q", name)
	}

	// Warn about required templates that are missing
	required := []string{"verify_email.html", "reset_password.html"}
	for _, name := range required {
		if _, ok := cache[name]; !ok {
			log.Printf("WARNING: required email template %q not found in %q — emails using this template will fail at send time", name, dir)
		}
	}

	return cache, nil
}

// SendEmail sends an HTML email using a pre-cached template.
// Returns ErrTemplateNotFound if the requested template was missing or failed to parse at startup.
func (s *EmailService) SendEmail(to []string, subject string, templateName string, data interface{}) error {
	t, ok := s.templates[templateName]
	if !ok {
		return &ErrTemplateNotFound{Name: templateName}
	}

	var body bytes.Buffer
	if err := t.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute email template %q: %w", templateName, err)
	}

	headers := make(map[string]string)
	headers["From"] = s.config.FromEmail
	headers["To"] = to[0]
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=\"UTF-8\""

	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body.String()

	auth := smtp.PlainAuth("", s.config.SMTPUser, s.config.SMTPPassword, s.config.SMTPHost)

	addr := fmt.Sprintf("%s:%d", s.config.SMTPHost, s.config.SMTPPort)
	if err := smtp.SendMail(addr, auth, s.config.FromEmail, to, []byte(message)); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// SendVerificationEmail sends the email verification link.
func (s *EmailService) SendVerificationEmail(email, token, appURL string) error {
	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", appURL, token)

	data := struct {
		VerifyURL string
		AppName   string
	}{
		VerifyURL: verifyURL,
		AppName:   "Auth Server",
	}

	return s.SendEmail([]string{email}, "Verify your email", "verify_email.html", data)
}

// SendPasswordResetEmail sends the password reset link.
func (s *EmailService) SendPasswordResetEmail(email, token, appURL string) error {
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", appURL, token)

	data := struct {
		ResetURL string
		AppName  string
	}{
		ResetURL: resetURL,
		AppName:  "Auth Server",
	}

	return s.SendEmail([]string{email}, "Reset your password", "reset_password.html", data)
}