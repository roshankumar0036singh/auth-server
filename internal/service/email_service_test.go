package service_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmailService_Lifecycle(t *testing.T) {
	// 1. Create a workspace matching the relative directory paths
	tempDir := t.TempDir()
	
	// Change working directory to the temp workspace so filepath.Join("templates", ...) works
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tempDir))
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	// Create mock html templates directory structure
	templatesDir := filepath.Join(tempDir, "templates")
	err = os.MkdirAll(templatesDir, 0755)
	require.NoError(t, err)

	// Write verification email template stub
	verifyTmplContent := `<html><body><a href="{{.VerifyURL}}">Verify Link</a> - {{.AppName}}</body></html>`
	err = os.WriteFile(filepath.Join(templatesDir, "verify_email.html"), []byte(verifyTmplContent), 0644)
	require.NoError(t, err)

	// Write password reset email template stub
	resetTmplContent := `<html><body><a href="{{.ResetURL}}">Reset Link</a> - {{.AppName}}</body></html>`
	err = os.WriteFile(filepath.Join(templatesDir, "reset_password.html"), []byte(resetTmplContent), 0644)
	require.NoError(t, err)

	// 2. Initialize our Configuration Matrix using an unreachable mock local SMTP host
	cfg := &config.Config{
		Email: config.EmailConfig{
			SMTPHost:     "127.0.0.1",
			SMTPPort:     1, // Invalid port ensures network connection execution isolation drops out quickly
			SMTPUser:     "test-user",
			SMTPPassword: "test-password",
			FromEmail:    "noreply@example.com",
		},
	}

	emailSvc := service.NewEmailService(cfg)

	t.Run("SendVerificationEmail - Processes Templates and Safely Errors on Network", func(t *testing.T) {
		err := emailSvc.SendVerificationEmail("dev@example.com", "mock-verification-token", "http://localhost:3000")
		
		// Assert that template parsing and header assembly pass completely,
		// failing only when it hits the dial stage on port 1.
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to send email")
	})

	t.Run("SendPasswordResetEmail - Processes Templates and Safely Errors on Network", func(t *testing.T) {
		err := emailSvc.SendPasswordResetEmail("dev@example.com", "mock-reset-token", "http://localhost:3000")
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to send email")
	})

	t.Run("SendEmail - Missing File Template Fallback Error Handling", func(t *testing.T) {
		// Attempting to send an email using a non-existent file name should trigger parsing errors instantly
		err := emailSvc.SendEmail([]string{"test@example.com"}, "Subject", "missing_file_stub.html", nil)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse email template")
	})
}