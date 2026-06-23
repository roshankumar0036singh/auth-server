package service_test

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMFAService_Lifecycle(t *testing.T) {
	cfg := &config.Config{}
	mfaSvc := service.NewMFAService(cfg)
	userEmail := "mfa-test-user@example.com"

	// 1. Test registration setup: Secret Generation and QR Image Encoding
	secret, qrCodeURL, err := mfaSvc.GenerateMFA(userEmail)
	require.NoError(t, err)
	assert.NotEmpty(t, secret, "Secret key generation should not be blank")
	assert.Contains(t, qrCodeURL, "data:image/png;base64,", "QR Code payload should be correctly structured as a data URL")

	// 2. Test successful validation path: Simulate generating a valid code via TOTP specs
	currentCode, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	isValid := mfaSvc.ValidateMFA(secret, currentCode)
	assert.True(t, isValid, "A fresh token matching the secret signature should pass validation")

	// 3. Test failed validation path: Provide an explicitly invalid token string
	isInvalid := mfaSvc.ValidateMFA(secret, "000000")
	assert.False(t, isInvalid, "An incorrect code entry should be strictly rejected")
}