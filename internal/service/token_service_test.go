package service_test

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/stretchr/testify/assert"
)

func setupTokenServiceInfrastructure() (*service.TokenService, *config.Config) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			AccessSecret:  "test-access-secret-key-string-12345",
			RefreshSecret: "test-refresh-secret-key-string-12345",
		},
	}
	return service.NewTokenService(cfg), cfg
}

func TestTokenService_GenerateAccessToken(t *testing.T) {
	svc, _ := setupTokenServiceInfrastructure()

	user := &models.User{
		ID:    "user-123",
		Email: "test@example.com",
		Role:  "user",
	}
	sessionID := "session-123"

	token, err := svc.GenerateAccessToken(user, sessionID)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate valid access token signature
	claims, err := svc.ValidateAccessToken(token)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, user.Email, claims.Email)
	assert.Equal(t, user.Role, claims.Role)
	assert.Equal(t, sessionID, claims.SessionID)
}

func TestTokenService_GenerateRefreshToken(t *testing.T) {
	svc, _ := setupTokenServiceInfrastructure()

	user := &models.User{
		ID:    "user-123",
		Email: "test@example.com",
		Role:  "user",
	}

	token, err := svc.GenerateRefreshToken(user)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate valid refresh token signature
	claims, err := svc.ValidateRefreshToken(token)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, claims.UserID)
}

func TestTokenService_GenerateRandomString(t *testing.T) {
	svc, _ := setupTokenServiceInfrastructure()

	str := svc.GenerateRandomString(32)
	// Base64 encoding of 32 bytes result in 4*ceil(32/3) = 44 characters
	assert.Equal(t, 44, len(str))
}

func TestTokenService_MFATokenLifecycleAndCrossValidation(t *testing.T) {
	svc, _ := setupTokenServiceInfrastructure()
	userID := "user-mfa-555"

	// 1. Validate complete MFA generation and validation pipeline
	mfaToken, err := svc.GenerateMFAToken(userID)
	assert.NoError(t, err)
	assert.NotEmpty(t, mfaToken)

	resolvedUID, err := svc.ValidateMFAToken(mfaToken)
	assert.NoError(t, err)
	assert.Equal(t, userID, resolvedUID)

	// 2. Cross-Validation Security Safeguard: 
	// Access token validation logic must explicitly reject purpose-scoped MFA tokens
	_, accessErr := svc.ValidateAccessToken(mfaToken)
	assert.Error(t, accessErr)

	// 3. Conversely, ValidateMFAToken must reject a normal access token
	user := &models.User{ID: userID, Email: "mfa@example.com", Role: "user"}
	accessToken, err := svc.GenerateAccessToken(user, "sess-active")
	assert.NoError(t, err)

	_, mfaErr := svc.ValidateMFAToken(accessToken)
	assert.Error(t, mfaErr)
}

func TestTokenService_ValidationErrorHandlingPaths(t *testing.T) {
	svc, _ := setupTokenServiceInfrastructure()

	t.Run("Reject tokens signed with different signature configurations", func(t *testing.T) {
		// Create a separate standalone claims instance token signed with a bogus secret key
		claims := &service.JWTClaims{
			UserID: "hacker-999",
		}
		bogusToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		invalidSignedStr, _ := bogusToken.SignedString([]byte("completely-wrong-secret"))

		_, err := svc.ValidateAccessToken(invalidSignedStr)
		assert.Error(t, err)

		_, err = svc.ValidateRefreshToken(invalidSignedStr)
		assert.Error(t, err)
	})

	t.Run("Reject tokens signed with an unsupported signing algorithm profile", func(t *testing.T) {
		claims := &service.JWTClaims{
			UserID: "user-777",
		}
		// Go-JWT permits creating tokens without keys via the unauthenticated "none" method signature
		noneToken := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		noneTokenStr, err := noneToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
		assert.NoError(t, err)

		_, err = svc.ValidateAccessToken(noneTokenStr)
		assert.Error(t, err, "Should trigger the invalid signing method handler safeguard block")
		assert.Contains(t, err.Error(), "invalid signing method")

		_, err = svc.ValidateRefreshToken(noneTokenStr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signing method")
		
		_, err = svc.ValidateMFAToken(noneTokenStr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signing method")
	})

	t.Run("Return error on completely malformed token string arrays", func(t *testing.T) {
		_, err := svc.ValidateAccessToken("garbage.token.string")
		assert.Error(t, err)

		_, err = svc.ValidateRefreshToken("garbage.token.string")
		assert.Error(t, err)
	})
}