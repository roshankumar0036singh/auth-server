package service_test

import (
	"testing"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/stretchr/testify/assert"
)

func TestTokenService_GenerateAccessToken(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			AccessSecret:  "test-secret",
			RefreshSecret: "test-refresh-secret",
		},
	}
	svc := service.NewTokenService(cfg)

	user := &models.User{
		ID:    "user-123",
		Email: "test@example.com",
		Role:  "user",
	}

	token, err := svc.GenerateAccessToken(user)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate
	claims, err := svc.ValidateAccessToken(token)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, user.Email, claims.Email)
	assert.Equal(t, user.Role, claims.Role)
}

func TestTokenService_GenerateRefreshToken(t *testing.T) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			AccessSecret:  "test-secret",
			RefreshSecret: "test-refresh-secret",
		},
	}
	svc := service.NewTokenService(cfg)

	user := &models.User{
		ID:    "user-123",
		Email: "test@example.com",
		Role:  "user",
	}

	token, err := svc.GenerateRefreshToken(user)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate (assuming we add ValidateRefreshToken method or standard validation)
	// For now just checking it generates without error
}

func TestTokenService_GenerateRandomString(t *testing.T) {
	cfg := &config.Config{}
	svc := service.NewTokenService(cfg)

	str := svc.GenerateRandomString(32)
	// Base64 encoding of 32 bytes result in 4*ceil(32/3) = 44 characters
	assert.Greater(t, len(str), 32)
	assert.Equal(t, 44, len(str))
}
