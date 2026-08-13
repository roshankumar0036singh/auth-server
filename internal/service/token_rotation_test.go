package service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/service"
)

func TestJWTRotation_OldTokensSurviveRotation(t *testing.T) {
	oldAccess := "old-access-secret-0123456789abcdef"
	oldRefresh := "old-refresh-secret-0123456789abcdef"
	newAccess := "new-access-secret-0123456789abcdef"
	newRefresh := "new-refresh-secret-0123456789abcdef"

	user := &models.User{ID: "u-1", Email: "rotate@example.com", Role: "user"}

	// v1: tokens signed with the old primary secrets
	v1 := service.NewTokenService(&config.Config{
		JWT: config.JWTConfig{AccessSecret: oldAccess, RefreshSecret: oldRefresh},
	})
	access, err := v1.GenerateAccessToken(user, "sess-1")
	require.NoError(t, err)
	refresh, err := v1.GenerateRefreshToken(user)
	require.NoError(t, err)

	// v2: primary rotates, old keys demoted to rotation list
	v2 := service.NewTokenService(&config.Config{
		JWT: config.JWTConfig{
			AccessSecret:    newAccess,
			RefreshSecret:   newRefresh,
			RotationSecrets: []string{oldAccess, oldRefresh},
		},
	})

	// old tokens still validate on the rotated server
	claims, err := v2.ValidateAccessToken(access)
	require.NoError(t, err)
	assert.Equal(t, "u-1", claims.UserID)
	assert.Equal(t, "sess-1", claims.SessionID)

	rClaims, err := v2.ValidateRefreshToken(refresh)
	require.NoError(t, err)
	assert.Equal(t, "u-1", rClaims.UserID)

	// new tokens validate and were signed by the new primary
	actual := models.User{ID: "u-2", Email: "user2@example.com", Role: "admin"}
	access2, err := v2.GenerateAccessToken(&actual, "sess-2")
	require.NoError(t, err)
	c2, err := v2.ValidateAccessToken(access2)
	require.NoError(t, err)
	assert.Equal(t, "u-2", c2.UserID)
}

func TestJWTValidation_RejectsUnknownSecret(t *testing.T) {
	svc := service.NewTokenService(&config.Config{
		JWT: config.JWTConfig{AccessSecret: "secret-one-0123456789abcdef", RefreshSecret: "refresh-one-0123456789abcdef"},
	})

	user := &models.User{ID: "u-1", Email: "x@example.com"}
	access, err := svc.GenerateAccessToken(user, "s")
	require.NoError(t, err)

	// wrong rotation list -> token must fail
	svc2 := service.NewTokenService(&config.Config{
		JWT: config.JWTConfig{
			AccessSecret:    "rotated-primary-0123456789abcd",
			RefreshSecret:   "rotated-refresh-0123456789abc",
			RotationSecrets: []string{"some-unrelated-key-012345678abcdef"},
		},
	})
	_, err = svc2.ValidateAccessToken(access)
	assert.Error(t, err)
}
