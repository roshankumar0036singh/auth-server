package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func TestWebAuthnService_FinishLogin_AccountStateChecks(t *testing.T) {
	// Use the integration test setup to get a real db, cacheService, and userRepo
	_, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	cacheService := service.NewCacheService(rdb)
	userRepo := repository.NewUserRepository(db)

	cfg := &config.Config{
		App: config.AppConfig{URL: "http://localhost"},
		WebAuthn: config.WebAuthnConfig{
			RPDisplayName: "Test RP",
			RPID:          "localhost",
			RPOrigins:     []string{"http://localhost"},
		},
	}

	svc, err := service.NewWebAuthnService(cfg, userRepo, cacheService)
	assert.NoError(t, err)
	assert.NotNil(t, svc)

	ctx := context.Background()

	// Case 1: Invalid session
	_, _, err = svc.FinishLogin(ctx, "invalid-session", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired authentication session")

	// Helper to set up a session for a given user
	setupSession := func(userID string) string {
		sessionID := "test-session-" + userID
		sessionData := webauthn.SessionData{
			Challenge: "challenge",
			UserID:    []byte(userID),
		}
		_ = cacheService.StoreWebAuthnSession(ctx, sessionID, userID, sessionData, 5*time.Minute)
		return sessionID
	}

	inactiveUser := &models.User{
		Email: "inactive@example.com",
		Role:  "user",
	}
	err = userRepo.Create(inactiveUser)
	assert.NoError(t, err)

	err = userRepo.Update(inactiveUser.ID, map[string]interface{}{"is_active": false})
	assert.NoError(t, err)

	// Fetch again to ensure IsActive is false in our local object (FindByID is what the service uses)
	inactiveUser, _ = userRepo.FindByID(inactiveUser.ID)

	sessionInactive := setupSession(inactiveUser.ID)
	_, _, err = svc.FinishLogin(ctx, sessionInactive, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "account is inactive")

	// Case 3: Locked account
	lockedUser := &models.User{
		Email:    "locked@example.com",
		Role:     "user",
		IsActive: true,
	}
	err = userRepo.Create(lockedUser)
	assert.NoError(t, err)

	futureTime := time.Now().Add(1 * time.Hour)
	err = userRepo.LockUser(lockedUser.ID, futureTime)
	assert.NoError(t, err)

	sessionLocked := setupSession(lockedUser.ID)
	_, _, err = svc.FinishLogin(ctx, sessionLocked, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "account is locked")
}
