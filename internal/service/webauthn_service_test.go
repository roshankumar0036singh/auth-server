package service_test

import (
	"context"
	"testing"

	"github.com/go-redis/redis/v8"
	"github.com/roshankumar0036singh/auth-server/internal/config"
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

	svc, err := service.NewWebAuthnService(cfg, userRepo, cacheService, db)
	assert.NoError(t, err)
	assert.NotNil(t, svc)

	ctx := context.Background()
	_, _, err = svc.FinishLogin(ctx, "invalid-session", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired authentication session")
}
