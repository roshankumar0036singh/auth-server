package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/stretchr/testify/assert"
)

func setupCacheServiceTest(t *testing.T) (*service.CacheService, *miniredis.Miniredis) {
	mr, err := miniredis.Run()
	assert.NoError(t, err)

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	cacheService := service.NewCacheService(rdb)
	return cacheService, mr
}

func TestCacheService_BlacklistToken(t *testing.T) {
	cache, mr := setupCacheServiceTest(t)
	defer mr.Close()

	ctx := context.Background()

	blacklisted, err := cache.IsTokenBlacklisted(ctx, "token-abc")
	assert.NoError(t, err)
	assert.False(t, blacklisted)

	err = cache.BlacklistToken(ctx, "token-abc", 1*time.Minute)
	assert.NoError(t, err)

	blacklisted, err = cache.IsTokenBlacklisted(ctx, "token-abc")
	assert.NoError(t, err)
	assert.True(t, blacklisted)
}

func TestCacheService_Sessions(t *testing.T) {
	cache, mr := setupCacheServiceTest(t)
	defer mr.Close()

	ctx := context.Background()

	err := cache.StoreSession(ctx, "session-123", "user-data", 1*time.Minute)
	assert.NoError(t, err)

	data, err := cache.GetSession(ctx, "session-123")
	assert.NoError(t, err)
	assert.Equal(t, "user-data", data)

	err = cache.DeleteSession(ctx, "session-123")
	assert.NoError(t, err)

	_, err = cache.GetSession(ctx, "session-123")
	assert.ErrorIs(t, err, redis.Nil)
}

func TestCacheService_WebAuthnSessions(t *testing.T) {
	cache, mr := setupCacheServiceTest(t)
	defer mr.Close()

	ctx := context.Background()
	sessionData := webauthn.SessionData{
		Challenge:            "test-challenge",
		UserID:               []byte("user-1"),
		UserVerification:     "preferred",
	}

	err := cache.StoreWebAuthnSession(ctx, "webauthn-sess", "user-1", sessionData, 1*time.Minute)
	assert.NoError(t, err)

	userID, consumedData, err := cache.ConsumeWebAuthnSession(ctx, "webauthn-sess")
	assert.NoError(t, err)
	assert.Equal(t, "user-1", userID)
	assert.Equal(t, "test-challenge", consumedData.Challenge)

	// Consume again should fail since it gets deleted
	_, _, err = cache.ConsumeWebAuthnSession(ctx, "webauthn-sess")
	assert.Error(t, err)
}

func TestCacheService_LoginAttempts(t *testing.T) {
	cache, mr := setupCacheServiceTest(t)
	defer mr.Close()

	ctx := context.Background()
	email := "test@example.com"

	attempts, err := cache.GetLoginAttempts(ctx, email)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), attempts)

	count, err := cache.IncrementLoginAttempts(ctx, email)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count)

	count, err = cache.IncrementLoginAttempts(ctx, email)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), count)

	attempts, err = cache.GetLoginAttempts(ctx, email)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), attempts)

	err = cache.ResetLoginAttempts(ctx, email)
	assert.NoError(t, err)

	attempts, err = cache.GetLoginAttempts(ctx, email)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), attempts)
}

func TestCacheService_MFAAttempts(t *testing.T) {
	cache, mr := setupCacheServiceTest(t)
	defer mr.Close()

	ctx := context.Background()
	userID := "user-mfa-123"

	attempts, err := cache.GetMFAAttempts(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), attempts)

	count, err := cache.IncrementMFAAttempts(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count)

	err = cache.ResetMFAAttempts(ctx, userID)
	assert.NoError(t, err)

	attempts, err = cache.GetMFAAttempts(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), attempts)
}

func TestCacheService_AllowRequest(t *testing.T) {
	cache, mr := setupCacheServiceTest(t)
	defer mr.Close()

	ctx := context.Background()
	key := "rate-key"

	allowed, err := cache.AllowRequest(ctx, key, 2, 1*time.Minute)
	assert.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = cache.AllowRequest(ctx, key, 2, 1*time.Minute)
	assert.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = cache.AllowRequest(ctx, key, 2, 1*time.Minute)
	assert.NoError(t, err)
	assert.False(t, allowed)
}
