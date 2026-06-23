package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupCacheServiceInfrastructure(t *testing.T) (*service.CacheService, *miniredis.Miniredis) {
	// Spin up an isolated miniredis server wrapper for testing
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(func() { mr.Close() })

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	cacheService := service.NewCacheService(rdb)
	return cacheService, mr
}

func TestCacheService_BlacklistTokenLifecycle(t *testing.T) {
	s, _ := setupCacheServiceInfrastructure(t)
	ctx := context.Background()
	token := "sample-jwt-access-token-string"

	// 1. Initially, the token should not be blacklisted
	blacklisted, err := s.IsTokenBlacklisted(ctx, token)
	assert.NoError(t, err)
	assert.False(t, blacklisted)

	// 2. Blacklist the token with a 5-minute TTL window
	err = s.BlacklistToken(ctx, token, 5*time.Minute)
	assert.NoError(t, err)

	// 3. Verify it registers as explicitly blacklisted
	blacklisted, err = s.IsTokenBlacklisted(ctx, token)
	assert.NoError(t, err)
	assert.True(t, blacklisted)
}

func TestCacheService_SessionManagement(t *testing.T) {
	s, _ := setupCacheServiceInfrastructure(t)
	ctx := context.Background()
	sessionID := "sess_abc123"
	sessionData := "user-metadata-payload-string"

	// 1. Save session data payload context
	err := s.StoreSession(ctx, sessionID, sessionData, 1*time.Hour)
	assert.NoError(t, err)

	// 2. Read back and assert data content match
	val, err := s.GetSession(ctx, sessionID)
	assert.NoError(t, err)
	assert.Equal(t, sessionData, val)

	// 3. Wipe out session and check for redis.Nil fallback safety
	err = s.DeleteSession(ctx, sessionID)
	assert.NoError(t, err)

	_, err = s.GetSession(ctx, sessionID)
	assert.ErrorIs(t, err, redis.Nil)
}

func TestCacheService_LoginAttemptsCounterMatrix(t *testing.T) {
	s, mr := setupCacheServiceInfrastructure(t)
	ctx := context.Background()
	email := "security-audit@example.com"

	// 1. Check initial target count values default cleanly to 0
	count, err := s.GetLoginAttempts(ctx, email)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), count)

	// 2. Step up the counter and check incremental growth tracking
	newCount, err := s.IncrementLoginAttempts(ctx, email)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), newCount)

	// Verify TTL eviction window was registered on the key
	mr.FastForward(16 * time.Minute)

	count, err = s.GetLoginAttempts(ctx, email)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), count)

	// 3. Clear metrics using an explicit reset command
	_, _ = s.IncrementLoginAttempts(ctx, email)
	err = s.ResetLoginAttempts(ctx, email)
	assert.NoError(t, err)

	count, err = s.GetLoginAttempts(ctx, email)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestCacheService_MFAAttemptsCounterMatrix(t *testing.T) {
	s, _ := setupCacheServiceInfrastructure(t)
	ctx := context.Background()
	userID := "usr_9999"

	// 1. Verify initial MFA attempt values
	count, err := s.GetMFAAttempts(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), count)

	// 2. Increment failed code entries consecutively
	_, _ = s.IncrementMFAAttempts(ctx, userID)
	currentCount, err := s.IncrementMFAAttempts(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), currentCount)

	// 3. Test Reset clears key entries cleanly
	err = s.ResetMFAAttempts(ctx, userID)
	assert.NoError(t, err)

	count, err = s.GetMFAAttempts(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestCacheService_AllowRequest_RateLimiter(t *testing.T) {
	s, _ := setupCacheServiceInfrastructure(t)
	ctx := context.Background()
	rateKey := "ip_block:192.168.1.50"

	// Enforce strict limit boundary window constraints: Max 2 hits allowed
	allowed, err := s.AllowRequest(ctx, rateKey, 2, 10*time.Second)
	assert.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = s.AllowRequest(ctx, rateKey, 2, 10*time.Second)
	assert.NoError(t, err)
	assert.True(t, allowed)

	// 3rd hit breaches threshold, expect rejection state assertion
	allowed, err = s.AllowRequest(ctx, rateKey, 2, 10*time.Second)
	assert.NoError(t, err)
	assert.False(t, allowed)
}