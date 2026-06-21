package service

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/stretchr/testify/assert"
)

func setupCacheServiceTest(t *testing.T) (*CacheService, *miniredis.Miniredis) {
	mr, err := miniredis.Run()
	assert.NoError(t, err)

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	cacheService := NewCacheService(rdb)
	return cacheService, mr
}

func TestCacheService_AcquireAndReleaseLock(t *testing.T) {
	cacheService, mr := setupCacheServiceTest(t)
	defer mr.Close()

	ctx := context.Background()
	lockKey := "test_lock_123"

	// 1. Acquire lock successfully
	acquired, err := cacheService.AcquireLock(ctx, lockKey, 5*time.Second)
	assert.NoError(t, err)
	assert.True(t, acquired, "should successfully acquire a free lock")

	// 2. Try to acquire the same lock, should fail
	acquiredAgain, err := cacheService.AcquireLock(ctx, lockKey, 5*time.Second)
	assert.NoError(t, err)
	assert.False(t, acquiredAgain, "should fail to acquire an already held lock")

	// 3. Release the lock
	err = cacheService.ReleaseLock(ctx, lockKey)
	assert.NoError(t, err)

	// 4. Acquire again, should succeed after release
	acquiredAfterRelease, err := cacheService.AcquireLock(ctx, lockKey, 5*time.Second)
	assert.NoError(t, err)
	assert.True(t, acquiredAfterRelease, "should successfully acquire lock after it was released")
}

func TestCacheService_CacheAndGetRefreshResponse(t *testing.T) {
	cacheService, mr := setupCacheServiceTest(t)
	defer mr.Close()

	ctx := context.Background()
	tokenKey := "grace_period_token_456"

	response := &dto.TokenRefreshResponse{
		AccessToken:  "new_access_token_abc",
		RefreshToken: "new_refresh_token_def",
	}

	// 1. Get non-existent should return nil without error
	cached, err := cacheService.GetCachedRefreshResponse(ctx, tokenKey)
	assert.NoError(t, err)
	assert.Nil(t, cached, "should return nil for non-existent key")

	// 2. Cache the response
	err = cacheService.CacheRefreshResponse(ctx, tokenKey, response, 5*time.Second)
	assert.NoError(t, err)

	// 3. Retrieve the cached response
	cachedAgain, err := cacheService.GetCachedRefreshResponse(ctx, tokenKey)
	assert.NoError(t, err)
	assert.NotNil(t, cachedAgain)
	assert.Equal(t, response.AccessToken, cachedAgain.AccessToken)
	assert.Equal(t, response.RefreshToken, cachedAgain.RefreshToken)
}
