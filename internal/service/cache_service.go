package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	cacheKeySession       = "session:%s"
	cacheKeyLoginAttempts = "login_attempts:%s"
	cacheKeyMFAAttempts   = "mfa_attempts:%s"
)

var incrExpireScript = redis.NewScript(`
	local count = redis.call("INCR", KEYS[1])
	if count == 1 then
		redis.call("PEXPIRE", KEYS[1], ARGV[1])
	end
	return count
`)

type CacheService struct {
	client *redis.Client
}

func NewCacheService(client *redis.Client) *CacheService {
	return &CacheService{client: client}
}

// BlacklistToken adds a token to the blacklist (for logout)
func (s *CacheService) BlacklistToken(ctx context.Context, token string, expiry time.Duration) error {
	key := fmt.Sprintf("blacklist:%s", token)
	return s.client.Set(ctx, key, "1", expiry).Err()
}

// IsTokenBlacklisted checks if a token is blacklisted
func (s *CacheService) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	key := fmt.Sprintf("blacklist:%s", token)
	result, err := s.client.Get(ctx, key).Result()

	if err == redis.Nil {
		return false, nil // Not blacklisted
	}
	if err != nil {
		return false, err // Error occurred
	}

	return result == "1", nil
}

// StoreSession stores session data in Redis
func (s *CacheService) StoreSession(ctx context.Context, sessionID string, data interface{}, expiry time.Duration) error {
	key := fmt.Sprintf(cacheKeySession, sessionID)
	return s.client.Set(ctx, key, data, expiry).Err()
}

// GetSession retrieves session data from Redis
func (s *CacheService) GetSession(ctx context.Context, sessionID string) (string, error) {
	key := fmt.Sprintf(cacheKeySession, sessionID)
	return s.client.Get(ctx, key).Result()
}

// DeleteSession removes a session from Redis
func (s *CacheService) DeleteSession(ctx context.Context, sessionID string) error {
	key := fmt.Sprintf(cacheKeySession, sessionID)
	return s.client.Del(ctx, key).Err()
}

type WebAuthnSession struct {
	UserID      string               `json:"user_id"`
	SessionData webauthn.SessionData `json:"session_data"`
}

func (s *CacheService) StoreWebAuthnSession(ctx context.Context, sessionID string, userID string, data webauthn.SessionData, expiry time.Duration) error {
	key := fmt.Sprintf("webauthn_session:%s", sessionID)
	payload := WebAuthnSession{
		UserID:      userID,
		SessionData: data,
	}
	bytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, key, bytes, expiry).Err()
}

func (s *CacheService) ConsumeWebAuthnSession(ctx context.Context, sessionID string) (string, webauthn.SessionData, error) {
	key := fmt.Sprintf("webauthn_session:%s", sessionID)
	val, err := s.client.GetDel(ctx, key).Result()
	if err != nil {
		return "", webauthn.SessionData{}, err
	}
	var data WebAuthnSession
	err = json.Unmarshal([]byte(val), &data)
	return data.UserID, data.SessionData, err
}

// IncrementLoginAttempts increments failed login attempts for an email
func (s *CacheService) IncrementLoginAttempts(ctx context.Context, email string) (int64, error) {
	key := fmt.Sprintf(cacheKeyLoginAttempts, email)
	count, err := incrExpireScript.Run(ctx, s.client, []string{key}, (15 * time.Minute).Milliseconds()).Int64()
	if err != nil {
		return 0, err
	}

	return count, nil
}

// GetLoginAttempts gets the number of failed login attempts
func (s *CacheService) GetLoginAttempts(ctx context.Context, email string) (int64, error) {
	key := fmt.Sprintf(cacheKeyLoginAttempts, email)
	count, err := s.client.Get(ctx, key).Int64()

	if err == redis.Nil {
		return 0, nil
	}
	return count, err
}

// ResetLoginAttempts resets failed login attempts for an email
func (s *CacheService) ResetLoginAttempts(ctx context.Context, email string) error {
	key := fmt.Sprintf(cacheKeyLoginAttempts, email)
	return s.client.Del(ctx, key).Err()
}

// IncrementMFAAttempts increments failed MFA code attempts for a user.
func (s *CacheService) IncrementMFAAttempts(ctx context.Context, userID string) (int64, error) {
	key := fmt.Sprintf(cacheKeyMFAAttempts, userID)
	count, err := incrExpireScript.Run(ctx, s.client, []string{key}, (15 * time.Minute).Milliseconds()).Int64()
	if err != nil {
		return 0, err
	}

	return count, nil
}

// GetMFAAttempts gets the number of failed MFA code attempts for a user.
func (s *CacheService) GetMFAAttempts(ctx context.Context, userID string) (int64, error) {
	key := fmt.Sprintf(cacheKeyMFAAttempts, userID)
	count, err := s.client.Get(ctx, key).Int64()

	if err == redis.Nil {
		return 0, nil
	}
	return count, err
}

// ResetMFAAttempts resets failed MFA code attempts for a user.
func (s *CacheService) ResetMFAAttempts(ctx context.Context, userID string) error {
	key := fmt.Sprintf(cacheKeyMFAAttempts, userID)
	return s.client.Del(ctx, key).Err()
}

// AllowRequest checks if a request is allowed based on rate limiting logic
func (s *CacheService) AllowRequest(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	count, err := incrExpireScript.Run(ctx, s.client, []string{key}, window.Milliseconds()).Int64()
	if err != nil {
		return false, err
	}

	return count <= int64(limit), nil
}
