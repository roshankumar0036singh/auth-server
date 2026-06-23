package repository

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestOAuthTokenRepository(t *testing.T) {
	// Setup isolated in-memory SQLite DB
	db, err := gorm.Open(sqlite.Open("file::memory:?mode=memory&cache=private"), &gorm.Config{})
	assert.NoError(t, err)

	// Create table schema locally matching your application model names
	err = db.Exec(`CREATE TABLE oauth_access_tokens (
		id TEXT PRIMARY KEY,
		token TEXT UNIQUE NOT NULL,
		client_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		scopes TEXT,
		expires_at DATETIME NOT NULL,
		is_revoked INTEGER DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	)`).Error
	assert.NoError(t, err)

	repo := NewOAuthTokenRepository(db)

	token1 := &models.OAuthAccessToken{
		ID:        "token-uuid-1",
		Token:     "access-token-string-123",
		ClientID:  "client-app-a",
		UserID:    "user-id-99",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	t.Run("Create", func(t *testing.T) {
		err := repo.Create(token1)
		assert.NoError(t, err)
	})

	t.Run("FindByToken", func(t *testing.T) {
		found, err := repo.FindByToken("access-token-string-123")
		assert.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, "user-id-99", found.UserID)
	})

	t.Run("FindByToken NotFound", func(t *testing.T) {
		found, err := repo.FindByToken("non-existent-token")
		assert.Error(t, err)
		assert.Nil(t, found)
	})

	t.Run("FindByUserAndClient", func(t *testing.T) {
		tokens, err := repo.FindByUserAndClient("user-id-99", "client-app-a")
		assert.NoError(t, err)
		assert.Len(t, tokens, 1)
		assert.Equal(t, "access-token-string-123", tokens[0].Token)
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		expiredToken := &models.OAuthAccessToken{
			ID:        "token-uuid-expired",
			Token:     "expired-token-string",
			ClientID:  "client-app-a",
			UserID:    "user-id-99",
			ExpiresAt: time.Now().Add(-5 * time.Minute),
		}
		err := repo.Create(expiredToken)
		assert.NoError(t, err)

		err = repo.DeleteExpired()
		assert.NoError(t, err)

		// Confirm it's gone
		found, err := repo.FindByToken("expired-token-string")
		assert.Error(t, err)
		assert.Nil(t, found)
	})

	t.Run("RevokeByUserAndClient", func(t *testing.T) {
		err := repo.RevokeByUserAndClient("user-id-99", "client-app-a")
		assert.NoError(t, err)

		// Verification should show the token array is now empty
		tokens, err := repo.FindByUserAndClient("user-id-99", "client-app-a")
		assert.NoError(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("RevokeByClient", func(t *testing.T) {
		// Insert a fresh token to test client-wide revocation
		token2 := &models.OAuthAccessToken{
			ID:        "token-uuid-2",
			Token:     "access-token-string-456",
			ClientID:  "client-app-b",
			UserID:    "user-id-100",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		_ = repo.Create(token2)

		err := repo.RevokeByClient("client-app-b")
		assert.NoError(t, err)

		found, err := repo.FindByToken("access-token-string-456")
		assert.Error(t, err)
		assert.Nil(t, found)
	})
}