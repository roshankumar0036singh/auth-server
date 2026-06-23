package repository

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestVerificationRepository(t *testing.T) {
	// Setup isolated in-memory SQLite DB
	db, err := gorm.Open(sqlite.Open("file::memory:?mode=memory&cache=private"), &gorm.Config{})
	assert.NoError(t, err)

	// Create table schema locally matching your VerificationToken model
	err = db.Exec(`CREATE TABLE verification_tokens (
		id TEXT PRIMARY KEY,
		token TEXT UNIQUE NOT NULL,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME,
		updated_at DATETIME
	)`).Error
	assert.NoError(t, err)

	repo := NewVerificationRepository(db)

	tokenData := &models.VerificationToken{
		ID:        "verify-id-1",
		Token:     "verify-token-string-123",
		UserID:    "user-id-555",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	t.Run("Create", func(t *testing.T) {
		err := repo.Create(tokenData)
		assert.NoError(t, err)
	})

	t.Run("FindByToken - Success", func(t *testing.T) {
		found, err := repo.FindByToken("verify-token-string-123")
		assert.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, "user-id-555", found.UserID)
	})

	t.Run("FindByToken - Invalid Token Error Handling", func(t *testing.T) {
		found, err := repo.FindByToken("non-existent-token")
		assert.Error(t, err)
		assert.Nil(t, found)
		assert.Equal(t, "invalid token", err.Error())
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		expiredToken := &models.VerificationToken{
			ID:        "verify-id-expired",
			Token:     "expired-verify-token",
			UserID:    "user-id-777",
			ExpiresAt: time.Now().Add(-10 * time.Minute),
		}
		err := repo.Create(expiredToken)
		assert.NoError(t, err)

		err = repo.DeleteExpired()
		assert.NoError(t, err)

		// Verification to confirm it's gone
		_, err = repo.FindByToken("expired-verify-token")
		assert.Error(t, err)
	})

	t.Run("DeleteByUserID", func(t *testing.T) {
		err := repo.DeleteByUserID("user-id-555")
		assert.NoError(t, err)

		// Verification to confirm the original token was successfully removed
		_, err = repo.FindByToken("verify-token-string-123")
		assert.Error(t, err)
	})
}