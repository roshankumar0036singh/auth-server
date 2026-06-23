package repository

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestPasswordResetRepository(t *testing.T) {
	// Setup isolated in-memory SQLite DB
	db, err := gorm.Open(sqlite.Open("file::memory:?mode=memory&cache=private"), &gorm.Config{})
	assert.NoError(t, err)

	// Create table schema locally matching your application's PasswordResetToken model fields
	err = db.Exec(`CREATE TABLE password_reset_tokens (
		id TEXT PRIMARY KEY,
		token TEXT UNIQUE NOT NULL,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		used INTEGER DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	)`).Error
	assert.NoError(t, err)

	repo := NewPasswordResetRepository(db)

	tokenData := &models.PasswordResetToken{
		ID:        "reset-id-1",
		Token:     "reset-token-secret-xyz",
		UserID:    "user-id-abc",
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Used:      false,
	}

	t.Run("Create", func(t *testing.T) {
		err := repo.Create(tokenData)
		assert.NoError(t, err)
	})

	t.Run("FindByToken - Success", func(t *testing.T) {
		found, err := repo.FindByToken("reset-token-secret-xyz")
		assert.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, "user-id-abc", found.UserID)
	})

	t.Run("FindByToken - Invalid Token Error Handling", func(t *testing.T) {
		found, err := repo.FindByToken("completely-fake-token")
		assert.Error(t, err)
		assert.Nil(t, found)
		assert.Equal(t, "invalid token", err.Error(), "Should match the custom GORM record mapping")
	})

	t.Run("MarkAsUsed", func(t *testing.T) {
		err := repo.MarkAsUsed("reset-id-1")
		assert.NoError(t, err)

		found, err := repo.FindByToken("reset-token-secret-xyz")
		assert.NoError(t, err)
		// SQLite treats booleans as integers (0/1). GORM maps this correctly.
		assert.True(t, found.Used)
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		expiredToken := &models.PasswordResetToken{
			ID:        "reset-id-expired",
			Token:     "expired-token-string",
			UserID:    "user-id-abc",
			ExpiresAt: time.Now().Add(-1 * time.Minute),
			Used:      false,
		}
		err := repo.Create(expiredToken)
		assert.NoError(t, err)

		err = repo.DeleteExpired()
		assert.NoError(t, err)

		// Confirm it was removed from the database
		_, err = repo.FindByToken("expired-token-string")
		assert.Error(t, err)
	})

	t.Run("DeleteByUserID", func(t *testing.T) {
		err := repo.DeleteByUserID("user-id-abc")
		assert.NoError(t, err)

		// Verification should confirm the original valid token is now also gone
		_, err = repo.FindByToken("reset-token-secret-xyz")
		assert.Error(t, err)
	})
}