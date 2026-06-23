package repository

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/lib/pq"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestUserConsentRepository(t *testing.T) {
	// Setup isolated in-memory SQLite DB
	db, err := gorm.Open(sqlite.Open("file::memory:?mode=memory&cache=private"), &gorm.Config{})
	assert.NoError(t, err)

	// 🌟 FIX: Manually create a compatible table setup for SQLite to sidestep Postgres gen_random_uuid() / text[] syntax errors
	err = db.Exec(`CREATE TABLE user_consents (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		client_id TEXT NOT NULL,
		scopes TEXT,
		created_at DATETIME,
		updated_at DATETIME
	)`).Error
	assert.NoError(t, err)

	repo := NewUserConsentRepository(db)

	consent := &models.UserConsent{
		ID:       "consent-1",
		UserID:   "user-main",
		ClientID: "client-app-x",
		Scopes:   pq.StringArray{"read", "write", "openid"},
	}

	t.Run("Create", func(t *testing.T) {
		err := repo.Create(consent)
		assert.NoError(t, err)
	})

	t.Run("FindByUserAndClient - Success", func(t *testing.T) {
		found, err := repo.FindByUserAndClient("user-main", "client-app-x")
		assert.NoError(t, err)
		assert.NotNil(t, found)
		assert.Contains(t, found.Scopes, "read")
		assert.Contains(t, found.Scopes, "write")
		assert.Contains(t, found.Scopes, "openid")
	})

	t.Run("FindByUserAndClient - NotFound", func(t *testing.T) {
		found, err := repo.FindByUserAndClient("user-main", "non-existent-app")
		assert.Error(t, err)
		assert.Nil(t, found)
	})

	t.Run("Update", func(t *testing.T) {
		consent.Scopes = pq.StringArray{"read", "openid"}
		err := repo.Update(consent)
		assert.NoError(t, err)

		found, err := repo.FindByUserAndClient("user-main", "client-app-x")
		assert.NoError(t, err)
		assert.Len(t, found.Scopes, 2)
		assert.NotContains(t, found.Scopes, "write")
	})

	t.Run("FindByUser", func(t *testing.T) {
		consent2 := &models.UserConsent{
			ID:       "consent-2",
			UserID:   "user-main",
			ClientID: "client-app-y",
			Scopes:   pq.StringArray{"profile"},
		}
		assert.NoError(t, repo.Create(consent2))

		consents, err := repo.FindByUser("user-main")
		assert.NoError(t, err)
		assert.Len(t, consents, 2, "Should return all consent records for this specific user")
	})

	t.Run("Delete", func(t *testing.T) {
		err := repo.Delete("user-main", "client-app-x")
		assert.NoError(t, err)

		// Verify it was deleted
		found, err := repo.FindByUserAndClient("user-main", "client-app-x")
		assert.Error(t, err)
		assert.Nil(t, found)

		// Verify that the other client consent still stands untouched
		consents, err := repo.FindByUser("user-main")
		assert.NoError(t, err)
		assert.Len(t, consents, 1)
	})
}