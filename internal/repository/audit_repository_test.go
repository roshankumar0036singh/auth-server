package repository

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

// Helper function to turn a string literal into a *string pointer
func strPtr(s string) *string {
	return &s
}

func TestAuditRepository(t *testing.T) {
	// Setup isolated in-memory SQLite DB
	db, err := gorm.Open(sqlite.Open("file::memory:?mode=memory&cache=private"), &gorm.Config{})
	assert.NoError(t, err)

	// 🌟 FIX: Let GORM automatically create the exact table layout based on your Go struct definitions
	err = db.AutoMigrate(&models.AuditLog{})
	assert.NoError(t, err)

	repo := NewAuditRepository(db)

	t.Run("Create", func(t *testing.T) {
		log := &models.AuditLog{
			ID:        "log-1",
			UserID:    strPtr("user-100"),
			Action:    "user.login",
			IPAddress: "127.0.0.1",
			CreatedAt: time.Now(),
		}
		err := repo.Create(log)
		assert.NoError(t, err)
	})

	t.Run("FindByUserID - Limits and Ordering Check", func(t *testing.T) {
		userID := "user-200"
		baseTime := time.Now()

		// Insert an older log entry
		oldLog := &models.AuditLog{
			ID:        "log-old",
			UserID:    strPtr(userID),
			Action:    "user.view_profile",
			CreatedAt: baseTime.Add(-10 * time.Minute),
		}
		assert.NoError(t, repo.Create(oldLog))

		// Insert a newer log entry
		newLog := &models.AuditLog{
			ID:        "log-new",
			UserID:    strPtr(userID),
			Action:    "user.password_change",
			CreatedAt: baseTime,
		}
		assert.NoError(t, repo.Create(newLog))

		// Insert an even newer log entry to test limit boundary truncation
		newestLog := &models.AuditLog{
			ID:        "log-newest",
			UserID:    strPtr(userID),
			Action:    "user.logout",
			CreatedAt: baseTime.Add(10 * time.Minute),
		}
		assert.NoError(t, repo.Create(newestLog))

		// Request logs with a limit of 2. It should only return the 2 most recent logs.
		logs, err := repo.FindByUserID(userID, 2)
		assert.NoError(t, err)
		assert.Len(t, logs, 2, "Should respect the limit parameter")

		// Verify reverse chronological ordering (Created DESC)
		assert.Equal(t, "log-newest", logs[0].ID, "First element must be the newest log")
		assert.Equal(t, "log-new", logs[1].ID, "Second element must be the second newest log")
	})
}