package repository

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestOAuthClientRepository(t *testing.T) {
	// Setup localized in-memory SQLite DB
	db, err := gorm.Open(sqlite.Open("file::memory:?mode=memory&cache=private"), &gorm.Config{})
	assert.NoError(t, err)

	// Create table schema locally using raw SQL matching your setup definitions
	err = db.Exec(`CREATE TABLE oauth_clients (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		client_id TEXT UNIQUE NOT NULL,
		client_secret TEXT NOT NULL,
		redirect_uris TEXT,
		scopes TEXT,
		owner_id TEXT,
		is_active INTEGER DEFAULT 1,
		is_public INTEGER DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	)`).Error
	assert.NoError(t, err)

	repo := NewOAuthClientRepository(db)

	client := &models.OAuthClient{
		ID:           "id-client-1",
		Name:         "Test App",
		ClientID:     "client-id-123",
		ClientSecret: "super-secret-key",
		OwnerID:      "user-owner-99",
	}

	t.Run("Create", func(t *testing.T) {
		err := repo.Create(client)
		assert.NoError(t, err)
	})

	t.Run("FindByClientID", func(t *testing.T) {
		found, err := repo.FindByClientID("client-id-123")
		assert.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, "Test App", found.Name)
	})

	t.Run("FindByClientID NotFound", func(t *testing.T) {
		found, err := repo.FindByClientID("non-existent-client")
		assert.Error(t, err)
		assert.Nil(t, found)
	})

	t.Run("FindByID", func(t *testing.T) {
		found, err := repo.FindByID("id-client-1")
		assert.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, "client-id-123", found.ClientID)
	})

	t.Run("FindByID NotFound", func(t *testing.T) {
		found, err := repo.FindByID("invalid-uuid")
		assert.Error(t, err)
		assert.Nil(t, found)
	})

	t.Run("FindByOwner", func(t *testing.T) {
		clients, err := repo.FindByOwner("user-owner-99")
		assert.NoError(t, err)
		assert.Len(t, clients, 1)
		assert.Equal(t, "id-client-1", clients[0].ID)
	})

	t.Run("FindAll", func(t *testing.T) {
		clients, err := repo.FindAll()
		assert.NoError(t, err)
		assert.NotEmpty(t, clients)
	})

	t.Run("Update", func(t *testing.T) {
		client.Name = "Updated Test App Name"
		err := repo.Update(client)
		assert.NoError(t, err)

		found, err := repo.FindByID("id-client-1")
		assert.NoError(t, err)
		assert.Equal(t, "Updated Test App Name", found.Name)
	})

	t.Run("Delete", func(t *testing.T) {
		err := repo.Delete("id-client-1")
		assert.NoError(t, err)

		found, err := repo.FindByID("id-client-1")
		assert.Error(t, err)
		assert.Nil(t, found)
	})
}