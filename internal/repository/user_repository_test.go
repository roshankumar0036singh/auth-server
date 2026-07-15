package repository_test

import (
	"testing"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func TestUserRepository(t *testing.T) {
	_, db, _ := testutils.SetupIntegrationTest(t)
	repo := repository.NewUserRepository(db)

	user := &models.User{
		Email:        "user.test@example.com",
		PasswordHash: "hashed",
		FirstName:    "John",
		LastName:     "Doe",
		Role:         "user",
		IsActive:     true,
	}

	t.Run("Create & FindByID & FindByEmail", func(t *testing.T) {
		err := repo.Create(user)
		assert.NoError(t, err)
		assert.NotEmpty(t, user.ID)

		foundByID, err := repo.FindByID(user.ID)
		assert.NoError(t, err)
		assert.Equal(t, user.Email, foundByID.Email)

		foundByEmail, err := repo.FindByEmail(user.Email)
		assert.NoError(t, err)
		assert.Equal(t, user.ID, foundByEmail.ID)

		_, err = repo.FindByID("non-existent-id")
		assert.ErrorIs(t, err, repository.ErrUserNotFound)

		_, err = repo.FindByEmail("non-existent@example.com")
		assert.ErrorIs(t, err, repository.ErrUserNotFound)
	})

	t.Run("EmailExists", func(t *testing.T) {
		exists, err := repo.EmailExists("user.test@example.com")
		assert.NoError(t, err)
		assert.True(t, exists)

		exists, err = repo.EmailExists("unknown@example.com")
		assert.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("GetUsers (Pagination)", func(t *testing.T) {
		paginated, err := repo.GetUsers(10, 0)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, paginated.Total, int64(1))
		assert.NotEmpty(t, paginated.Users)
	})

	t.Run("Update", func(t *testing.T) {
		err := repo.Update(user.ID, map[string]interface{}{"first_name": "Jane"})
		assert.NoError(t, err)

		updated, _ := repo.FindByID(user.ID)
		assert.Equal(t, "Jane", updated.FirstName)

		err = repo.Update("non-existent-id", map[string]interface{}{"first_name": "Nobody"})
		assert.ErrorIs(t, err, repository.ErrUserNotFound)
	})

	t.Run("LockUser & UnlockUser", func(t *testing.T) {
		lockUntil := time.Now().Add(1 * time.Hour)
		err := repo.LockUser(user.ID, lockUntil)
		assert.NoError(t, err)

		locked, _ := repo.FindByID(user.ID)
		assert.NotNil(t, locked.LockedUntil)

		err = repo.UnlockUser(user.ID)
		assert.NoError(t, err)

		unlocked, _ := repo.FindByID(user.ID)
		assert.Nil(t, unlocked.LockedUntil)
	})

	t.Run("WebAuthn Credentials & LoadPasskeys", func(t *testing.T) {
		cred := &models.WebAuthnCredential{
			ID:           "cred-1",
			UserID:       user.ID,
			CredentialID: []byte("passkey-cred-id"),
			Data:         []byte(`{"publicKey": "xyz"}`),
		}
		err := repo.CreateWebAuthnCredential(cred)
		assert.NoError(t, err)

		err = repo.LoadPasskeys(user)
		assert.NoError(t, err)
		assert.Len(t, user.Passkeys, 1)

		err = repo.UpdateWebAuthnCredentialData([]byte("passkey-cred-id"), []byte(`{"publicKey": "new-xyz"}`))
		assert.NoError(t, err)
	})

	t.Run("RunInTx", func(t *testing.T) {
		err := repo.RunInTx(func(u *repository.UserRepository, tr *repository.TokenRepository) error {
			newUser := &models.User{Email: "tx@example.com"}
			return u.Create(newUser)
		})
		assert.NoError(t, err)

		exists, _ := repo.EmailExists("tx@example.com")
		assert.True(t, exists)
	})

	t.Run("Delete", func(t *testing.T) {
		err := repo.Delete(user.ID)
		assert.NoError(t, err)

		_, err = repo.FindByID(user.ID)
		assert.ErrorIs(t, err, repository.ErrUserNotFound)
	})
}
