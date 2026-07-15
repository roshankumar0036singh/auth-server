package repository_test

import (
	"testing"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func TestTokenRepository(t *testing.T) {
	_, db, _ := testutils.SetupIntegrationTest(t)
	repo := repository.NewTokenRepository(db)

	userID := "user-token-repo-1"
	token := &models.RefreshToken{
		UserID:    userID,
		Token:     "refresh-token-123",
		FamilyID:  "family-1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IsRevoked: false,
	}

	t.Run("CreateRefreshToken", func(t *testing.T) {
		err := repo.CreateRefreshToken(token)
		assert.NoError(t, err)
		assert.NotEmpty(t, token.ID)
	})

	t.Run("FindRefreshToken", func(t *testing.T) {
		found, err := repo.FindRefreshToken("refresh-token-123")
		assert.NoError(t, err)
		assert.Equal(t, userID, found.UserID)

		_, err = repo.FindRefreshToken("non-existent")
		assert.ErrorIs(t, err, repository.ErrRefreshTokenNotFound)
	})

	t.Run("FindRefreshTokenByID", func(t *testing.T) {
		found, err := repo.FindRefreshTokenByID(token.ID)
		assert.NoError(t, err)
		assert.Equal(t, token.Token, found.Token)
	})

	t.Run("FindUserRefreshTokens & CountUserActiveSessions", func(t *testing.T) {
		tokens, err := repo.FindUserRefreshTokens(userID)
		assert.NoError(t, err)
		assert.Len(t, tokens, 1)

		count, err := repo.CountUserActiveSessions(userID)
		assert.NoError(t, err)
		assert.Equal(t, int64(1), count)
	})

	t.Run("RotateRefreshToken", func(t *testing.T) {
		newToken := &models.RefreshToken{
			UserID:    userID,
			Token:     "refresh-token-456",
			FamilyID:  "family-1",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		err := repo.RotateRefreshToken("refresh-token-123", newToken)
		assert.NoError(t, err)

		old, err := repo.FindRefreshToken("refresh-token-123")
		assert.NoError(t, err)
		assert.True(t, old.IsRevoked)

		current, err := repo.FindActiveTokenInFamily("family-1")
		assert.NoError(t, err)
		assert.Equal(t, "refresh-token-456", current.Token)
	})

	t.Run("RevokeRefreshToken", func(t *testing.T) {
		err := repo.RevokeRefreshToken("refresh-token-456")
		assert.NoError(t, err)

		revoked, _ := repo.FindRefreshToken("refresh-token-456")
		assert.True(t, revoked.IsRevoked)
	})

	t.Run("RevokeTokenFamily", func(t *testing.T) {
		token2 := &models.RefreshToken{
			UserID:    userID,
			Token:     "token-fam-2",
			FamilyID:  "family-xyz",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		repo.CreateRefreshToken(token2)

		err := repo.RevokeTokenFamily("family-xyz")
		assert.NoError(t, err)

		active, err := repo.FindActiveTokenInFamily("family-xyz")
		assert.NoError(t, err)
		assert.Nil(t, active)
	})

	t.Run("RevokeAllUserTokens", func(t *testing.T) {
		token3 := &models.RefreshToken{
			UserID:    userID,
			Token:     "token-user-all",
			FamilyID:  "family-abc",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		repo.CreateRefreshToken(token3)

		err := repo.RevokeAllUserTokens(userID)
		assert.NoError(t, err)

		tokens, err := repo.FindUserRefreshTokens(userID)
		assert.NoError(t, err)
		assert.Len(t, tokens, 0)
	})
}
