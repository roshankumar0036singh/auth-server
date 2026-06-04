package service

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type mockEmailSender struct{}

func (m *mockEmailSender) SendVerificationEmail(email, token, appURL string) error {
	return nil
}

func (m *mockEmailSender) SendPasswordResetEmail(email, token, appURL string) error {
	return nil
}

func setupAuthService(t *testing.T) (*AuthService, *gorm.DB) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.VerificationToken{},
		&models.PasswordResetToken{},
		&models.AuditLog{},
	))

	userRepo := repository.NewUserRepository(db)

	cfg := &config.Config{
		JWT: config.JWTConfig{
			AccessSecret:  "secret",
			RefreshSecret: "refresh",
		},
	}

	authService := NewAuthService(
		userRepo,
		repository.NewTokenRepository(db),
		repository.NewVerificationRepository(db),
		repository.NewPasswordResetRepository(db),
		NewTokenService(cfg),
		nil,
		&mockEmailSender{},
		NewAuditService(repository.NewAuditRepository(db)),
		nil,
		cfg,
	)

	return authService, db
}

func registerUser(t *testing.T, authSvc *AuthService, email string) *models.User {
	t.Helper()

	user, err := authSvc.Register(&dto.RegisterRequest{
		Email:     email,
		Password:  "Password123!",
		FirstName: "Test",
		LastName:  "User",
	})
	require.NoError(t, err)

	return user
}

func promoteAdmin(t *testing.T, db *gorm.DB, userID string) {
	t.Helper()

	require.NoError(t,
		db.Model(&models.User{}).
			Where("id = ?", userID).
			Update("role", "admin").Error,
	)
}

func TestAuthService_LockUser(t *testing.T) {
	authSvc, db := setupAuthService(t)

	admin := registerUser(t, authSvc, "admin@example.com")
	user := registerUser(t, authSvc, "user@example.com")

	promoteAdmin(t, db, admin.ID)

	require.NoError(t,
		authSvc.LockUser(user.ID, admin.ID, "", ""),
	)

	updatedUser, err := repository.NewUserRepository(db).FindByID(user.ID)
	require.NoError(t, err)

	assert.NotNil(t, updatedUser.LockedUntil)
}

func TestAuthService_UnlockUser(t *testing.T) {
	authSvc, db := setupAuthService(t)

	admin := registerUser(t, authSvc, "admin1@example.com")
	user := registerUser(t, authSvc, "user1@example.com")

	promoteAdmin(t, db, admin.ID)

	require.NoError(t,
		authSvc.LockUser(user.ID, admin.ID, "", ""),
	)

	require.NoError(t,
		authSvc.UnlockUser(user.ID, admin.ID, "", ""),
	)

	updatedUser, err := repository.NewUserRepository(db).FindByID(user.ID)
	require.NoError(t, err)

	assert.Nil(t, updatedUser.LockedUntil)
}