package service_test

import (
	"testing"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestAuthService_Register_Integration(t *testing.T) {
	service, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	req := &dto.RegisterRequest{
		Email:     "newuser@example.com",
		Password:  "Password123!",
		FirstName: "John",
		LastName:  "Doe",
	}

	user, err := service.Register(req)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, req.Email, user.Email)
	assert.False(t, user.EmailVerified)
}

func TestAuthService_Login_Integration(t *testing.T) {
	service, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	// Setup: Create user via Register to ensure hashing
	req := &dto.RegisterRequest{
		Email:     "login@example.com",
		Password:  "Password123!",
		FirstName: "Login",
		LastName:  "User",
	}
	_, err := service.Register(req)
	assert.NoError(t, err)

	// Test Login Success
	loginReq := &dto.LoginRequest{
		Email:    "login@example.com",
		Password: "Password123!",
	}
	resp, err := service.Login(loginReq, "127.0.0.1", "UserAgent")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)

	// Test Login Fail
	loginReqFail := &dto.LoginRequest{
		Email:    "login@example.com",
		Password: "WrongPassword!",
	}
	_, err = service.Login(loginReqFail, "127.0.0.1", "UserAgent")
	assert.Error(t, err)
}

func registerUser(t *testing.T, authSvc *service.AuthService, email string) *models.User {
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
	authSvc, db, _ := testutils.SetupIntegrationTest(t)

	admin := registerUser(t, authSvc, "admin@example.com")
	user := registerUser(t, authSvc, "user@example.com")

	promoteAdmin(t, db, admin.ID)

	require.NoError(t,
		authSvc.LockUser(user.ID, admin.ID, "127.0.0.1", "test-agent"),
	)

	updatedUser, err := repository.NewUserRepository(db).FindByID(user.ID)
	require.NoError(t, err)

	assert.NotNil(t, updatedUser.LockedUntil)
	assert.True(t, updatedUser.IsLocked())

	var tokenCount int64
	db.Model(&models.RefreshToken{}).
		Where("user_id = ?", user.ID).
		Count(&tokenCount)

	assert.Equal(t, int64(0), tokenCount)
}

func TestAuthService_LockUser_TokenRevocation(t *testing.T) {
	authSvc, db, _ := testutils.SetupIntegrationTest(t)

	admin := registerUser(t, authSvc, "admin2@example.com")
	user := registerUser(t, authSvc, "user2@example.com")

	promoteAdmin(t, db, admin.ID)

	require.NoError(t,
		authSvc.LockUser(user.ID, admin.ID, "", ""),
	)

	updatedUser, err := repository.NewUserRepository(db).FindByID(user.ID)
	require.NoError(t, err)

	assert.NotNil(t, updatedUser.LockedUntil)
}

func TestAuthService_LockUser_SelfLock(t *testing.T) {
	authSvc, db, _ := testutils.SetupIntegrationTest(t)

	user := registerUser(t, authSvc, "self@example.com")
	promoteAdmin(t, db, user.ID)

	err := authSvc.LockUser(user.ID, user.ID, "", "")
	assert.ErrorIs(t, err, service.ErrSelfLock)
}

func TestAuthService_LockUser_AdminLock(t *testing.T) {
	authSvc, db, _ := testutils.SetupIntegrationTest(t)

	admin := registerUser(t, authSvc, "admin5@example.com")
	user := registerUser(t, authSvc, "user5@example.com")

	promoteAdmin(t, db, admin.ID)

	err := authSvc.LockUser(admin.ID, user.ID, "", "")
	assert.ErrorIs(t, err, service.ErrAdminLock)
}

func TestAuthService_UnlockUser(t *testing.T) {
	authSvc, db, _ := testutils.SetupIntegrationTest(t)

	admin := registerUser(t, authSvc, "admin3@example.com")
	user := registerUser(t, authSvc, "user3@example.com")

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

func TestAuthService_UnlockUser_WhenNotLocked(t *testing.T) {
	authSvc, db, _ := testutils.SetupIntegrationTest(t)

	admin := registerUser(t, authSvc, "admin4@example.com")
	user := registerUser(t, authSvc, "user4@example.com")

	promoteAdmin(t, db, admin.ID)

	err := authSvc.UnlockUser(user.ID, admin.ID, "", "")
	assert.ErrorIs(t, err, service.ErrNotLocked)
}
