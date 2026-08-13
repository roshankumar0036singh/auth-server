package service_test

import (
	"testing"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func TestAuthService_Register(t *testing.T) {
	authService, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	req := &dto.RegisterRequest{
		Email:     "newuser@example.com",
		Password:  "StrongP@ss123",
		FirstName: "Alice",
		LastName:  "Wonderland",
	}

	user, err := authService.Register(req)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "newuser@example.com", user.Email)
	assert.False(t, user.EmailVerified)

	// Test duplicate email
	_, err = authService.Register(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email already registered")

	// Test weak password
	weakReq := &dto.RegisterRequest{
		Email:    "weak@example.com",
		Password: "123",
	}
	_, err = authService.Register(weakReq)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be at least 8 characters")

	// Check verification token created in DB
	var vToken models.VerificationToken
	err = db.Where("user_id = ?", user.ID).First(&vToken).Error
	assert.NoError(t, err)
	assert.NotEmpty(t, vToken.Token)
}

func TestAuthService_VerifyEmail(t *testing.T) {
	authService, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	req := &dto.RegisterRequest{
		Email:    "verify@example.com",
		Password: "StrongP@ss123",
	}
	user, err := authService.Register(req)
	assert.NoError(t, err)

	var vToken models.VerificationToken
	db.Where("user_id = ?", user.ID).First(&vToken)

	// Verify with valid token
	err = authService.VerifyEmail(vToken.Token)
	assert.NoError(t, err)

	userRepo := repository.NewUserRepository(db)
	verifiedUser, _ := userRepo.FindByID(user.ID)
	assert.True(t, verifiedUser.EmailVerified)

	// Verify with invalid token
	err = authService.VerifyEmail("invalid-token-string")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired verification token")

	// Verify with expired token
	expiredToken := &models.VerificationToken{
		UserID:    user.ID,
		Token:     "expired-token-123",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	db.Create(expiredToken)
	err = authService.VerifyEmail("expired-token-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification token has expired")
}

func TestAuthService_ResendVerification(t *testing.T) {
	authService, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	req := &dto.RegisterRequest{
		Email:    "resend@example.com",
		Password: "StrongP@ss123",
	}
	user, _ := authService.Register(req)

	err := authService.ResendVerification("resend@example.com")
	assert.NoError(t, err)

	// Verify resend fails if already verified
	var vToken models.VerificationToken
	db.Where("user_id = ?", user.ID).First(&vToken)
	authService.VerifyEmail(vToken.Token)

	err = authService.ResendVerification("resend@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email already verified")

	// Verify resend fails if user not found
	err = authService.ResendVerification("nobody@example.com")
	assert.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrUserNotFound)
}

func TestAuthService_LoginDeactivatedAccountRejectedBeforePasswordCheck(t *testing.T) {
	authService, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	req := &dto.RegisterRequest{
		Email:    "deactivated@example.com",
		Password: "StrongP@ss123",
	}
	user, err := authService.Register(req)
	assert.NoError(t, err)

	// Deactivate the account
	err = db.Model(user).Update("is_active", false).Error
	assert.NoError(t, err)

	// Correct password, deactivated account -> must be rejected as deactivated
	// (NOT as "invalid email or password", which would mean the password was
	// verified before the IsActive check).
	_, err = authService.Login(&dto.LoginRequest{
		Email:    "deactivated@example.com",
		Password: "StrongP@ss123",
	}, "127.0.0.1", "test-agent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "account is deactivated")

	// Even a wrong password must report the deactivation, never the password
	// result (the bcrypt compare must not run for deactivated accounts).
	_, err = authService.Login(&dto.LoginRequest{
		Email:    "deactivated@example.com",
		Password: "DefinitelyWrongP@ss",
	}, "127.0.0.1", "test-agent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "account is deactivated")
}
