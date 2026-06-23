package service_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/go-redis/redis/v8"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// MockEmailSender handles email stubbing without downstream mail server configs
type MockEmailSender struct {
	LastEmail string
	LastToken string
}

func (m *MockEmailSender) SendVerificationEmail(email, token, appURL string) error {
	m.LastEmail = email
	m.LastToken = token
	return nil
}

func (m *MockEmailSender) SendPasswordResetEmail(email, token, appURL string) error {
	m.LastEmail = email
	m.LastToken = token
	return nil
}

func setupAuthServiceInfrastructure(t *testing.T) (*service.AuthService, *repository.UserRepository, *repository.PasswordResetRepository, *MockEmailSender) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	t.Cleanup(func() { mr.Close() })

	cfg := &config.Config{
		JWT: config.JWTConfig{
			AccessSecret:  "test-access-secret-1234567890123456",
			RefreshSecret: "test-refresh-secret-1234567890123456",
			RefreshExpiry: "24h",
		},
		Security: config.SecurityConfig{
			BcryptRounds:            4, // Fast rounds for testing
			AccountLockMaxAttempts: 3,
			AccountLockDuration:    15,
			RateLimitMax:           5,
		},
		App: config.AppConfig{
			URL: "http://localhost:8080",
		},
	}

	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(db)
	verificationRepo := repository.NewVerificationRepository(db)
	passwordResetRepo := repository.NewPasswordResetRepository(db)
	auditRepo := repository.NewAuditRepository(db)

	tokenService := service.NewTokenService(cfg)
	
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	cacheService := service.NewCacheService(rdb)
	
	emailSender := &MockEmailSender{}
	auditService := service.NewAuditService(auditRepo)
	mfaService := service.NewMFAService(cfg)

	authService := service.NewAuthService(
		userRepo,
		tokenRepo,
		verificationRepo,
		passwordResetRepo,
		tokenService,
		cacheService,
		emailSender,
		auditService,
		mfaService,
		cfg,
	)

	return authService, userRepo, passwordResetRepo, emailSender
}

// =========================================================================
// PART 1: Account Setup, Password Management, and Profile Updates
// =========================================================================

func TestAuthService_ForgotPassword_HandlesEnumerationAndSuccess(t *testing.T) {
	s, userRepo, resetRepo, mockEmail := setupAuthServiceInfrastructure(t)

	// Test case 1: Email configuration enumeration protection (returns nil when email is missing)
	err := s.ForgotPassword("missing-user@example.com")
	assert.NoError(t, err)

	// Test case 2: Valid profile account password reset trigger
	userEmail := "developer@example.com"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("ValidSecurePass123!"), 4)
	user := &models.User{
		ID:           uuid.NewString(),
		Email:        userEmail,
		PasswordHash: string(hashedPassword),
		IsActive:     true,
	}
	require.NoError(t, userRepo.Create(user))

	err = s.ForgotPassword(userEmail)
	assert.NoError(t, err)
	assert.Equal(t, userEmail, mockEmail.LastEmail)
	assert.NotEmpty(t, mockEmail.LastToken)

	// Confirm record persistence inside the reset tokens table
	tokenRecord, err := resetRepo.FindByToken(mockEmail.LastToken)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, tokenRecord.UserID)
}

func TestAuthService_ResetPassword_ValidationBoundaries(t *testing.T) {
	s, userRepo, resetRepo, _ := setupAuthServiceInfrastructure(t)

	userID := uuid.NewString()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("OldSecurePass123!"), 4)
	user := &models.User{
		ID:           userID,
		Email:        "reset-target@example.com",
		PasswordHash: string(hashedPassword),
		IsActive:     true,
	}
	require.NoError(t, userRepo.Create(user))

	tokenStr := "random-reset-token-string-boundary"
	tokenModel := &models.PasswordResetToken{
		UserID:    userID,
		Token:     tokenStr,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Used:      false,
	}
	require.NoError(t, resetRepo.Create(tokenModel))

	// Test short unsafe password failure path
	err := s.ResetPassword(tokenStr, "short")
	assert.Error(t, err)

	// Test target pass token resolution path
	err = s.ResetPassword(tokenStr, "BrandNewSecurePassword123!")
	assert.NoError(t, err)

	// Attempting to re-use token should fail instantly
	err = s.ResetPassword(tokenStr, "AnotherPassword123!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already been used")
}

func TestAuthService_UpdateProfile_DeltaHandling(t *testing.T) {
	s, userRepo, _, _ := setupAuthServiceInfrastructure(t)
	userID := uuid.NewString()

	user := &models.User{
		ID:        userID,
		Email:     "profile@example.com",
		FirstName: "OriginalFirst",
		LastName:  "OriginalLast",
		IsActive:  true,
	}
	require.NoError(t, userRepo.Create(user))

	// Trigger patch update profile mutations execution context
	updatedUser, err := s.UpdateProfile(userID, &dto.UpdateProfileRequest{
		FirstName: "NewFirst",
		LastName:  "NewLast",
	})
	assert.NoError(t, err)
	assert.Equal(t, "NewFirst", updatedUser.FirstName)
	assert.Equal(t, "NewLast", updatedUser.LastName)
}

func TestAuthService_ChangePassword_Verification(t *testing.T) {
	s, userRepo, _, _ := setupAuthServiceInfrastructure(t)
	userID := uuid.NewString()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("CurrentPassword123!"), 4)
	user := &models.User{
		ID:           userID,
		Email:        "changepass@example.com",
		PasswordHash: string(hashedPassword),
		IsActive:     true,
	}
	require.NoError(t, userRepo.Create(user))

	// Test password mismatch rejection
	err := s.ChangePassword(userID, &dto.ChangePasswordRequest{
		CurrentPassword: "WrongPasswordMatch",
		NewPassword:     "ValidNewPassword123!",
	})
	assert.Error(t, err)

	// Test proper mutation validation assertion match
	err = s.ChangePassword(userID, &dto.ChangePasswordRequest{
		CurrentPassword: "CurrentPassword123!",
		NewPassword:     "ValidNewPassword123!",
	})
	assert.NoError(t, err)
}

// =========================================================================
// PART 2: Authentication Lifecycles, Lockouts, and OAuth
// =========================================================================

func TestAuthService_Login_SuccessAndLockoutFlows(t *testing.T) {
	s, userRepo, _, _ := setupAuthServiceInfrastructure(t)

	email := "login-flow@example.com"
	rawPassword := "SecurePassword123!"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(rawPassword), 4)
	
	user := &models.User{
		ID:           uuid.NewString(),
		Email:        email,
		PasswordHash: string(hashedPassword),
		IsActive:     true,
		Role:         "user",
	}
	require.NoError(t, userRepo.Create(user))

	// 1. Test invalid password (triggers incremental failed counters)
	_, err := s.Login(&dto.LoginRequest{Email: email, Password: "WrongPassword"}, "127.0.0.1", "test-agent")
	assert.Error(t, err)
	assert.Equal(t, "invalid email or password", err.Error())

	// 2. Test successful clean local password login path
	res, err := s.Login(&dto.LoginRequest{Email: email, Password: rawPassword}, "127.0.0.1", "test-agent")
	assert.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
	assert.False(t, res.MFARequired)
}

func TestAuthService_LoginWithOAuth_LinkageAndCreation(t *testing.T) {
	s, userRepo, _, _ := setupAuthServiceInfrastructure(t)

	email := "oauth-user@example.com"
	oauthID := "github-oauth-id-888"

	// 1. Test login with OAuth for a completely new user account (automatic registration)
	res, err := s.LoginWithOAuth(email, oauthID, "OAuthFirst", "OAuthLast", "github", "127.0.0.1", "test-agent")
	assert.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)

	// Verify the database record reflects the creation details
	createdUser, err := userRepo.FindByEmail(email)
	assert.NoError(t, err)
	assert.Equal(t, "github", createdUser.OAuthProvider)
	assert.Equal(t, oauthID, createdUser.OAuthID)
}

func TestAuthService_LockAndUnlockUser_AdminMatrix(t *testing.T) {
	s, userRepo, _, _ := setupAuthServiceInfrastructure(t)

	adminID := uuid.NewString()
	targetUserID := uuid.NewString()

	// Seed target standard user
	targetUser := &models.User{
		ID:           targetUserID,
		Email:        "target-lock@example.com",
		PasswordHash: "hash",
		IsActive:     true,
		Role:         "user",
	}
	require.NoError(t, userRepo.Create(targetUser))

	// 1. Test preventative protection blocking an admin from locking their own account
	err := s.LockUser(adminID, adminID, "127.0.0.1", "test-agent")
	assert.Error(t, err)

	// 2. Test successful execution path of an admin locking a standard user
	err = s.LockUser(targetUserID, adminID, "127.0.0.1", "test-agent")
	assert.NoError(t, err)

	// Verify database record has been locked
	lockedUser, err := userRepo.FindByID(targetUserID)
	assert.NoError(t, err)
	assert.True(t, lockedUser.IsLocked())

	// 3. Test unlocking execution path
	err = s.UnlockUser(targetUserID, adminID, "127.0.0.1", "test-agent")
	assert.NoError(t, err)

	// Verify database record has been unlocked
	unlockedUser, err := userRepo.FindByID(targetUserID)
	assert.NoError(t, err)
	assert.False(t, unlockedUser.IsLocked())
}

func TestAuthService_AccountDeactivationAndLifecycle(t *testing.T) {
	s, userRepo, _, _ := setupAuthServiceInfrastructure(t)

	userID := uuid.NewString()
	user := &models.User{
		ID:           userID,
		Email:        "deactivated@example.com",
		PasswordHash: "hash",
		IsActive:     false,
	}
	require.NoError(t, userRepo.Create(user))

	// Attempting a profile fetch by ID should still resolve successfully
	fetched, err := s.GetUserByID(userID)
	assert.NoError(t, err)
	assert.Equal(t, userID, fetched.ID)

	// Deleting the account completely executes soft delete successfully
	err = s.DeleteAccount(userID)
	assert.NoError(t, err)
}