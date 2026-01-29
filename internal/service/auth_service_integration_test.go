package service

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/stretchr/testify/assert"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// MockEmailSender
type MockEmailSender struct {
	LastEmail map[string]string
}

func (m *MockEmailSender) SendVerificationEmail(email, token, appURL string) error {
	if m.LastEmail == nil {
		m.LastEmail = make(map[string]string)
	}
	m.LastEmail["verification"] = email
	return nil
}

func (m *MockEmailSender) SendPasswordResetEmail(email, token, appURL string) error {
	m.LastEmail["reset"] = email
	return nil
}

func SetupIntegrationTest(t *testing.T) (*AuthService, *gorm.DB, *miniredis.Miniredis) {
	// 1. In-memory SQLite
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	assert.NoError(t, err)

	// Migrate
	err = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.VerificationToken{},
		&models.PasswordResetToken{},
		&models.AuditLog{},
	)
	assert.NoError(t, err)

	// 2. Miniredis
	mr, err := miniredis.Run()
	assert.NoError(t, err)

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	// 3. Repositories
	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(db)
	verificationRepo := repository.NewVerificationRepository(db)
	passwordResetRepo := repository.NewPasswordResetRepository(db)
	auditRepo := repository.NewAuditRepository(db)

	// 4. Services
	cfg := &config.Config{
		JWT: config.JWTConfig{AccessSecret: "secret", RefreshSecret: "refresh"},
		Security: config.SecurityConfig{RateLimitMax: 10, RateLimitWindow: 60}, 
		App: config.AppConfig{URL: "http://localhost"},
	}
	tokenService := NewTokenService(cfg)
	cacheService := NewCacheService(rdb)
	emailService := &MockEmailSender{}
	auditService := NewAuditService(auditRepo)
	mfaService := NewMFAService(cfg)

	authService := NewAuthService(
		userRepo,
		tokenRepo,
		verificationRepo,
		passwordResetRepo,
		tokenService,
		cacheService,
		emailService,
		auditService,
		mfaService,
		cfg,
	)

	return authService, db, mr
}

func TestAuthService_Register_Integration(t *testing.T) {
	service, _, mr := SetupIntegrationTest(t)
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
	assert.False(t, user.EmailVerified) // Should send email, not verify immediately
}

func TestAuthService_Login_Integration(t *testing.T) {
	service, _, mr := SetupIntegrationTest(t)
	defer mr.Close()

	// Setup: Create user
	// Or just use Register to create the user properly with hashing!
	
	req := &dto.RegisterRequest{
		Email:     "login@example.com",
		Password:  "Password123!",
		FirstName: "Login",
		LastName:  "User",
	}
	_, err := service.Register(req)
	assert.NoError(t, err)

	// Verify the user email manually to allow login if we enforced it? 
	// Logic says: if !user.IsActive return error. Register sets IsActive=true.
	// Logic doesn't check EmailVerified yet for Login except maybe? Checked Login code: no.

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
	loginReqInfo := &dto.LoginRequest{
		Email:    "login@example.com",
		Password: "WrongPassword!",
	}
	_, err = service.Login(loginReqInfo, "127.0.0.1", "UserAgent")
	assert.Error(t, err)
}
