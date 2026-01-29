package testutils

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/glebarez/sqlite"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/stretchr/testify/assert"
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
	if m.LastEmail == nil {
		m.LastEmail = make(map[string]string)
	}
	m.LastEmail["reset"] = email
	return nil
}

func SetupIntegrationTest(t *testing.T) (*service.AuthService, *gorm.DB, *miniredis.Miniredis) {
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
	tokenService := service.NewTokenService(cfg)
	cacheService := service.NewCacheService(rdb)
	emailService := &MockEmailSender{}
	auditService := service.NewAuditService(auditRepo)
	mfaService := service.NewMFAService(cfg)

	authService := service.NewAuthService(
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
