package service

import (
	"errors"
	"log"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

var (
	ErrSelfLock           = errors.New("admin cannot lock their own account")
	ErrAdminLock          = errors.New("admin accounts cannot be locked")
	ErrAlreadyLocked      = errors.New("account is already locked")
	ErrNotLocked          = errors.New("account is not locked")
	ErrTooManyAttempts    = errors.New("too many failed attempts, please try again later")
	ErrInvalidMFACode     = errors.New("invalid MFA code")
	ErrMFANotEnabled      = errors.New("MFA not enabled")
	ErrIncorrectPassword  = errors.New("incorrect current password")
	ErrServiceUnavailable = errors.New("authentication service temporarily unavailable")
)

const (
	errGenAccessToken               = "failed to generate access token"
	errGenRefreshToken              = "failed to generate refresh token"
	errStoreRefreshToken            = "failed to store refresh token"
	errHashPassword                 = "failed to hash password"
	errInvalidOrExpiredRefreshToken = "invalid or expired refresh token"
)

type AuthService struct {
	userRepo          *repository.UserRepository
	tokenRepo         *repository.TokenRepository
	verificationRepo  *repository.VerificationRepository
	passwordResetRepo *repository.PasswordResetRepository
	tokenService      *TokenService
	cacheService      *CacheService
	emailService      EmailSender
	auditService      *AuditService
	mfaService        *MFAService
	config            *config.Config
}

func NewAuthService(
	userRepo *repository.UserRepository,
	tokenRepo *repository.TokenRepository,
	verificationRepo *repository.VerificationRepository,
	passwordResetRepo *repository.PasswordResetRepository,
	tokenService *TokenService,
	cacheService *CacheService,
	emailService EmailSender,
	auditService *AuditService,
	mfaService *MFAService,
	cfg *config.Config,
) *AuthService {
	return &AuthService{
		userRepo:          userRepo,
		tokenRepo:         tokenRepo,
		verificationRepo:  verificationRepo,
		passwordResetRepo: passwordResetRepo,
		tokenService:      tokenService,
		cacheService:      cacheService,
		emailService:      emailService,
		auditService:      auditService,
		mfaService:        mfaService,
		config:            cfg,
	}
}

// Register creates a new user account and sends verification email
func (s *AuthService) Register(req *dto.RegisterRequest) (*models.User, error) {
	// Check if email already exists
	exists, err := s.userRepo.EmailExists(req.Email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New("email already registered")
	}

	// Validate password strength
	if err := utils.ValidatePassword(req.Password); err != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := s.hashPassword(req.Password)
	if err != nil {
		return nil, errors.New(errHashPassword)
	}

	// Create user
	user := &models.User{
		Email:         req.Email,
		PasswordHash:  string(hashedPassword),
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		OAuthProvider: "local",
		IsActive:      true, // Can allow login but restrict features, or set false
		EmailVerified: false,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, errors.New("failed to create user")
	}

	// Generate and send verification email
	if err := s.sendVerificationEmail(user); err != nil {
		// Log error but don't fail registration
		log.Printf("Failed to send verification email to %s: %v", user.Email, err)
	}

	// Audit Log
	s.auditService.LogEvent(&user.ID, "USER_REGISTERED", "USER", user.ID, "", "", nil)

	return user, nil
}

func (s *AuthService) sendVerificationEmail(user *models.User) error {
	// Generate verification token
	token := &models.VerificationToken{
		UserID:    user.ID,
		Token:     s.tokenService.GenerateRandomString(32),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := s.verificationRepo.Create(token); err != nil {
		return err
	}

	// Send email
	return s.emailService.SendVerificationEmail(user.Email, token.Token, s.config.App.URL)
}

// VerifyEmail verifies a user's email address
func (s *AuthService) VerifyEmail(tokenString string) error {
	// Find token
	token, err := s.verificationRepo.FindByToken(tokenString)
	if err != nil {
		return errors.New("invalid or expired verification token")
	}

	// Check expiry
	if token.IsExpired() {
		return errors.New("verification token has expired")
	}

	// Update user
	if err := s.userRepo.Update(token.UserID, map[string]interface{}{
		"email_verified": true,
	}); err != nil {
		return errors.New("failed to verify email")
	}

	// Delete used token (and potentially all tokens for this user)
	s.verificationRepo.DeleteByUserID(token.UserID)

	return nil
}

// ResendVerification sends a new verification email
func (s *AuthService) ResendVerification(email string) error {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return ErrUserNotFound
	}

	if user.EmailVerified {
		return errors.New("email already verified")
	}

	// Delete existing tokens
	s.verificationRepo.DeleteByUserID(user.ID)

	// Send new email
	return s.sendVerificationEmail(user)
}
