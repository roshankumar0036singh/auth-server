package service

import (
	"context"
	"errors"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
)

type AuthService struct {
	userRepo          *repository.UserRepository
	tokenRepo         *repository.TokenRepository
	verificationRepo  *repository.VerificationRepository
	passwordResetRepo *repository.PasswordResetRepository
	tokenService      *TokenService
	cacheService      *CacheService
	emailService      *EmailService
	config            *config.Config
}

func NewAuthService(
	userRepo *repository.UserRepository,
	tokenRepo *repository.TokenRepository,
	verificationRepo *repository.VerificationRepository,
	passwordResetRepo *repository.PasswordResetRepository,
	tokenService *TokenService,
	cacheService *CacheService,
	emailService *EmailService,
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
		config:            cfg,
	}
}

// ... Register and other methods remain same ...

// ForgotPassword initiates the password reset flow
func (s *AuthService) ForgotPassword(email string) error {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		// Return nil to prevent email enumeration
		return nil
	}

	// Delete existing reset tokens
	s.passwordResetRepo.DeleteByUserID(user.ID)

	// Create new reset token
	token := &models.PasswordResetToken{
		UserID:    user.ID,
		Token:     s.tokenService.GenerateRandomString(32),
		ExpiresAt: time.Now().Add(1 * time.Hour), 
	}

	if err := s.passwordResetRepo.Create(token); err != nil {
		return err
	}

	// Send email
	return s.emailService.SendPasswordResetEmail(user.Email, token.Token, s.config.App.URL)
}

// ResetPassword resets the user's password using a valid token
func (s *AuthService) ResetPassword(tokenString, newPassword string) error {
	// Find token
	token, err := s.passwordResetRepo.FindByToken(tokenString)
	if err != nil {
		return errors.New("invalid or expired reset token")
	}

	if token.IsExpired() {
		return errors.New("reset token has expired")
	}

	if token.Used {
		return errors.New("reset token has already been used")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("failed to hash password")
	}

	// Update user password
	if err := s.userRepo.Update(token.UserID, map[string]interface{}{
		"password_hash": string(hashedPassword),
	}); err != nil {
		return errors.New("failed to update password")
	}

	// Mark token as used
	s.passwordResetRepo.MarkAsUsed(token.ID)

	// Revoke all existing sessions for security
	s.tokenRepo.RevokeAllUserTokens(token.UserID)

	return nil
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

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.New("failed to hash password")
	}

	// Create user
	user := &models.User{
		Email:         req.Email,
		PasswordHash:  string(hashedPassword),
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		OAuthProvider: "local",
		IsActive:      true,  // Can allow login but restrict features, or set false
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
		return errors.New("user not found")
	}

	if user.EmailVerified {
		return errors.New("email already verified")
	}

	// Delete existing tokens
	s.verificationRepo.DeleteByUserID(user.ID)

	// Send new email
	return s.sendVerificationEmail(user)
}


// Login authenticates a user and returns tokens with device tracking
func (s *AuthService) Login(req *dto.LoginRequest, ipAddress, userAgent string) (*dto.LoginResponse, error) {
	ctx := context.Background()

	// Check login attempts (rate limiting)
	attempts, err := s.cacheService.GetLoginAttempts(ctx, req.Email)
	if err == nil && attempts >= 5 {
		return nil, errors.New("too many login attempts, please try again later")
	}

	// Find user by email
	user, err := s.userRepo.FindByEmail(req.Email)
	if err != nil {
		// Increment failed attempts
		s.cacheService.IncrementLoginAttempts(ctx, req.Email)
		return nil, errors.New("invalid credentials")
	}

	// Check if account is active
	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		// Increment failed attempts
		s.cacheService.IncrementLoginAttempts(ctx, req.Email)
		return nil, errors.New("invalid credentials")
	}

	// Reset login attempts on successful login
	s.cacheService.ResetLoginAttempts(ctx, req.Email)

	// Update last login time (non-critical operation)
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.userRepo.Update(user.ID, map[string]interface{}{
		"last_login_at": now,
	}); err != nil {
		// Log warning but don't fail login for non-critical operation
		log.Printf("Warning: Failed to update last_login_at for user %s: %v", user.ID, err)
	}

	// Generate tokens
	accessToken, err := s.tokenService.GenerateAccessToken(user)
	if err != nil {
		return nil, errors.New("failed to generate access token")
	}

	refreshTokenString, err := s.tokenService.GenerateRefreshToken(user)
	if err != nil {
		return nil, errors.New("failed to generate refresh token")
	}

	// Store refresh token in database with device info
	refreshToken := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshTokenString,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := s.tokenRepo.CreateRefreshToken(refreshToken); err != nil {
		log.Printf("Warning: Failed to store refresh token: %v", err)
		// Continue anyway - token is still valid
	}

	return &dto.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenString,
		User:         user.ToPublic(),
	}, nil
}

// RefreshAccessToken generates a new access token using refresh token with rotation
func (s *AuthService) RefreshAccessToken(refreshTokenString string, ipAddress, userAgent string) (*dto.TokenRefreshResponse, error) {
	ctx := context.Background()

	// Validate refresh token JWT
	claims, err := s.tokenService.ValidateRefreshToken(refreshTokenString)
	if err != nil {
		return nil, errors.New("invalid or expired refresh token")
	}

	// Check if token is blacklisted
	blacklisted, err := s.cacheService.IsTokenBlacklisted(ctx, refreshTokenString)
	if err != nil {
		log.Printf("Warning: Failed to check token blacklist: %v", err)
	}
	if blacklisted {
		return nil, errors.New("refresh token has been revoked")
	}

	// Find refresh token in database
	storedToken, err := s.tokenRepo.FindRefreshToken(refreshTokenString)
	if err != nil {
		return nil, errors.New("refresh token not found")
	}

	// Verify token is valid (not revoked and not expired)
	if !storedToken.IsValid() {
		return nil, errors.New("refresh token is invalid or expired")
	}

	// Get user
	user, err := s.userRepo.FindByID(claims.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Generate new access token
	newAccessToken, err := s.tokenService.GenerateAccessToken(user)
	if err != nil {
		return nil, errors.New("failed to generate access token")
	}

	// Token rotation: Generate new refresh token
	newRefreshTokenString, err := s.tokenService.GenerateRefreshToken(user)
	if err != nil {
		return nil, errors.New("failed to generate refresh token")
	}

	// Revoke old refresh token
	if err := s.tokenRepo.RevokeRefreshToken(refreshTokenString); err != nil {
		log.Printf("Warning: Failed to revoke old refresh token: %v", err)
	}

	// Store new refresh token
	newRefreshToken := &models.RefreshToken{
		UserID:    user.ID,
		Token:     newRefreshTokenString,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := s.tokenRepo.CreateRefreshToken(newRefreshToken); err != nil {
		log.Printf("Warning: Failed to store new refresh token: %v", err)
	}

	return &dto.TokenRefreshResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshTokenString,
	}, nil
}

// Logout revokes the refresh token and blacklists the access token
func (s *AuthService) Logout(accessToken, refreshToken string) error {
	ctx := context.Background()

	// Blacklist access token (expires in 15 minutes)
	if accessToken != "" {
		if err := s.cacheService.BlacklistToken(ctx, accessToken, 15*time.Minute); err != nil {
			log.Printf("Warning: Failed to blacklist access token: %v", err)
		}
	}

	// Revoke refresh token in database
	if refreshToken != "" {
		if err := s.tokenRepo.RevokeRefreshToken(refreshToken); err != nil {
			log.Printf("Warning: Failed to revoke refresh token: %v", err)
		}
	}

	return nil
}

// LogoutAll revokes all refresh tokens for a user
func (s *AuthService) LogoutAll(userID string, currentAccessToken string) error {
	ctx := context.Background()

	// Blacklist current access token
	if currentAccessToken != "" {
		if err := s.cacheService.BlacklistToken(ctx, currentAccessToken, 15*time.Minute); err != nil {
			log.Printf("Warning: Failed to blacklist access token: %v", err)
		}
	}

	// Revoke all user refresh tokens
	if err := s.tokenRepo.RevokeAllUserTokens(userID); err != nil {
		return errors.New("failed to revoke all sessions")
	}

	return nil
}

// GetUserByID retrieves a user by ID
func (s *AuthService) GetUserByID(userID string) (*models.User, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, errors.New("user not found")
	}
	return user, nil
}

// GetUserSessions retrieves all active sessions for a user
func (s *AuthService) GetUserSessions(userID string) ([]models.RefreshToken, error) {
	tokens, err := s.tokenRepo.FindUserRefreshTokens(userID)
	if err != nil {
		return nil, errors.New("failed to retrieve sessions")
	}
	return tokens, nil
}

// RevokeSession revokes a specific session by token ID
func (s *AuthService) RevokeSession(userID, tokenID string) error {
	// Verify the token belongs to the user
	token, err := s.tokenRepo.FindRefreshTokenByID(tokenID)
	if err != nil {
		return errors.New("session not found")
	}

	if token.UserID != userID {
		return errors.New("unauthorized to revoke this session")
	}

	if err := s.tokenRepo.RevokeRefreshTokenByID(tokenID); err != nil {
		return errors.New("failed to revoke session")
	}

	return nil
}
