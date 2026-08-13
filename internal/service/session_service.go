package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/metrics"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"golang.org/x/crypto/bcrypt"
)

// Login authenticates a user and returns tokens with device tracking
func (s *AuthService) Login(req *dto.LoginRequest, ipAddress, userAgent string) (*dto.LoginResponse, error) {
	ctx := context.Background()

	// Check login attempts (Redis - brute force mitigation for IP/User combination)
	attempts, err := s.cacheService.GetLoginAttempts(ctx, req.Email)
	if err == nil && attempts >= int64(s.config.Security.RateLimitMax) {
		return nil, errors.New("too many login attempts, please try again later")
	}

	user, err := s.userRepo.FindByEmail(req.Email)
	if err != nil {
		// Increment attempts even for non-existent users (to prevent enumeration)
		s.cacheService.IncrementLoginAttempts(ctx, req.Email)
		metrics.LoginFailureTotal.Inc()
		return nil, errors.New("invalid email or password")
	}

	// Check if account is locked (Database - persistent lock)
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, fmt.Errorf("account is locked until %v", user.LockedUntil)
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		s.handleFailedLogin(user, req.Email, ctx)
		return nil, errors.New("invalid email or password")
	}

	return s.ProcessPostLogin(ctx, user, ipAddress, userAgent, false)
}

func (s *AuthService) ProcessPostLogin(ctx context.Context, user *models.User, ipAddress, userAgent string, skipMFA bool) (*dto.LoginResponse, error) {
	// Check if user is active FIRST
	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	// Reset failed attempts on successful login
	if user.FailedLoginAttempts > 0 || user.LockedUntil != nil {
		if err := s.userRepo.Update(user.ID, map[string]interface{}{
			"failed_login_attempts": 0,
			"locked_until":          nil,
		}); err != nil {
			log.Printf("Warning: failed to reset login attempts for user %s: %v", user.ID, err)
		}
	}

	// Reset Redis attempts too
	if err := s.cacheService.ResetLoginAttempts(ctx, user.Email); err != nil {
		log.Printf("Warning: failed to reset redis login attempts for email %s: %v", user.Email, err)
	}

	// Check MFA
	if user.MFAEnabled && !skipMFA {
		mfaToken, err := s.tokenService.GenerateMFAToken(user.ID)
		if err != nil {
			return nil, err
		}
		return &dto.LoginResponse{MFARequired: true, MFAToken: mfaToken}, nil
	}

	// Update last login
	if err := s.userRepo.Update(user.ID, map[string]interface{}{"last_login_at": time.Now()}); err != nil {
		log.Printf("Failed to update last login for user %s: %v", user.ID, err)
	}

	response, err := s.CreateLoginResponse(user, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	metrics.LoginSuccessTotal.Inc()

	// Audit Log
	s.auditService.LogEvent(&user.ID, "USER_LOGIN_SUCCESS", "USER", user.ID, ipAddress, userAgent, nil)

	return response, nil
}

// LoginWithOAuth handles login or registration via OAuth provider
func (s *AuthService) LoginWithOAuth(email, oauthID, firstName, lastName, provider, ipAddress, userAgent string) (*dto.LoginResponse, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		// User does not exist, create new one
		password, err := s.tokenService.GenerateRandomString(32)
		if err != nil {
			return nil, err
		}

		hashedPassword, err := s.hashPassword(password)
		if err != nil {
			return nil, err
		}
		user = &models.User{
			Email:         email,
			PasswordHash:  hashedPassword,
			FirstName:     firstName,
			LastName:      lastName,
			OAuthProvider: provider,
			OAuthID:       oauthID,
			IsActive:      true,
			EmailVerified: true, // Trusted from OAuth
		}

		if err := s.userRepo.Create(user); err != nil {
			return nil, errors.New("failed to create user")
		}

		s.auditService.LogEvent(&user.ID, "USER_REGISTERED_OAUTH", "USER", user.ID, "", "", map[string]interface{}{"provider": provider})
	} else {
		// Check if user account is active
		if !user.IsActive {
			return nil, errors.New("account is deactivated")
		}

		// User exists, check if linking is needed and safe
		if user.OAuthID == "" {
			if !user.EmailVerified {
				return nil, errors.New("cannot link OAuth to unverified account; please verify your email first")
			}
			updates := map[string]interface{}{
				"oauth_provider": provider,
				"oauth_id":       oauthID,
			}
			if err := s.userRepo.Update(user.ID, updates); err != nil {
				log.Printf("Warning: failed to update OAuth link for user %s: %v", user.ID, err)
			}
			s.auditService.LogEvent(&user.ID, "ACCOUNT_LINKED_OAUTH", "USER", user.ID, "", "", map[string]interface{}{"provider": provider})
		} else if user.OAuthProvider != provider || user.OAuthID != oauthID {
			return nil, errors.New("account is linked to a different OAuth provider/ID")
		}
	}

	response, err := s.CreateLoginResponse(user, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	s.auditService.LogEvent(&user.ID, "USER_LOGIN_SUCCESS_OAUTH", "USER", user.ID, ipAddress, userAgent, nil)

	return response, nil

}

func (s *AuthService) handleFailedLogin(user *models.User, email string, ctx context.Context) {
	// Increment Redis counter (cheap, fast)
	s.cacheService.IncrementLoginAttempts(ctx, email)

	// Increment Database counter (persistent)
	attempts := user.FailedLoginAttempts + 1
	updates := map[string]interface{}{
		"failed_login_attempts": attempts,
	}

	if attempts >= s.config.Security.AccountLockMaxAttempts {
		lockDuration := time.Duration(s.config.Security.AccountLockDuration) * time.Minute
		lockedUntil := time.Now().Add(lockDuration)
		updates["locked_until"] = lockedUntil
		// Audit Log Lock
		s.auditService.LogEvent(&user.ID, "ACCOUNT_LOCKED", "USER", user.ID, "", "", map[string]interface{}{"reason": "too_many_failed_attempts"})
	}

	s.userRepo.Update(user.ID, updates)

	metrics.LoginFailureTotal.Inc()

	// Audit Log Failed Login
	s.auditService.LogEvent(&user.ID, "USER_LOGIN_FAILED", "USER", user.ID, "", "", map[string]interface{}{"email": email})
}

func (s *AuthService) verifyRefreshTokenState(ctx context.Context, refreshTokenString, ipAddress, userAgent string) (*models.RefreshToken, string, bool, error) {
	// Validate refresh token JWT
	claims, err := s.tokenService.ValidateRefreshToken(refreshTokenString)
	if err != nil {
		return nil, "", false, errors.New(errInvalidOrExpiredRefreshToken)
	}

	// Check if token is blacklisted
	blacklisted, err := s.cacheService.IsTokenBlacklisted(ctx, refreshTokenString)
	if err != nil {
		log.Printf("Warning: Failed to check token blacklist: %v", err)
	}
	if blacklisted {
		return nil, "", false, errors.New("refresh token has been revoked")
	}

	// Find refresh token in database
	storedToken, err := s.tokenRepo.FindRefreshToken(refreshTokenString)
	if err != nil {
		return nil, "", false, errors.New("refresh token not found")
	}

	// Verify token is valid (not revoked and not expired)
	if !storedToken.IsValid() {
		if storedToken.IsRevoked {
			allowedToken, isGrace, err := s.handleRevokedRefreshToken(ctx, storedToken, claims.UserID, ipAddress, userAgent)
			if err != nil || allowedToken == nil {
				return nil, "", false, err
			}
			return allowedToken, claims.UserID, isGrace, nil
		}
		return nil, "", false, errors.New(errInvalidOrExpiredRefreshToken)
	}

	return storedToken, claims.UserID, false, nil
}

func (s *AuthService) handleRevokedRefreshToken(ctx context.Context, storedToken *models.RefreshToken, userID, ipAddress, userAgent string) (*models.RefreshToken, bool, error) {
	gracePeriod := s.getRefreshTokenGracePeriod()
	if gracePeriod > 0 && time.Since(storedToken.UpdatedAt) <= gracePeriod {
		activeToken, err := s.tokenRepo.FindActiveTokenInFamily(storedToken.FamilyID)
		if err != nil {
			return nil, false, errors.New("failed to verify refresh token state")
		}
		if activeToken != nil {
			log.Printf("Grace period: allowing concurrent refresh token reuse for user %s family %s", storedToken.UserID, storedToken.FamilyID)
			return activeToken, true, nil
		}
	}

	s.revokeRefreshTokenFamily(storedToken, ipAddress, userAgent)
	return nil, false, errors.New(errInvalidOrExpiredRefreshToken)
}

func (s *AuthService) revokeRefreshTokenFamily(storedToken *models.RefreshToken, ipAddress, userAgent string) {
	log.Printf("Security Alert: Refresh token reuse detected for user %s, family %s. Revoking family sessions.", storedToken.UserID, storedToken.FamilyID)
	if err := s.tokenRepo.RevokeTokenFamily(storedToken.FamilyID); err != nil {
		log.Printf("Error revoking tokens for family %s: %v", storedToken.FamilyID, err)
	}
	if err := s.auditService.LogEvent(&storedToken.UserID, "REFRESH_TOKEN_REUSE_DETECTED", "USER", storedToken.UserID, ipAddress, userAgent, map[string]interface{}{
		"token_id": storedToken.ID,
	}); err != nil {
		log.Printf("Error logging REFRESH_TOKEN_REUSE_DETECTED audit event: %v", err)
	}
}

// RefreshAccessToken generates a new access token using refresh token with rotation
func (s *AuthService) RefreshAccessToken(refreshTokenString string, ipAddress, userAgent string) (*dto.TokenRefreshResponse, error) {
	ctx := context.Background()

	storedToken, userID, isGrace, err := s.verifyRefreshTokenState(ctx, refreshTokenString, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	// Get user
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Token rotation: Generate new refresh token
	newRefreshTokenString, err := s.tokenService.GenerateRefreshToken(user)
	if err != nil {
		return nil, errors.New(errGenRefreshToken)
	}

	// Store new refresh token
	newRefreshToken := &models.RefreshToken{
		UserID:    user.ID,
		FamilyID:  storedToken.FamilyID,
		Token:     newRefreshTokenString,
		ExpiresAt: time.Now().Add(s.getRefreshTokenExpiry()),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if isGrace {
		newAccessToken, err := s.tokenService.GenerateAccessToken(user, storedToken.ID)
		if err != nil {
			return nil, errors.New(errGenAccessToken)
		}

		return &dto.TokenRefreshResponse{
			AccessToken:  newAccessToken,
			RefreshToken: storedToken.Token,
		}, nil
	}

	// Generate new access token
	newAccessToken, err := s.tokenService.GenerateAccessToken(user, newRefreshToken.ID)
	if err != nil {
		return nil, errors.New(errGenAccessToken)
	}

	// transaction handling creation and rotation of refresh tokens
	if err := s.tokenRepo.RotateRefreshToken(
		refreshTokenString,
		newRefreshToken,
	); err != nil {
		return nil, errors.New("failed to rotate refresh token")
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
		claims, err := s.tokenService.ValidateAccessToken(accessToken)
		if err == nil {
			ttl := time.Until(claims.ExpiresAt.Time)
			if ttl > 0 {
				if err := s.cacheService.BlacklistToken(ctx, claims.ID, ttl); err != nil {
					log.Printf("Warning: Failed to blacklist access token: %v", err)
				}
			}
		} else {
			log.Printf("Warning: Failed to validate access token during logout: %v", err)
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
		claims, err := s.tokenService.ValidateAccessToken(currentAccessToken)
		if err == nil {
			ttl := time.Until(claims.ExpiresAt.Time)
			if ttl > 0 {
				if err := s.cacheService.BlacklistToken(ctx, claims.ID, ttl); err != nil {
					log.Printf("Warning: Failed to blacklist access token: %v", err)
				}
			}
		} else {
			log.Printf("Warning: Failed to validate access token during logout all: %v", err)
		}
	}

	// Revoke all user refresh tokens
	if err := s.tokenRepo.RevokeAllUserTokens(userID); err != nil {
		return errors.New("failed to revoke all sessions")
	}

	return nil
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

func (s *AuthService) CreateLoginResponse(
	user *models.User,
	ipAddress string,
	userAgent string,
) (*dto.LoginResponse, error) {

	refreshTokenString, err := s.tokenService.GenerateRefreshToken(user)
	if err != nil {
		return nil, errors.New("failed to generate refresh token")
	}

	refreshToken := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshTokenString,
		ExpiresAt: time.Now().Add(s.getRefreshTokenExpiry()),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := s.tokenRepo.CreateRefreshToken(refreshToken); err != nil {
		return nil, errors.New(errStoreRefreshToken)
	}

	accessToken, err := s.tokenService.GenerateAccessToken(user, refreshToken.ID)
	if err != nil {
		return nil, errors.New(errGenAccessToken)
	}

	return &dto.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenString,
		User:         user.ToPublic(),
	}, nil
}
