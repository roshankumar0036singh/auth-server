package service

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

// mfaSecretPrefix marks encrypted-at-rest TOTP seeds (#149). Existing
// plaintext values (from before this feature) remain readable via fallback.
const mfaSecretPrefix = "enc:"

// encryptMFASecret seals a TOTP seed with AES-GCM using ENCRYPTION_KEY.
func (s *AuthService) encryptMFASecret(plaintext string) (string, error) {
	if s.config.Security.EncryptionKey == "" {
		return plaintext, nil
	}
	sealed, err := utils.Encrypt(plaintext, s.config.Security.EncryptionKey)
	if err != nil {
		return "", err
	}
	return mfaSecretPrefix + sealed, nil
}

// decryptMFASecret opens an encrypted seed, falling back to legacy plaintext
// so pre-existing accounts keep working.
func (s *AuthService) decryptMFASecret(stored string) (string, error) {
	if !strings.HasPrefix(stored, mfaSecretPrefix) {
		return stored, nil
	}
	plain, err := utils.Decrypt(strings.TrimPrefix(stored, mfaSecretPrefix), s.config.Security.EncryptionKey)
	if err != nil {
		return "", err
	}
	return plain, nil
}

// EnableMFA generates a secret and returns it with QR code URL
func (s *AuthService) EnableMFA(userID string) (*dto.MFAEnableResponse, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if user.MFAEnabled {
		return nil, errors.New("MFA is already enabled")
	}

	secret, qrCodeURL, err := s.mfaService.GenerateMFA(user.Email)
	if err != nil {
		return nil, err
	}

	// Save temp secret, encrypted at rest (#149)
	sealed, err := s.encryptMFASecret(secret)
	if err != nil {
		return nil, errors.New("failed to seal MFA secret")
	}
	if err := s.userRepo.Update(userID, map[string]interface{}{
		"mfa_secret": sealed,
	}); err != nil {
		return nil, errors.New("failed to save temp MFA secret")
	}

	return &dto.MFAEnableResponse{
		Secret:    secret,
		QRCodeURL: qrCodeURL,
	}, nil
}

// VerifyEnableMFA verifies the code and enables MFA
func (s *AuthService) VerifyEnableMFA(userID, code string) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return ErrUserNotFound
	}

	if user.MFAEnabled {
		return errors.New("MFA is already enabled")
	}

	if user.MFASecret == "" {
		return errors.New("MFA setup not initiated")
	}

	seed, err := s.decryptMFASecret(user.MFASecret)
	if err != nil {
		return errors.New("failed to open MFA secret")
	}
	if !s.mfaService.ValidateMFA(seed, code) {
		return ErrInvalidMFACode
	}

	// Enable MFA
	if err := s.userRepo.Update(userID, map[string]interface{}{
		"mfa_enabled": true,
	}); err != nil {
		return errors.New("failed to enable MFA")
	}

	s.auditService.LogEvent(&userID, "MFA_ENABLED", "USER", userID, "", "", nil)
	return nil
}

// DisableMFA re-authenticates the user via password and TOTP code, then disables MFA on their account
func (s *AuthService) DisableMFA(userID, password, code string) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	if !user.MFAEnabled {
		return ErrMFANotEnabled
	}

	// Disabling MFA is security-sensitive: require a fresh password check
	// in addition to the TOTP code.
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return ErrIncorrectPassword
	}

	seed, err := s.decryptMFASecret(user.MFASecret)
	if err != nil {
		return errors.New("failed to open MFA secret")
	}
	if !s.mfaService.ValidateMFA(seed, code) {
		return ErrInvalidMFACode
	}

	if err := s.userRepo.Update(userID, map[string]interface{}{
		"mfa_enabled": false,
		"mfa_secret":  "",
	}); err != nil {
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	if err := s.auditService.LogEvent(&userID, "MFA_DISABLED", "USER", userID, "", "", nil); err != nil {
		return fmt.Errorf("failed to write MFA_DISABLED audit log for user %s: %w", userID, err)
	}
	return nil
}

// VerifyLoginMFA completes the login process with an MFA code. It requires the
// short-lived MFA-pending token issued by the password step (Login), so the
// password cannot be bypassed, and rate-limits code attempts to prevent
// brute-forcing the 6-digit TOTP.
func (s *AuthService) VerifyLoginMFA(mfaToken, code, ipAddress, userAgent string) (*dto.LoginResponse, error) {
	ctx := context.Background()

	userID, err := s.tokenService.ValidateMFAToken(mfaToken)
	if err != nil {
		return nil, errors.New("invalid or expired MFA session")
	}

	// Rate-limit MFA code attempts per user.
	attempts, err := s.cacheService.GetMFAAttempts(ctx, userID)
	if err == nil && attempts >= int64(s.config.Security.RateLimitMax) {
		return nil, errors.New("too many MFA attempts, please try again later")
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		s.cacheService.IncrementMFAAttempts(ctx, userID)
		s.auditService.LogEvent(nil, "MFA_LOGIN_UNKNOWN_USER", "SYSTEM", "", ipAddress, userAgent,
			map[string]interface{}{"user_id": userID})
		return nil, ErrInvalidMFACode
	}

	if !user.MFAEnabled {
		return nil, errors.New("MFA not enabled for this user")
	}

	seed, err := s.decryptMFASecret(user.MFASecret)
	if err != nil {
		s.cacheService.IncrementMFAAttempts(ctx, userID)
		return nil, ErrInvalidMFACode
	}
	if !s.mfaService.ValidateMFA(seed, code) {
		s.cacheService.IncrementMFAAttempts(ctx, userID)
		if err := s.auditService.LogEvent(&user.ID, "MFA_LOGIN_FAILED", "USER", user.ID, ipAddress, userAgent, nil); err != nil {
			log.Printf("failed to write MFA_LOGIN_FAILED audit log for user %s: %v", user.ID, err)
		}
		return nil, ErrInvalidMFACode
	}

	s.cacheService.ResetMFAAttempts(ctx, userID)

	response, err := s.CreateLoginResponse(user, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	s.auditService.LogEvent(&user.ID, "USER_LOGIN_SUCCESS_MFA", "USER", user.ID, ipAddress, userAgent, nil)
	return response, nil
}

// SetEncryptionKeyForTest injects an encryption key for at-rest tests.
func (s *AuthService) SetEncryptionKeyForTest(key string) {
	s.config.Security.EncryptionKey = key
}

// DecryptMFASecretForTest exposes the decrypt path for tests.
func (s *AuthService) DecryptMFASecretForTest(stored string) (string, error) {
	return s.decryptMFASecret(stored)
}
