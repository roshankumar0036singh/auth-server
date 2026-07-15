package service

import (
	"errors"
	"log"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

func (s *AuthService) hashPassword(password string) (string, error) {
	rounds := s.config.Security.BcryptRounds
	if rounds < bcrypt.MinCost || rounds > bcrypt.MaxCost {
		rounds = bcrypt.DefaultCost
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		rounds,
	)

	if err != nil {
		return "", errors.New("failed to hash password")
	}

	return string(hashedPassword), nil
}

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
	err = s.emailService.SendPasswordResetEmail(user.Email, token.Token, s.config.App.URL)
	if err == nil {
		s.auditService.LogEvent(&user.ID, "PASSWORD_RESET_REQUESTED", "USER", user.ID, "", "", nil)
	}
	return err
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

	// Validate password strength
	if err := utils.ValidatePassword(newPassword); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := s.hashPassword(newPassword)
	if err != nil {
		return errors.New(errHashPassword)
	}

	// Update user password
	if err := s.userRepo.Update(token.UserID, map[string]interface{}{
		"password_hash": string(hashedPassword),
	}); err != nil {
		return errors.New("failed to update password")
	}

	// Mark token as used
	if err := s.passwordResetRepo.MarkAsUsed(token.ID); err != nil {
		log.Printf("Warning: failed to mark password reset token %s as used: %v", token.ID, err)
	}

	// Revoke all existing sessions for security
	if err := s.tokenRepo.RevokeAllUserTokens(token.UserID); err != nil {
		log.Printf("Warning: failed to revoke tokens after password reset for user %s: %v", token.UserID, err)
	}

	// Audit Log
	s.auditService.LogEvent(&token.UserID, "PASSWORD_RESET_SUCCESS", "USER", token.UserID, "", "", nil)

	return nil
}

// ChangePassword changes the user's password
func (s *AuthService) ChangePassword(userID string, req *dto.ChangePasswordRequest) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		return errors.New("incorrect current password")
	}

	// Validate password strength
	if err := utils.ValidatePassword(req.NewPassword); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := s.hashPassword(req.NewPassword)
	if err != nil {
		return errors.New(errHashPassword)
	}

	// Update password
	if err := s.userRepo.Update(userID, map[string]interface{}{
		"password_hash": string(hashedPassword),
	}); err != nil {
		return errors.New("failed to update password")
	}

	// Revoke all sessions on password change for security
	if err := s.tokenRepo.RevokeAllUserTokens(userID); err != nil {
		log.Printf("Warning: failed to revoke tokens after ChangePassword for user %s: %v", userID, err)
	}

	// Audit Log
	s.auditService.LogEvent(&userID, "PASSWORD_CHANGED", "USER", userID, "", "", nil)

	return nil
}
