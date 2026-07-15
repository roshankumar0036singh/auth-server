package service

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
)

func (s *AuthService) getRefreshTokenExpiry() time.Duration {
	expiry, err := time.ParseDuration(s.config.JWT.RefreshExpiry)

	if err != nil {
		log.Printf("Warning: invalid RefreshExpiry value %q, using default 7 days", s.config.JWT.RefreshExpiry)
		return 7 * 24 * time.Hour
	}

	return expiry
}

func (s *AuthService) getRefreshTokenGracePeriod() time.Duration {
	grace, err := time.ParseDuration(s.config.JWT.RefreshGracePeriod)
	if err != nil {
		log.Printf("Warning: invalid RefreshGracePeriod value %q, using default 10 seconds", s.config.JWT.RefreshGracePeriod)
		return 10 * time.Second
	}
	return grace
}

func (s *AuthService) SetRefreshTokenGracePeriod(value string) {
	s.config.JWT.RefreshGracePeriod = value
}

// UpdateProfile updates user profile information
func (s *AuthService) UpdateProfile(userID string, req *dto.UpdateProfileRequest) (*models.User, error) {
	updates := make(map[string]interface{})

	if req.FirstName != "" {
		updates["first_name"] = req.FirstName
	}
	if req.LastName != "" {
		updates["last_name"] = req.LastName
	}
	if req.Phone != "" {
		updates["phone"] = req.Phone
	}

	if len(updates) == 0 {
		return s.userRepo.FindByID(userID)
	}

	if err := s.userRepo.Update(userID, updates); err != nil {
		return nil, errors.New("failed to update profile")
	}

	// Audit Log
	s.auditService.LogEvent(&userID, "PROFILE_UPDATED", "USER", userID, "", "", nil)

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// GetUserAuditLogs proxies the call to audit service
func (s *AuthService) GetUserAuditLogs(userID string, page, limit int) (*dto.AuditLogsResponse, error) {
	return s.auditService.GetUserAuditLogs(userID, page, limit)
}

// DeleteAccount soft deletes the user account
func (s *AuthService) DeleteAccount(userID string) error {
	// Revoke all tokens first
	if err := s.tokenRepo.RevokeAllUserTokens(userID); err != nil {
		log.Printf("Warning: failed to revoke tokens during account deletion for user %s: %v", userID, err)
	}

	// Delete user (Soft delete via GORM)
	err := s.userRepo.Delete(userID)
	if err != nil {
		return err
	}
	// Audit Log
	s.auditService.LogEvent(&userID, "ACCOUNT_DELETED", "USER", userID, "", "", nil)
	return nil
}

// GetUserByID retrieves a user by ID
func (s *AuthService) GetUserByID(userID string) (*models.User, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// GetUsers get all users by limit and offset [Pagination]
func (s *AuthService) GetUsers(limit, offset int) (models.PaginatedUsers, error) {
	users, err := s.userRepo.GetUsers(limit, offset)
	if err != nil {
		return models.PaginatedUsers{}, err
	}
	return users, nil
}

type userLocker interface {
	FindByID(id string) (*models.User, error)
}

func validateLockUser(repo userLocker, userID string) error {
	user, err := repo.FindByID(userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return ErrUserNotFound
		}
		return err
	}
	if user.Role == "admin" {
		return ErrAdminLock
	}
	if user.IsLocked() {
		return ErrAlreadyLocked
	}
	return nil
}

func (s *AuthService) LockUser(userID, adminID, ipAddress, userAgent string) error {
	if userID == adminID {
		return ErrSelfLock
	}

	var lockedUntil time.Time

	err := s.userRepo.RunInTx(func(userRepo *repository.UserRepository, tokenRepo *repository.TokenRepository) error {
		if err := validateLockUser(userRepo, userID); err != nil {
			return err
		}

		lockedUntil = time.Now().AddDate(100, 0, 0)

		if err := userRepo.LockUser(userID, lockedUntil); err != nil {
			return fmt.Errorf("lock user: %w", err)
		}

		if err := userRepo.Update(userID, map[string]interface{}{
			"failed_login_attempts": 0,
		}); err != nil {
			return fmt.Errorf("reset failed login attempts: %w", err)
		}

		if err := tokenRepo.RevokeAllUserTokens(userID); err != nil {
			return fmt.Errorf("revoke user tokens: %w", err)
		}

		return nil
	})

	if err != nil {
		return err
	}

	if err := s.auditService.LogEvent(
		&adminID,
		"USER_LOCKED",
		"USER",
		userID,
		ipAddress,
		userAgent,
		map[string]interface{}{"locked_until": lockedUntil},
	); err != nil {
		log.Printf("failed to write USER_LOCKED audit log: %v", err)
	}

	return nil
}

// UnlockUser removes the account lock state.
// Previously revoked refresh tokens remain revoked and are not restored.
// Users must log in again after the account is unlocked.
func (s *AuthService) UnlockUser(userID, adminID, ipAddress, userAgent string) error {
	err := s.userRepo.RunInTx(func(userRepo *repository.UserRepository, tokenRepo *repository.TokenRepository) error {
		user, err := userRepo.FindByID(userID)
		if err != nil {
			return err
		}

		if !user.IsLocked() {
			return ErrNotLocked
		}

		if err := userRepo.UnlockUser(userID); err != nil {
			return fmt.Errorf("unlock user: %w", err)
		}

		return nil
	})

	if err != nil {
		return err
	}

	if err := s.auditService.LogEvent(
		&adminID,
		"USER_UNLOCKED",
		"USER",
		userID,
		ipAddress,
		userAgent,
		map[string]interface{}{"locked_until": nil},
	); err != nil {
		log.Printf("failed to write USER_UNLOCKED audit log: %v", err)
	}

	return nil
}
