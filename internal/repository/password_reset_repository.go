package repository

import (
	"errors"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

type PasswordResetRepository struct {
	db *gorm.DB
}

func NewPasswordResetRepository(db *gorm.DB) *PasswordResetRepository {
	return &PasswordResetRepository{db: db}
}

// Create stores a new password reset token
func (r *PasswordResetRepository) Create(token *models.PasswordResetToken) error {
	return r.db.Create(token).Error
}

// FindByToken retrieves a token by its string value
func (r *PasswordResetRepository) FindByToken(tokenString string) (*models.PasswordResetToken, error) {
	var token models.PasswordResetToken
	if err := r.db.Where("token = ?", tokenString).First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid token")
		}
		return nil, err
	}
	return &token, nil
}

// MarkAsUsed marks a token as used
func (r *PasswordResetRepository) MarkAsUsed(id string) error {
	return r.db.Model(&models.PasswordResetToken{}).Where("id = ?", id).Update("used", true).Error
}

// DeleteByUserID removes all reset tokens for a user
func (r *PasswordResetRepository) DeleteByUserID(userID string) error {
	return r.db.Where("user_id = ?", userID).Delete(&models.PasswordResetToken{}).Error
}

// DeleteExpired removes expired tokens
func (r *PasswordResetRepository) DeleteExpired() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&models.PasswordResetToken{}).Error
}
