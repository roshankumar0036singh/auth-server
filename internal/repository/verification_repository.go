package repository

import (
	"errors"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

type VerificationRepository struct {
	db *gorm.DB
}

func NewVerificationRepository(db *gorm.DB) *VerificationRepository {
	return &VerificationRepository{db: db}
}

// Create stores a new verification token
func (r *VerificationRepository) Create(token *models.VerificationToken) error {
	return r.db.Create(token).Error
}

// FindByToken retrieves a token by its string value
func (r *VerificationRepository) FindByToken(tokenString string) (*models.VerificationToken, error) {
	var token models.VerificationToken
	if err := r.db.Where("token = ?", tokenString).First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid token")
		}
		return nil, err
	}
	return &token, nil
}

// DeleteByUserID removes all verification tokens for a user
func (r *VerificationRepository) DeleteByUserID(userID string) error {
	return r.db.Where("user_id = ?", userID).Delete(&models.VerificationToken{}).Error
}

// DeleteExpired removes expired tokens
func (r *VerificationRepository) DeleteExpired() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&models.VerificationToken{}).Error
}
