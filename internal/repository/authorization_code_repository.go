package repository

import (
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

type AuthorizationCodeRepository struct {
	db *gorm.DB
}

func NewAuthorizationCodeRepository(db *gorm.DB) *AuthorizationCodeRepository {
	return &AuthorizationCodeRepository{db: db}
}

// Create creates a new authorization code
func (r *AuthorizationCodeRepository) Create(code *models.AuthorizationCode) error {
	return r.db.Create(code).Error
}

// FindByCode finds an authorization code by its code string
func (r *AuthorizationCodeRepository) FindByCode(code string) (*models.AuthorizationCode, error) {
	var authCode models.AuthorizationCode
	err := r.db.Where("code = ?", code).First(&authCode).Error
	if err != nil {
		return nil, err
	}
	return &authCode, nil
}

// MarkAsUsed marks an authorization code as used
func (r *AuthorizationCodeRepository) MarkAsUsed(code string) error {
	return r.db.Model(&models.AuthorizationCode{}).
		Where("code = ?", code).
		Update("used", true).Error
}

// DeleteExpired deletes all expired authorization codes
func (r *AuthorizationCodeRepository) DeleteExpired() error {
	return r.db.Where("expires_at < NOW()").Delete(&models.AuthorizationCode{}).Error
}
