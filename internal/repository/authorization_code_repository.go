package repository


import (
	"time"
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

// MarkAsUsed atomically marks an authorization code as used. It returns
// (true, nil) only when this call is the one that flipped used from false to
// true; (false, nil) means the code was already used (a replay), and a
// non-nil error indicates a database failure. Callers must treat a false
// result as a single-use violation and refuse to issue a token.
func (r *AuthorizationCodeRepository) MarkAsUsed(code string) (bool, error) {
	result := r.db.Model(&models.AuthorizationCode{}).
		Where("code = ? AND used = ?", code, false).
		Update("used", true)
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected == 1, nil
}

// DeleteExpired deletes all expired authorization codes
func (r *AuthorizationCodeRepository) DeleteExpired() error {
	// return r.db.Where("expires_at < NOW()").Delete(&models.AuthorizationCode{}).Error
	return r.db.Where("expires_at < ?", time.Now()).Delete(&models.AuthorizationCode{}).Error
}
