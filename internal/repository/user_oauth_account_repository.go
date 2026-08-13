package repository

import (
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

// UserOAuthAccountRepository manages provider identities per user (issue #89).
type UserOAuthAccountRepository struct {
	db *gorm.DB
}

func NewUserOAuthAccountRepository(db *gorm.DB) *UserOAuthAccountRepository {
	return &UserOAuthAccountRepository{db: db}
}

// Create links a new provider identity to a user.
func (r *UserOAuthAccountRepository) Create(account *models.UserOAuthAccount) error {
	return r.db.Create(account).Error
}

// FindByProviderAndOAuthID looks up an identity by provider + provider user ID.
func (r *UserOAuthAccountRepository) FindByProviderAndOAuthID(provider, oauthID string) (*models.UserOAuthAccount, error) {
	var account models.UserOAuthAccount
	err := r.db.Where("provider = ? AND oauth_id = ?", provider, oauthID).First(&account).Error
	if err != nil {
		return nil, err
	}
	return &account, nil
}

// ListByUserID returns every linked identity for a user, most recent first.
func (r *UserOAuthAccountRepository) ListByUserID(userID string) ([]models.UserOAuthAccount, error) {
	var accounts []models.UserOAuthAccount
	err := r.db.Where("user_id = ?", userID).Order("created_at DESC").Find(&accounts).Error
	return accounts, err
}

// Delete removes one provider link; returns ErrNoRows-style error when absent.
func (r *UserOAuthAccountRepository) Delete(userID, provider string) error {
	return r.db.Where("user_id = ? AND provider = ?", userID, provider).Delete(&models.UserOAuthAccount{}).Error
}

// CountByProviderAndEmail prevents duplicate links across accounts.
func (r *UserOAuthAccountRepository) CountByProviderAndOAuthID(provider, oauthID string) (int64, error) {
	var count int64
	err := r.db.Model(&models.UserOAuthAccount{}).Where("provider = ? AND oauth_id = ?", provider, oauthID).Count(&count).Error
	return count, err
}
