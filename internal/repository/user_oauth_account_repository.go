package repository

import (
	"errors"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

type UserOAuthAccountRepository struct {
	db *gorm.DB
}

func NewUserOAuthAccountRepository(db *gorm.DB) *UserOAuthAccountRepository {
	return &UserOAuthAccountRepository{
		db: db,
	}
}

func (r *UserOAuthAccountRepository) Create(account *models.UserOAuthAccount) error {
	return r.db.Create(account).Error
}

func (r *UserOAuthAccountRepository) FindByProvider(
	provider, providerUserID string,
) (*models.UserOAuthAccount, error) {

	var account models.UserOAuthAccount

	if err := r.db.
		Where(
			"provider = ? AND provider_user_id = ?",
			provider,
			providerUserID,
		).
		First(&account).Error; err != nil {

		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}

		return nil, err
	}

	return &account, nil
}

func (r *UserOAuthAccountRepository) FindByUserID(
	userID string,
) ([]models.UserOAuthAccount, error) {

	var accounts []models.UserOAuthAccount

	err := r.db.
		Where("user_id = ?", userID).
		Find(&accounts).Error

	return accounts, err
}

func (r *UserOAuthAccountRepository) Delete(
	userID, provider string,
) error {

	result := r.db.
		Where(
			"user_id = ? AND provider = ?",
			userID,
			provider,
		).
		Delete(&models.UserOAuthAccount{})

	if result.RowsAffected == 0 {
		return errors.New("oauth account not found")
	}

	return result.Error
}
