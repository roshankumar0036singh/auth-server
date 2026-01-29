package repository

import (
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

type UserConsentRepository struct {
	db *gorm.DB
}

func NewUserConsentRepository(db *gorm.DB) *UserConsentRepository {
	return &UserConsentRepository{db: db}
}

// Create creates a new user consent record
func (r *UserConsentRepository) Create(consent *models.UserConsent) error {
	return r.db.Create(consent).Error
}

// FindByUserAndClient finds consent for a specific user and client
func (r *UserConsentRepository) FindByUserAndClient(userID, clientID string) (*models.UserConsent, error) {
	var consent models.UserConsent
	err := r.db.Where("user_id = ? AND client_id = ?", userID, clientID).First(&consent).Error
	if err != nil {
		return nil, err
	}
	return &consent, nil
}

// Update updates a user consent record
func (r *UserConsentRepository) Update(consent *models.UserConsent) error {
	return r.db.Save(consent).Error
}

// Delete deletes a user consent record
func (r *UserConsentRepository) Delete(userID, clientID string) error {
	return r.db.Where("user_id = ? AND client_id = ?", userID, clientID).
		Delete(&models.UserConsent{}).Error
}

// FindByUser finds all consents for a user
func (r *UserConsentRepository) FindByUser(userID string) ([]models.UserConsent, error) {
	var consents []models.UserConsent
	err := r.db.Where("user_id = ?", userID).Find(&consents).Error
	return consents, err
}
