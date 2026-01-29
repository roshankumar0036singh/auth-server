package repository

import (
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

type OAuthClientRepository struct {
	db *gorm.DB
}

func NewOAuthClientRepository(db *gorm.DB) *OAuthClientRepository {
	return &OAuthClientRepository{db: db}
}

// Create creates a new OAuth client
func (r *OAuthClientRepository) Create(client *models.OAuthClient) error {
	return r.db.Create(client).Error
}

// FindByClientID finds a client by its client ID
func (r *OAuthClientRepository) FindByClientID(clientID string) (*models.OAuthClient, error) {
	var client models.OAuthClient
	err := r.db.Where("client_id = ?", clientID).First(&client).Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// FindByID finds a client by its ID
func (r *OAuthClientRepository) FindByID(id string) (*models.OAuthClient, error) {
	var client models.OAuthClient
	err := r.db.Where("id = ?", id).First(&client).Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// FindByOwner finds all clients owned by a user
func (r *OAuthClientRepository) FindByOwner(ownerID string) ([]models.OAuthClient, error) {
	var clients []models.OAuthClient
	err := r.db.Where("owner_id = ?", ownerID).Find(&clients).Error
	return clients, err
}

// FindAll returns all OAuth clients
func (r *OAuthClientRepository) FindAll() ([]models.OAuthClient, error) {
	var clients []models.OAuthClient
	err := r.db.Find(&clients).Error
	return clients, err
}

// Update updates an OAuth client
func (r *OAuthClientRepository) Update(client *models.OAuthClient) error {
	return r.db.Save(client).Error
}

// Delete deletes an OAuth client
func (r *OAuthClientRepository) Delete(id string) error {
	return r.db.Delete(&models.OAuthClient{}, "id = ?", id).Error
}
