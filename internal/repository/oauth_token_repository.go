package repository

import (
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

type OAuthTokenRepository struct {
	db *gorm.DB
}

func NewOAuthTokenRepository(db *gorm.DB) *OAuthTokenRepository {
	return &OAuthTokenRepository{db: db}
}

// Create creates a new OAuth access token
func (r *OAuthTokenRepository) Create(token *models.OAuthAccessToken) error {
	return r.db.Create(token).Error
}

// FindByToken finds a token by its token string
func (r *OAuthTokenRepository) FindByToken(token string) (*models.OAuthAccessToken, error) {
	var oauthToken models.OAuthAccessToken
	err := r.db.Where("token = ?", token).First(&oauthToken).Error
	if err != nil {
		return nil, err
	}
	return &oauthToken, nil
}

// FindByUserAndClient finds tokens for a specific user and client
func (r *OAuthTokenRepository) FindByUserAndClient(userID, clientID string) ([]models.OAuthAccessToken, error) {
	var tokens []models.OAuthAccessToken
	err := r.db.Where("user_id = ? AND client_id = ?", userID, clientID).Find(&tokens).Error
	return tokens, err
}

// DeleteExpired deletes all expired tokens
func (r *OAuthTokenRepository) DeleteExpired() error {
	return r.db.Where("expires_at < NOW()").Delete(&models.OAuthAccessToken{}).Error
}

// RevokeByClient revokes all tokens for a specific client
func (r *OAuthTokenRepository) RevokeByClient(clientID string) error {
	return r.db.Where("client_id = ?", clientID).Delete(&models.OAuthAccessToken{}).Error
}
