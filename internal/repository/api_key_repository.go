package repository

import (
	"gorm.io/gorm"

	"github.com/roshankumar0036singh/auth-server/internal/models"
)

// ApiKeyRepository persists API keys for server-to-server auth (#169).
type ApiKeyRepository struct {
	db *gorm.DB
}

func NewApiKeyRepository(db *gorm.DB) *ApiKeyRepository {
	return &ApiKeyRepository{db: db}
}

// Create stores a new API key record.
func (r *ApiKeyRepository) Create(key *models.ApiKey) error {
	return r.db.Create(key).Error
}

// FindByKeyDigest looks up a key by the sha256 digest of its plaintext,
// enabling fast lookup without storing the value itself.
func (r *ApiKeyRepository) FindByKeyDigest(digest string) (*models.ApiKey, error) {
	var key models.ApiKey
	err := r.db.Where("key_digest = ?", digest).First(&key).Error
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// ListActive returns all non-revoked keys, newest first.
func (r *ApiKeyRepository) ListActive() ([]models.ApiKey, error) {
	var keys []models.ApiKey
	err := r.db.Where("revoked_at IS NULL").Order("created_at DESC").Find(&keys).Error
	return keys, err
}

// Revoke marks a key as revoked.
func (r *ApiKeyRepository) Revoke(id string, revokedAt interface{}) error {
	return r.db.Model(&models.ApiKey{}).Where("id = ?", id).
		Update("revoked_at", revokedAt).Error
}

// TouchLastUsed records the most recent successful use of a key.
func (r *ApiKeyRepository) TouchLastUsed(id string, usedAt interface{}) error {
	return r.db.Model(&models.ApiKey{}).Where("id = ?", id).
		Update("last_used_at", usedAt).Error
}