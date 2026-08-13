package repository

import (
	"gorm.io/gorm"

	"github.com/roshankumar0036singh/auth-server/internal/models"
)

// DeviceFingerprintRepository persists hashed device fingerprints (#168).
type DeviceFingerprintRepository struct {
	db *gorm.DB
}

func NewDeviceFingerprintRepository(db *gorm.DB) *DeviceFingerprintRepository {
	return &DeviceFingerprintRepository{db: db}
}

// Exists reports whether a user has been seen from the given fingerprint.
func (r *DeviceFingerprintRepository) Exists(userID, hash string) (bool, error) {
	var count int64
	err := r.db.Model(&models.DeviceFingerprint{}).
		Where("user_id = ? AND hash = ?", userID, hash).
		Count(&count).Error
	return count > 0, err
}

// Create stores a newly-seen fingerprint.
func (r *DeviceFingerprintRepository) Create(fp *models.DeviceFingerprint) error {
	return r.db.Create(fp).Error
}

// TouchLastSeen updates the last-seen timestamp of an existing fingerprint.
func (r *DeviceFingerprintRepository) TouchLastSeen(userID, hash string, at interface{}) error {
	return r.db.Model(&models.DeviceFingerprint{}).
		Where("user_id = ? AND hash = ?", userID, hash).
		Update("last_seen", at).Error
}
