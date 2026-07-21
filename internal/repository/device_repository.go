package repository

import (
	"errors"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

type DeviceRepository struct {
	db *gorm.DB
}

func NewDeviceRepository(db *gorm.DB) *DeviceRepository {
	return &DeviceRepository{db: db}
}

func (r *DeviceRepository) FindByFingerprint(userID, hash string) (*models.DeviceFingerprint, error) {
	var device models.DeviceFingerprint
	err := r.db.Where("user_id = ? AND fingerprint_hash = ?", userID, hash).First(&device).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Return nil if not found, instead of error
		}
		return nil, err
	}
	return &device, nil
}

func (r *DeviceRepository) Create(device *models.DeviceFingerprint) error {
	return r.db.Create(device).Error
}

func (r *DeviceRepository) UpdateLastSeen(id string, lastSeen time.Time) error {
	return r.db.Model(&models.DeviceFingerprint{}).Where("id = ?", id).Update("last_seen_at", lastSeen).Error
}
