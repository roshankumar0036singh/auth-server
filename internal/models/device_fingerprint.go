package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type DeviceFingerprint struct {
	ID              string    `gorm:"type:uuid;primary_key" json:"id"`
	UserID          string    `gorm:"type:uuid;not null;index" json:"userId"`
	FingerprintHash string    `gorm:"not null;index" json:"fingerprintHash"`
	UserAgent       string    `gorm:"size:500" json:"userAgent"`
	IPAddress       string    `gorm:"size:45" json:"ipAddress"`
	LastSeenAt      time.Time `json:"lastSeenAt"`
	CreatedAt       time.Time `json:"createdAt"`
}

func (d *DeviceFingerprint) BeforeCreate(tx *gorm.DB) error {
	if d.ID == "" {
		d.ID = uuid.New().String()
	}
	return nil
}

func (DeviceFingerprint) TableName() string {
	return "device_fingerprints"
}
