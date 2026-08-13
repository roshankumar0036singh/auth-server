package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DeviceFingerprint records a hashed device/location pair seen for a user,
// enabling "new device detected" alerts (#168). The raw User-Agent and IP are
// never stored; only the fingerprint hash is persisted.
type DeviceFingerprint struct {
	ID        string    `gorm:"type:uuid;primary_key" json:"id"`
	UserID    string    `gorm:"type:uuid;not null;index" json:"userId"`
	Hash      string    `gorm:"size:64;not null" json:"-"`
	UserAgent string    `gorm:"size:60;not null" json:"userAgent"` // truncated preview, no full UA
	IP        string    `gorm:"size:45;not null" json:"ip"`        // subnet only (e.g. 203.0.113.0/24)
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

func (d *DeviceFingerprint) BeforeCreate(_ *gorm.DB) error {
	if d.ID == "" {
		d.ID = uuid.New().String()
	}
	return nil
}
