package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ApiKey is a long-lived, server-to-server credential. Only its bcrypt hash
// is stored; the plaintext is returned exactly once at creation (#169).
type ApiKey struct {
	ID         string     `gorm:"type:uuid;primary_key" json:"id"`
	Name       string     `gorm:"size:100;not null" json:"name"`
	Prefix     string     `gorm:"size:8;not null" json:"prefix"`
	KeyDigest  string     `gorm:"size:64;not null;index" json:"-"` // hex sha256 of the key, for lookup
	KeyHash    string     `gorm:"size:255;not null" json:"-"`      // bcrypt of the key, for verification
	CreatedBy  string     `gorm:"size:100" json:"createdBy"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

func (k *ApiKey) BeforeCreate(_ *gorm.DB) error {
	if k.ID == "" {
		k.ID = uuid.New().String()
	}
	return nil
}

// IsRevoked reports whether the key has been revoked.
func (k *ApiKey) IsRevoked() bool {
	return k.RevokedAt != nil
}