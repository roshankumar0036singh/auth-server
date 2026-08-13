package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AuditLog represents a security audit event. Each entry carries a
// cryptographic chain (PrevHash + Hash) so tampering breaks the chain and is
// detectable by the verifier (issue #154).
type AuditLog struct {
	ID        string    `gorm:"type:uuid;primary_key" json:"id"`
	UserID    *string   `gorm:"index" json:"userId,omitempty"`
	Action    string    `gorm:"not null" json:"action"`
	Entity    string    `gorm:"size:50" json:"entity"`    // e.g., "USER", "TOKEN"
	EntityID  string    `gorm:"size:255" json:"entityId"` // ID of the affected entity
	IPAddress string    `gorm:"size:45" json:"ipAddress"`
	UserAgent string    `gorm:"size:255" json:"userAgent"`
	Metadata  string    `gorm:"type:text" json:"metadata"` // JSON string for extra details
	PrevHash  string    `gorm:"size:64" json:"prevHash"`   // sha256 of the previous entry
	Hash      string    `gorm:"size:64" json:"hash"`       // sha256 chain of this entry
	CreatedAt time.Time `json:"createdAt"`
}

func (a *AuditLog) BeforeCreate(tx *gorm.DB) error {
	if a.ID == "" {
		a.ID = uuid.New().String()
	}
	return nil
}
