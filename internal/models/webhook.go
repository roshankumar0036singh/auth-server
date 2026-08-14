package models

import (
	"time"

	"github.com/lib/pq"
)

// Webhook is a registered HTTP endpoint that receives signed notifications
// for subscribed user lifecycle events (issue #163).
type Webhook struct {
	ID        string         `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OwnerID   string         `gorm:"type:uuid;not null;index" json:"ownerId"`
	URL       string         `gorm:"not null;uniqueIndex" json:"url"`
	Secret    string         `gorm:"not null" json:"-"`
	Events    pq.StringArray `gorm:"type:text[]" json:"events"`
	IsActive  bool           `gorm:"default:true" json:"isActive"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
}
