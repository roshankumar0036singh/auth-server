package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserOAuthAccount links a user to one OAuth identity (issue #89). A user may
// have several rows, one per provider (Google + GitHub + ...).
type UserOAuthAccount struct {
	ID        string    `gorm:"type:uuid;primary_key" json:"id"`
	UserID    string    `gorm:"type:uuid;index;not null" json:"userId"`
	Provider  string    `gorm:"size:50;not null" json:"provider"` // 'google', 'github'
	OAuthID   string    `gorm:"column:oauth_id;size:255;not null" json:"-"`
	Email     string    `gorm:"size:255" json:"email,omitempty"` // snapshot for quick lookup
	CreatedAt time.Time `json:"createdAt"`
}

// TableName sets the table name
func (UserOAuthAccount) TableName() string { return "user_oauth_accounts" }

// BeforeCreate sets a UUID for the account link
func (a *UserOAuthAccount) BeforeCreate(tx *gorm.DB) error {
	if a.ID == "" {
		a.ID = uuid.New().String()
	}
	return nil
}
