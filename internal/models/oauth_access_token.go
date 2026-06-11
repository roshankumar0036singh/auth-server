package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// OAuthAccessToken represents an access token issued to a third-party app
type OAuthAccessToken struct {
	ID        string      `gorm:"primaryKey;type:uuid" json:"id"`
	Token     string      `gorm:"uniqueIndex;not null" json:"token"`
	ClientID  string      `gorm:"not null" json:"client_id"`
	UserID    string      `gorm:"type:uuid;not null" json:"user_id"`
	Scopes    StringArray `json:"scopes"`
	ExpiresAt time.Time   `json:"expires_at"`
	CreatedAt time.Time   `json:"created_at"`
}

// TableName specifies the table name for OAuthAccessToken
func (OAuthAccessToken) TableName() string {
	return "oauth_access_tokens"
}

func (t *OAuthAccessToken) BeforeCreate(tx *gorm.DB) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	return nil
}

// IsExpired checks if the token has expired
func (t *OAuthAccessToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}
