package models

import (
	"time"

	"github.com/lib/pq"
)

// AuthorizationCode represents a temporary code issued during OAuth flow
type AuthorizationCode struct {
	ID          string         `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"id"`
	Code        string         `gorm:"uniqueIndex;not null" json:"code"`
	ClientID    string         `gorm:"not null" json:"client_id"`
	UserID      string         `gorm:"type:uuid;not null" json:"user_id"`
	Scopes      pq.StringArray `gorm:"type:text[]" json:"scopes"`
	RedirectURI string         `gorm:"not null" json:"redirect_uri"`
	ExpiresAt   time.Time      `gorm:"not null" json:"expires_at"`
	Used        bool           `gorm:"default:false" json:"used"`
	CreatedAt   time.Time      `json:"created_at"`
}

// TableName specifies the table name for AuthorizationCode
func (AuthorizationCode) TableName() string {
	return "authorization_codes"
}

// IsExpired checks if the authorization code has expired
func (ac *AuthorizationCode) IsExpired() bool {
	return time.Now().After(ac.ExpiresAt)
}

// IsValid checks if the code is valid (not used and not expired)
func (ac *AuthorizationCode) IsValid() bool {
	return !ac.Used && !ac.IsExpired()
}
