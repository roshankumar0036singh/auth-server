package models

import (
	"time"

	"github.com/lib/pq"
)

// UserConsent tracks which apps a user has authorized
type UserConsent struct {
	ID        string         `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"id"`
	UserID    string         `gorm:"type:uuid;not null;index:idx_user_client,unique" json:"user_id"`
	ClientID  string         `gorm:"not null;index:idx_user_client,unique" json:"client_id"`
	Scopes    pq.StringArray `gorm:"type:text[]" json:"scopes"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// TableName specifies the table name for UserConsent
func (UserConsent) TableName() string {
	return "user_consents"
}
