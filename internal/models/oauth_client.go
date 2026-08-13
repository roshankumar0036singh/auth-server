package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// OAuthClient represents a third-party application that can authenticate users
type OAuthClient struct {
	ID           string         `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"id"`
	Name         string         `gorm:"not null" json:"name"`
	ClientID     string         `gorm:"uniqueIndex;not null" json:"client_id"`
	ClientSecret string         `gorm:"not null" json:"-"` // Hashed, never expose
	RedirectURIs pq.StringArray `gorm:"type:text[]" json:"redirect_uris" swaggertype:"array,string"`
	Scopes       pq.StringArray `gorm:"type:text[]" json:"scopes" swaggertype:"array,string"`
	OwnerID      string         `gorm:"type:uuid" json:"owner_id"`
	IsActive     bool           `gorm:"default:true" json:"is_active"`
	IsPublic     bool           `gorm:"default:false" json:"is_public"`
	// Per-client session TTLs in seconds (issue #162). Zero means "use the
	// global default" so existing clients keep current behavior.
	AccessTokenTTLSeconds  int64 `gorm:"default:0" json:"access_token_ttl_seconds"`
	RefreshTokenTTLSeconds int64 `gorm:"default:0" json:"refresh_token_ttl_seconds"`
        CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// TableName specifies the table name for OAuthClient
func (OAuthClient) TableName() string {
	return "oauth_clients"
}

// BeforeCreate sets a UUID for the client
func (c *OAuthClient) BeforeCreate(tx *gorm.DB) error {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return nil
}
