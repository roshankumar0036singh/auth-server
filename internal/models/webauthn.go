package models

import (
	"encoding/json"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type WebAuthnCredential struct {
	ID           string    `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID       string    `gorm:"type:uuid;not null;index"`
	CredentialID []byte    `gorm:"type:bytea;not null;uniqueIndex"`
	Data         []byte    `gorm:"type:jsonb;not null"` // Serialized webauthn.Credential
	CreatedAt    time.Time `gorm:"autoCreateTime"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime"`
}

func (c *WebAuthnCredential) ToWebAuthn() (*webauthn.Credential, error) {
	var cred webauthn.Credential
	err := json.Unmarshal(c.Data, &cred)
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

func FromWebAuthn(userID string, cred *webauthn.Credential) (*WebAuthnCredential, error) {
	data, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	return &WebAuthnCredential{
		UserID:       userID,
		CredentialID: cred.ID,
		Data:         data,
	}, nil
}
