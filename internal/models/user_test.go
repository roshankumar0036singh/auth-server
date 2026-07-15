package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUser_BeforeCreate(t *testing.T) {
	u := &User{
		Email: "test@example.com",
	}

	err := u.BeforeCreate(nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, u.ID)
	assert.Equal(t, "local", u.OAuthProvider)
	assert.Equal(t, "user", u.Role)

	// Test preserving existing values
	uCustom := &User{
		ID:            "custom-id",
		OAuthProvider: "google",
		Role:          "admin",
	}
	err = uCustom.BeforeCreate(nil)
	assert.NoError(t, err)
	assert.Equal(t, "custom-id", uCustom.ID)
	assert.Equal(t, "google", uCustom.OAuthProvider)
	assert.Equal(t, "admin", uCustom.Role)
}

func TestUser_TableName(t *testing.T) {
	u := User{}
	assert.Equal(t, "users", u.TableName())
}

func TestUser_ToPublic(t *testing.T) {
	now := time.Now()
	u := &User{
		ID:            "user-123",
		Email:         "test@example.com",
		FirstName:     "John",
		LastName:      "Doe",
		PasswordHash:  "secret-hash",
		EmailVerified: true,
		MFAEnabled:    true,
		CreatedAt:     now,
		LastLoginAt:   &now,
	}

	pub := u.ToPublic()
	assert.Equal(t, "user-123", pub.ID)
	assert.Equal(t, "test@example.com", pub.Email)
	assert.Equal(t, "John", pub.FirstName)
	assert.Equal(t, "Doe", pub.LastName)
	assert.True(t, pub.EmailVerified)
	assert.True(t, pub.MFAEnabled)
	assert.Equal(t, now, pub.CreatedAt)
	assert.Equal(t, &now, pub.LastLoginAt)
}

func TestUser_IsLocked(t *testing.T) {
	u := &User{}
	assert.False(t, u.IsLocked())

	future := time.Now().Add(1 * time.Hour)
	u.LockedUntil = &future
	assert.True(t, u.IsLocked())

	past := time.Now().Add(-1 * time.Hour)
	u.LockedUntil = &past
	assert.False(t, u.IsLocked())
}

func TestUser_WebAuthnMethods(t *testing.T) {
	u := &User{
		ID:           "webauthn-user-id",
		Email:        "webauthn@example.com",
		FirstName:    "Alice",
		LastName:     "Smith",
		ProfileImage: "https://example.com/avatar.png",
	}

	assert.Equal(t, []byte("webauthn-user-id"), u.WebAuthnID())
	assert.Equal(t, "webauthn@example.com", u.WebAuthnName())
	assert.Equal(t, "Alice Smith", u.WebAuthnDisplayName())
	assert.Equal(t, "https://example.com/avatar.png", u.WebAuthnIcon())

	uNoName := &User{
		Email: "noname@example.com",
	}
	assert.Equal(t, "noname@example.com", uNoName.WebAuthnDisplayName())
}
