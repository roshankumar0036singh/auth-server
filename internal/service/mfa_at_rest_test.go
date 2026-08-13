package service_test

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

func TestMFASecretEncryptedAtRest(t *testing.T) {
	authService, db, mr := testutils.SetupIntegrationTest(t)
	_ = db
	defer mr.Close()

	// enable encryption key so secrets get sealed
	authService.SetEncryptionKeyForTest("0123456789abcdef0123456789abcdef")

	user, err := authService.Register(&dto.RegisterRequest{
		Email:    "mfa-secure@example.com",
		Password: "StrongPass123!",
	})
	require.NoError(t, err)

	enableResp, err := authService.EnableMFA(user.ID)
	require.NoError(t, err)
	require.NotEmpty(t, enableResp.Secret)

	// the seed stored under mfa_secret must NOT be the plaintext
	var stored struct{ MFASecret string }
	require.NoError(t, db.Raw("SELECT mfa_secret FROM users WHERE id = ?", user.ID).Scan(&stored).Error)
	assert.Equal(t, "enc:", stored.MFASecret[:4], "secret must carry the encrypted marker")
	assert.NotEqual(t, enableResp.Secret, stored.MFASecret, "plaintext seed must never hit the DB")

	// verifying with a valid code still works (decrypt path)
	code, err := totp.GenerateCode(enableResp.Secret, time.Now())
	require.NoError(t, err)
	require.NoError(t, authService.VerifyEnableMFA(user.ID, code))
}

func TestMFALegacyPlaintextStillValidates(t *testing.T) {
	authService, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	user, err := authService.Register(&dto.RegisterRequest{
		Email:    "mfa-legacy@example.com",
		Password: "StrongPass123!",
	})
	require.NoError(t, err)

	// simulate a legacy account: plaintext seed in the db
	require.NoError(t, db.Exec("UPDATE users SET mfa_secret = ? WHERE id = ?", "legacyplainsecret123", user.ID).Error)

	// legacy fallback does not error and compares using the plaintext
	got, err := authService.DecryptMFASecretForTest("legacyplainsecret123")
	require.NoError(t, err)
	assert.Equal(t, "legacyplainsecret123", got)
}
