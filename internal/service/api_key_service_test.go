package service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

func TestAPIKeyService_GenerateAuthenticateRevoke(t *testing.T) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	require.NoError(t, db.AutoMigrate(&models.ApiKey{}))

	keyRepo := repository.NewApiKeyRepository(db)
	svc := service.NewAPIKeyService(keyRepo, service.NewAuditService(repository.NewAuditRepository(db)))

	// generate
	plaintext, id, err := svc.GenerateKey("ci-bot", "admin@example.com")
	require.NoError(t, err)
	assert.Contains(t, plaintext, service.APIKeyPrefix)
	assert.NotEqual(t, "", id)

	// plaintext must NOT be stored
	var raw models.ApiKey
	require.NoError(t, db.First(&raw, "id = ?", id).Error)
	assert.NotEqual(t, plaintext, raw.KeyHash)
	assert.NotEqual(t, plaintext, raw.KeyDigest)

	// authenticate with correct key
	key, err := svc.Authenticate(plaintext)
	require.NoError(t, err)
	assert.Equal(t, id, key.ID)
	assert.False(t, key.IsRevoked())
	assert.NotNil(t, key.LastUsedAt)

	// unknown key
	_, err = svc.Authenticate(service.APIKeyPrefix + "nonexistentvalue123456789012345678901234")
	assert.Error(t, err)

	// malformed header value
	_, err = svc.Authenticate("not-a-key")
	assert.Error(t, err)

	// revoke → authenticate must fail
	require.NoError(t, svc.RevokeKey(id))
	_, err = svc.Authenticate(plaintext)
	assert.Error(t, err)

	// list shows only active keys
	keys, err := svc.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestAPIKeyService_StoresDigestAndHashOnly(t *testing.T) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	require.NoError(t, db.AutoMigrate(&models.ApiKey{}))

	svc := service.NewAPIKeyService(
		repository.NewApiKeyRepository(db),
		service.NewAuditService(repository.NewAuditRepository(db)),
	)

	plaintext, id, err := svc.GenerateKey("digest-check", "admin")
	require.NoError(t, err)

	var stored models.ApiKey
	require.NoError(t, db.First(&stored, "id = ?", id).Error)

	// the bcrypt hash must never match the raw key
	assert.NotEqual(t, plaintext, stored.KeyHash)
	// digest differs from hash and is indexed for lookup
	assert.Len(t, stored.KeyDigest, 64)
	assert.NotEqual(t, stored.KeyHash, stored.KeyDigest)

	key, err := svc.Authenticate(plaintext)
	require.NoError(t, err)
	assert.Equal(t, id, key.ID)
}