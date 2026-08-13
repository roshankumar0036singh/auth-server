package service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

func TestAuditChain_IntegrityAndTampering(t *testing.T) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	auditRepo := repository.NewAuditRepository(db)
	auditService := service.NewAuditService(auditRepo)
	verifier := service.NewAuditChainVerifier(auditRepo)

	// fresh chain of 3 events
	for i := 0; i < 3; i++ {
		require.NoError(t, auditService.LogEvent(nil, "EVENT", "USER", "u1", "10.0.0.1", "agent", map[string]interface{}{"i": i}))
	}

	valid, broken := verifier.Verify()
	assert.True(t, valid, "untouched chain must verify")
	assert.Empty(t, broken)

	// tamper with the middle entry
	require.NoError(t, db.Model(&models.AuditLog{}).
		Where("action = ?", "EVENT").
		Order("created_at ASC").
		Limit(1).
		Update("metadata", `{"i":999}`).Error)

	valid, broken = verifier.Verify()
	assert.False(t, valid, "tampered chain must fail")
	assert.NotEmpty(t, broken)
}

func TestAuditChain_EmptyTable(t *testing.T) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	verifier := service.NewAuditChainVerifier(repository.NewAuditRepository(db))
	valid, broken := verifier.Verify()
	assert.True(t, valid)
	assert.Empty(t, broken)

	// single entry verifies too
	require.NoError(t, service.NewAuditService(repository.NewAuditRepository(db)).
		LogEvent(nil, "SOLO", "USER", "u9", "10.0.0.9", "a", nil))
	valid, broken = verifier.Verify()
	assert.True(t, valid)
	assert.Empty(t, broken)
}

