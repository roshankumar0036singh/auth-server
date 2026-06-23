package service_test

import (
	"testing"

	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupAuditService(t *testing.T) (*service.AuditService, *repository.AuditRepository) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	t.Cleanup(func() { mr.Close() })

	auditRepo := repository.NewAuditRepository(db)
	auditService := service.NewAuditService(auditRepo)

	return auditService, auditRepo
}

func TestAuditService_LogEvent_WithMetadata(t *testing.T) {
	s, _ := setupAuditService(t)

	userID := "user-abc-123"
	metadata := map[string]interface{}{
		"status": "success",
		"tier":   int(1),
	}

	err := s.LogEvent(&userID, "user.login", "users", "user-abc-123", "192.168.1.1", "Mozilla/5.0", metadata)
	assert.NoError(t, err)

	// Pull records back out to verify state values inside the persistence layer
	logs, err := s.GetUserAuditLogs(userID)
	assert.NoError(t, err)
	require.Len(t, logs, 1)

	assert.Equal(t, "user.login", logs[0].Action)
	assert.Equal(t, "192.168.1.1", logs[0].IPAddress)
	assert.Contains(t, logs[0].Metadata, `"status":"success"`)
}

func TestAuditService_LogEvent_NilMetadataAndNilUser(t *testing.T) {
	s, _ := setupAuditService(t)

	// Test fallback string literal handling "{}" when map input is omitted
	err := s.LogEvent(nil, "system.panic", "server", "node-01", "127.0.0.1", "Go-http-client", nil)
	assert.NoError(t, err)
}

func TestAuditService_GetUserAuditLogs_Empty(t *testing.T) {
	s, _ := setupAuditService(t)

	logs, err := s.GetUserAuditLogs("nonexistent-user")
	assert.NoError(t, err)
	assert.Empty(t, logs)
}