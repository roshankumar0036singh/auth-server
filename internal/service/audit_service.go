package service

import (
	"encoding/json"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
)

type AuditService struct {
	auditRepo *repository.AuditRepository
}

func NewAuditService(auditRepo *repository.AuditRepository) *AuditService {
	return &AuditService{auditRepo: auditRepo}
}

// LogEvent creates an audit log entry
func (s *AuditService) LogEvent(userID *string, action, entity, entityID, ip, userAgent string, metadata map[string]interface{}) error {
	metadataJSON := "{}"
	if metadata != nil {
		bytes, err := json.Marshal(metadata)
		if err == nil {
			metadataJSON = string(bytes)
		}
	}

	log := &models.AuditLog{
		UserID:    userID,
		Action:    action,
		Entity:    entity,
		EntityID:  entityID,
		IPAddress: ip,
		UserAgent: userAgent,
		Metadata:  metadataJSON,
	}

	return s.auditRepo.Create(log)
}

// GetUserAuditLogs retrieves the audit logs for a specific user
func (s *AuditService) GetUserAuditLogs(userID string) ([]models.AuditLog, error) {
	// Limit to last 50 events for now
	return s.auditRepo.FindByUserID(userID, 50)
}
