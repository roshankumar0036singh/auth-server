package service

import (
	"context"
	"encoding/json"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
)

type AuditService struct {
	auditRepo *repository.AuditRepository
	webhooks  *WebhookService
}

func NewAuditService(auditRepo *repository.AuditRepository, webhooks *WebhookService) *AuditService {
	return &AuditService{auditRepo: auditRepo, webhooks: webhooks}
}

// LogEvent creates an audit log entry and (when webhooks are configured)
// asynchronously notifies subscribers of the lifecycle event (issue #163).
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

	if err := s.auditRepo.Create(log); err != nil {
		return err
	}

	s.dispatchWebhook(userID, action, entity, entityID, ip, userAgent, metadata)
	return nil
}

// dispatchWebhook fans the lifecycle event out to subscribed, active webhook
// endpoints. It never blocks the audit write.
func (s *AuditService) dispatchWebhook(userID *string, action, entity, entityID, ip, userAgent string, metadata map[string]interface{}) {
	if s.webhooks == nil {
		return
	}
	var uid string
	if userID != nil {
		uid = *userID
	}
	payload := map[string]interface{}{
		"userID":    uid,
		"entity":    entity,
		"entityID":  entityID,
		"ipAddress": ip,
		"userAgent": userAgent,
	}
	if metadata != nil {
		payload["metadata"] = metadata
	}
	s.webhooks.Dispatch(context.Background(), WebhookEventName(action), payload)
}

// GetUserAuditLogs retrieves the audit logs for a specific user
func (s *AuditService) GetUserAuditLogs(userID string, page, limit int) (*dto.AuditLogsResponse, error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	}
	maxInt := int(^uint(0) >> 1)
	maxPage := maxInt / limit
	if page > maxPage {
		page = maxPage
	}

	offset := (page - 1) * limit

	logs, err := s.auditRepo.FindByUserID(userID, limit, offset)
	if err != nil {
		return nil, err
	}

	totalCount, err := s.auditRepo.CountByUserID(userID)
	if err != nil {
		return nil, err
	}

	hasMore := int64(offset)+int64(len(logs)) < totalCount

	return &dto.AuditLogsResponse{
		Logs: logs,
		MetaData: dto.PaginationMetaData{
			TotalCount:  totalCount,
			CurrentPage: page,
			HasMore:     hasMore,
		},
	}, nil
}
