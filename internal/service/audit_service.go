package service

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
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

	// Cryptographic chaining (issue #154): each entry hashes its predecessor
	// plus its own canonical payload, so any edit or deletion is detectable.
	prevHash, err := s.auditRepo.LastHash()
	if err != nil {
		return err
	}
	now := time.Now()

	log := &models.AuditLog{
		UserID:    userID,
		Action:    action,
		Entity:    entity,
		EntityID:  entityID,
		IPAddress: ip,
		UserAgent: userAgent,
		Metadata:  metadataJSON,
		PrevHash:  prevHash,
		CreatedAt: now,
	}
	log.Hash = HashEntry(prevHash, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		strPtr(log.UserID), log.Action, log.Entity, log.EntityID, log.IPAddress, log.Metadata,
		now.UTC().Format(time.RFC3339Nano)))

	return s.auditRepo.Create(log)
}

func strPtr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
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
