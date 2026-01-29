package repository

import (
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

type AuditRepository struct {
	db *gorm.DB
}

func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// Create logs a new audit event
func (r *AuditRepository) Create(log *models.AuditLog) error {
	return r.db.Create(log).Error
}

// FindByUserID retrieves audit logs for a specific user
func (r *AuditRepository) FindByUserID(userID string, limit int) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	err := r.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Find(&logs).Error
	return logs, err
}
