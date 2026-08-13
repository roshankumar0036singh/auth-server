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
func (r *AuditRepository) FindByUserID(userID string, limit, offset int) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	err := r.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Order("id DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

func (r *AuditRepository) CountByUserID(userID string) (int64, error) {
	var count int64

	err := r.db.Model(&models.AuditLog{}).Where("user_id = ?", userID).Count(&count).Error

	return count, err
}

// LastHash returns the hash of the most recently written audit entry, or ""
// when the table is empty. Used to extend the cryptographic chain (#154).
func (r *AuditRepository) LastHash() (string, error) {
	var last models.AuditLog
	err := r.db.Order("created_at DESC, id DESC").First(&last).Error
	if err == gorm.ErrRecordNotFound {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return last.Hash, nil
}

// FindChained returns audit entries in insertion order for the chain
// verifier (#154).
func (r *AuditRepository) FindChained(offset, limit int) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	err := r.db.Order("created_at ASC, id ASC").Offset(offset).Limit(limit).Find(&logs).Error
	return logs, err
}
