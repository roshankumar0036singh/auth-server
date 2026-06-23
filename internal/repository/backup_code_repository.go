package repository

import (
	"errors"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

var ErrBackupCodeNotFound = errors.New("backup code not found")

type BackupCodeRepository struct {
	db *gorm.DB
}

func NewBackupCodeRepository(db *gorm.DB) *BackupCodeRepository {
	return &BackupCodeRepository{db: db}
}

func (r *BackupCodeRepository) Create(code *models.BackupCode) error {
	return r.db.Create(code).Error
}

func (r *BackupCodeRepository) FindByUserID(userID string) ([]models.BackupCode, error) {
	var codes []models.BackupCode

	err := r.db.
		Where("user_id = ? AND used = ?", userID, false).
		Find(&codes).Error

	return codes, err
}

func (r *BackupCodeRepository) MarkUsed(id string) error {
	return r.db.Model(&models.BackupCode{}).
		Where("id = ?", id).
		Update("used", true).Error
}