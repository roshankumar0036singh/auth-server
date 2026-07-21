package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type BackupCode struct {
	ID        string         `gorm:"type:uuid;primaryKey"`
	UserID    string         `gorm:"type:uuid;not null;index"`
	CodeHash  string         `gorm:"not null"`
	Used      bool           `gorm:"default:false"`
	CreatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (b *BackupCode) BeforeCreate(tx *gorm.DB) error {
	if b.ID == "" {
		b.ID = uuid.New().String()
	}
	return nil
}

func (BackupCode) TableName() string {
	return "backup_codes"
}