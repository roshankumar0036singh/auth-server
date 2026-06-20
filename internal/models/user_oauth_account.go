package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserOAuthAccount struct {
	ID             string `gorm:"type:uuid;primaryKey"`
	UserID         string `gorm:"type:uuid;not null"`
	Provider       string `gorm:"size:50;not null"`
	ProviderUserID string `gorm:"size:255;not null"`

	User User `gorm:"foreignKey:UserID"`
}

func (u *UserOAuthAccount) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	return nil
}

func (UserOAuthAccount) TableName() string {
	return "user_oauth_accounts"
}
