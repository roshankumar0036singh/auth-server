package repository

import (
	"github.com/google/uuid"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

// WebhookRepository persists registered webhook endpoints.
type WebhookRepository struct {
	db *gorm.DB
}

func NewWebhookRepository(db *gorm.DB) *WebhookRepository {
	return &WebhookRepository{db: db}
}

func (r *WebhookRepository) Create(webhook *models.Webhook) error {
	if webhook.ID == "" {
		webhook.ID = uuid.New().String()
	}
	return r.db.Create(webhook).Error
}

// FindAllActive returns every active webhook (used by the dispatcher).
func (r *WebhookRepository) FindAllActive() ([]models.Webhook, error) {
	var webhooks []models.Webhook
	err := r.db.Where("is_active = ?", true).Find(&webhooks).Error
	return webhooks, err
}

func (r *WebhookRepository) FindByID(id string) (*models.Webhook, error) {
	var webhook models.Webhook
	err := r.db.Where("id = ?", id).First(&webhook).Error
	if err != nil {
		return nil, err
	}
	return &webhook, nil
}

func (r *WebhookRepository) ListByOwner(ownerID string) ([]models.Webhook, error) {
	var webhooks []models.Webhook
	err := r.db.Where("owner_id = ?", ownerID).Find(&webhooks).Error
	return webhooks, err
}

func (r *WebhookRepository) Delete(id, ownerID string) error {
	return r.db.Where("id = ? AND owner_id = ?", id, ownerID).Delete(&models.Webhook{}).Error
}

func (r *WebhookRepository) SetActive(id, ownerID string, active bool) error {
	return r.db.Model(&models.Webhook{}).
		Where("id = ? AND owner_id = ?", id, ownerID).
		Update("is_active", active).Error
}
