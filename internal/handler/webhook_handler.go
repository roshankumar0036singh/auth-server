package handler

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

// WebhookHandler lets admins register, list, toggle and delete signed
// lifecycle-event webhook endpoints (issue #163).
type WebhookHandler struct {
	repo *repository.WebhookRepository
}

func NewWebhookHandler(repo *repository.WebhookRepository) *WebhookHandler {
	return &WebhookHandler{repo: repo}
}

// validEventName reports whether an event is one of the documented names or
// the wildcard "*".
func validEventName(event string) bool {
	switch event {
	case "*", "user.registered", "user.deleted", "account.locked", "password.changed":
		return true
	default:
		return false
	}
}

// CreateWebhook registers a new webhook endpoint.
// @Summary Create webhook
// @Tags admin
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param body body object true "Webhook {url, events}"
// @Success 201 {object} utils.Response
// @Router /api/admin/webhooks [post]
func (h *WebhookHandler) CreateWebhook(c *gin.Context) {
	var req struct {
		URL    string   `json:"url"`
		Events []string `json:"events"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse("Invalid request body"))
		return
	}

	parsed, err := url.Parse(req.URL)
	if err != nil || parsed.Scheme != "https" && parsed.Scheme != "http" || parsed.Host == "" {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse("webhook URL must be a valid http(s) URL"))
		return
	}
	if len(req.Events) == 0 {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse("at least one event is required"))
		return
	}
	for _, e := range req.Events {
		if !validEventName(e) {
			c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse("invalid event: "+e))
			return
		}
	}

	ownerID := c.GetString("userID")
	webhook := &models.Webhook{
		OwnerID:  ownerID,
		URL:      parsed.String(),
		Secret:   generateWebhookSecret(),
		Events:   req.Events,
		IsActive: true,
	}
	if err := h.repo.Create(webhook); err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to create webhook", err))
		return
	}

	c.JSON(http.StatusCreated, utils.SuccessResponse("Webhook created", gin.H{
		"id":       webhook.ID,
		"url":      webhook.URL,
		"events":   webhook.Events,
		"isActive": webhook.IsActive,
	}))
}

// ListWebhooks lists the caller's webhooks.
// @Summary List webhooks
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Success 200 {object} utils.Response
// @Router /api/admin/webhooks [get]
func (h *WebhookHandler) ListWebhooks(c *gin.Context) {
	webhooks, err := h.repo.ListByOwner(c.GetString("userID"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to list webhooks", err))
		return
	}
	c.JSON(http.StatusOK, utils.SuccessResponse("Webhooks", webhooks))
}

// ToggleWebhook activates/deactivates a webhook.
// @Summary Toggle webhook
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param id path string true "Webhook ID"
// @Router /api/admin/webhooks/{id} [patch]
func (h *WebhookHandler) ToggleWebhook(c *gin.Context) {
	var req struct {
		IsActive *bool `json:"isActive"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.IsActive == nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse("isActive is required"))
		return
	}
	if err := h.repo.SetActive(c.Param("id"), c.GetString("userID"), *req.IsActive); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Failed to update webhook", err))
		return
	}
	c.JSON(http.StatusOK, utils.SuccessResponse("Webhook updated", nil))
}

// DeleteWebhook removes a webhook.
// @Summary Delete webhook
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param id path string true "Webhook ID"
// @Router /api/admin/webhooks/{id} [delete]
func (h *WebhookHandler) DeleteWebhook(c *gin.Context) {
	if err := h.repo.Delete(c.Param("id"), c.GetString("userID")); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Failed to delete webhook", err))
		return
	}
	c.JSON(http.StatusOK, utils.SuccessResponse("Webhook deleted", nil))
}

func generateWebhookSecret() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("x", 64)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
