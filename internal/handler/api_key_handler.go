package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
)

// APIKeyHandler exposes admin management of server-to-server API keys (#169).
type APIKeyHandler struct {
	apiKeyService *service.APIKeyService
	userRepo      *repository.UserRepository
}

func NewAPIKeyHandler(apiKeyService *service.APIKeyService, userRepo *repository.UserRepository) *APIKeyHandler {
	return &APIKeyHandler{apiKeyService: apiKeyService, userRepo: userRepo}
}

type createAPIKeyRequest struct {
	Name string `json:"name" binding:"required,min=3,max=100"`
}

type createAPIKeyResponse struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	APIKey string `json:"apiKey"` // plaintext, shown exactly once
}

// CreateAPIKey generates a new API key.
func (h *APIKeyHandler) CreateAPIKey(c *gin.Context) {
	var req createAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "name is required (3-100 chars)"})
		return
	}

	adminUserID, _ := c.Get("userID")

	plaintext, id, err := h.apiKeyService.GenerateKey(req.Name, toString(adminUserID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "key_generation_failed"})
		return
	}

	c.JSON(http.StatusCreated, createAPIKeyResponse{
		ID:     id,
		Name:   req.Name,
		APIKey: plaintext,
	})
}

// ListAPIKeys returns all active keys, newest first.
func (h *APIKeyHandler) ListAPIKeys(c *gin.Context) {
	keys, err := h.apiKeyService.ListKeys()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list_failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

// RevokeAPIKey revokes a key by id.
func (h *APIKeyHandler) RevokeAPIKey(c *gin.Context) {
	id := c.Param("keyId")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "keyId is required"})
		return
	}
	if err := h.apiKeyService.RevokeKey(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "revoke_failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// VerifyUser is a server-to-server endpoint for microservices that cannot use
// user JWTs: it resolves whether the given email belongs to a confirmed user.
func (h *APIKeyHandler) VerifyUser(c *gin.Context) {
	email := strings.ToLower(strings.TrimSpace(c.Param("email")))
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "email is required"})
		return
	}

	user, err := h.userRepo.FindByEmail(email)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"verified": false, "email": email})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"verified": user.EmailVerified && user.IsActive,
		"email":    email,
		"userId":   user.ID,
	})
}

func toString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}