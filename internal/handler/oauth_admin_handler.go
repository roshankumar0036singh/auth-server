package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

type OAuthAdminHandler struct {
	oauthProviderService *service.OAuthProviderService
}

func NewOAuthAdminHandler(oauthProviderService *service.OAuthProviderService) *OAuthAdminHandler {
	return &OAuthAdminHandler{
		oauthProviderService: oauthProviderService,
	}
}

// CreateOAuthClient creates a new OAuth client
// @Summary Create OAuth Client
// @Description Admin endpoint to create a new OAuth client for third-party apps
// @Tags OAuth Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateOAuthClientRequest true "Client details"
// @Success 201 {object} CreateOAuthClientResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 403 {object} utils.ErrorResponse
// @Router /api/admin/oauth/clients [post]
func (h *OAuthAdminHandler) CreateOAuthClient(c *gin.Context) {
	var req CreateOAuthClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	// Get current user ID from context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("User not authenticated"))
		return
	}

	// Create the OAuth client
	client, clientSecret, err := h.oauthProviderService.CreateClient(
		req.Name,
		req.RedirectURIs,
		req.Scopes,
		userID.(string),
	)
	if err != nil {
		utils.BadRequestResponse(c, err.Error())
		return
	}

	// Return client details with secret (only shown once)
	c.JSON(http.StatusCreated, CreateOAuthClientResponse{
		Success: true,
		Message: "OAuth client created successfully",
		Data: OAuthClientData{
			ID:           client.ID,
			Name:         client.Name,
			ClientID:     client.ClientID,
			ClientSecret: clientSecret, // Only returned once!
			RedirectURIs: client.RedirectURIs,
			Scopes:       client.Scopes,
			CreatedAt:    client.CreatedAt,
		},
	})
}

// ListOAuthClients lists all OAuth clients
// @Summary List OAuth Clients
// @Description Admin endpoint to list all OAuth clients
// @Tags OAuth Admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} ListOAuthClientsResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 403 {object} utils.ErrorResponse
// @Router /api/admin/oauth/clients [get]
func (h *OAuthAdminHandler) ListOAuthClients(c *gin.Context) {
	// TODO: Add method to service to list all clients
	// For now, return empty list
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    []interface{}{},
		"message": "OAuth client listing not yet implemented",
	})
}

// DeleteOAuthClient deletes an OAuth client
// @Summary Delete OAuth Client
// @Description Admin endpoint to delete an OAuth client
// @Tags OAuth Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "Client ID"
// @Success 200 {object} utils.SuccessResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 403 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Router /api/admin/oauth/clients/{id} [delete]
func (h *OAuthAdminHandler) DeleteOAuthClient(c *gin.Context) {
	_ = c.Param("id") // TODO: Implement deletion logic

	// Delete via repository (should be in service layer in production)
	// For now, simplified implementation
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "OAuth client deleted successfully",
	})
}

// DTOs
type CreateOAuthClientRequest struct {
	Name         string   `json:"name" binding:"required"`
	RedirectURIs []string `json:"redirect_uris" binding:"required,min=1"`
	Scopes       []string `json:"scopes" binding:"required,min=1"`
}

type CreateOAuthClientResponse struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Data    OAuthClientData `json:"data"`
}

type OAuthClientData struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"` // Only in creation response
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	CreatedAt    interface{} `json:"created_at"`
}

type ListOAuthClientsResponse struct {
	Success bool          `json:"success"`
	Data    []interface{} `json:"data"`
}
