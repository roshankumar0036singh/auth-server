package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/service"
)

type WebAuthnHandler struct {
	webAuthnService *service.WebAuthnService
	authService     *service.AuthService
}

func NewWebAuthnHandler(was *service.WebAuthnService, as *service.AuthService) *WebAuthnHandler {
	return &WebAuthnHandler{
		webAuthnService: was,
		authService:     as,
	}
}

func (h *WebAuthnHandler) BeginRegistration(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context", "code": "UNAUTHORIZED"})
		return
	}

	options, sessionID, err := h.webAuthnService.BeginRegistration(c.Request.Context(), userID.(string))
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found", "code": "USER_NOT_FOUND"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_SERVER_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"options":    options,
		"session_id": sessionID,
	})
}

func (h *WebAuthnHandler) FinishRegistration(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context", "code": "UNAUTHORIZED"})
		return
	}

	sessionID := c.Param("session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id is required", "code": "BAD_REQUEST"})
		return
	}

	credential, err := h.webAuthnService.FinishRegistration(c.Request.Context(), userID.(string), sessionID, c.Request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "BAD_REQUEST"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Passkey registered successfully",
		"id":      credential.ID,
	})
}

type BeginLoginRequest struct {
	Email string `json:"email" binding:"required,email"`
}

func (h *WebAuthnHandler) BeginLogin(c *gin.Context) {
	var req BeginLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "code": "BAD_REQUEST"})
		return
	}

	options, sessionID, err := h.webAuthnService.BeginLogin(c.Request.Context(), req.Email)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials", "code": "UNAUTHORIZED"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "code": "INTERNAL_SERVER_ERROR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"options":    options,
		"session_id": sessionID,
	})
}

func (h *WebAuthnHandler) FinishLogin(c *gin.Context) {
	sessionID := c.Param("session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session_id", "code": "BAD_REQUEST"})
		return
	}

	user, _, err := h.webAuthnService.FinishLogin(c.Request.Context(), sessionID, c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error(), "code": "UNAUTHORIZED"})
		return
	}

	ipAddress := c.ClientIP()
	userAgent := c.Request.UserAgent()

	response, err := h.authService.ProcessPostLogin(c.Request.Context(), user, ipAddress, userAgent, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens", "code": "INTERNAL_SERVER_ERROR"})
		return
	}

	c.JSON(http.StatusOK, response)
}
