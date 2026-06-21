package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

type WebAuthnHandler struct {
	webAuthnService *service.WebAuthnService
	userRepo        *repository.UserRepository
	authService     *service.AuthService
}

func NewWebAuthnHandler(was *service.WebAuthnService, ur *repository.UserRepository, as *service.AuthService) *WebAuthnHandler {
	return &WebAuthnHandler{
		webAuthnService: was,
		userRepo:        ur,
		authService:     as,
	}
}

func (h *WebAuthnHandler) BeginRegistration(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse("User not found in context", nil))
		return
	}

	user, err := h.userRepo.FindByID(userID.(string))
	if err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse("User not found", err))
		return
	}

	options, sessionID, err := h.webAuthnService.BeginRegistration(c.Request.Context(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(err.Error(), err))
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
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse("User not found in context", nil))
		return
	}

	sessionID := c.Param("session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("session_id is required", nil))
		return
	}

	user, err := h.userRepo.FindByID(userID.(string))
	if err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse("User not found", err))
		return
	}

	credential, err := h.webAuthnService.FinishRegistration(c.Request.Context(), user, sessionID, c.Request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(err.Error(), err))
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
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Invalid request body", err))
		return
	}

	user, err := h.userRepo.FindByEmail(req.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse("Invalid credentials", nil))
		return
	}

	options, sessionID, err := h.webAuthnService.BeginLogin(c.Request.Context(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(err.Error(), err))
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
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Invalid session_id", nil))
		return
	}

	user, _, err := h.webAuthnService.FinishLogin(c.Request.Context(), sessionID, c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse(err.Error(), err))
		return
	}

	ipAddress := c.ClientIP()
	userAgent := c.Request.UserAgent()

	response, err := h.authService.CreateLoginResponse(user, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to generate tokens", err))
		return
	}

	c.JSON(http.StatusOK, response)
}
