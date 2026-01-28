package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// Register handles user registration
// @Summary Register a new user
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.RegisterRequest true "Registration data"
// @Success 201 {object} utils.Response
// @Failure 400 {object} utils.Response
// @Router /api/auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req dto.RegisterRequest

	// Validate request body
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse(err.Error()))
		return
	}

	// Register user
	user, err := h.authService.Register(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Registration failed", err))
		return
	}

	c.JSON(http.StatusCreated, utils.SuccessResponse("Registration successful", user.ToPublic()))
}

// Login handles user login with device tracking
// @Summary Login user
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.LoginRequest true "Login credentials"
// @Success 200 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Router /api/auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req dto.LoginRequest

	// Validate request body
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse(err.Error()))
		return
	}

	// Get device information
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Authenticate user
	loginResp, err := h.authService.Login(&req, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse("Login failed", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Login successful", loginResp))
}

// RefreshToken handles refresh token requests with token rotation
// @Summary Refresh access token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.RefreshTokenRequest true "Refresh token"
// @Success 200 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Router /api/auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req dto.RefreshTokenRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse(err.Error()))
		return
	}

	// Get device information for new token
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Refresh with token rotation
	tokenResp, err := h.authService.RefreshAccessToken(req.RefreshToken, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse("Token refresh failed", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Token refreshed successfully", tokenResp))
}

// Logout handles user logout
// @Summary Logout user
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.LogoutRequest false "Logout request"
// @Success 200 {object} utils.Response
// @Router /api/auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	// Get access token from header
	authHeader := c.GetHeader("Authorization")
	accessToken := ""
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 {
			accessToken = parts[1]
		}
	}

	// Get refresh token from body (optional)
	var req dto.LogoutRequest
	c.ShouldBindJSON(&req)

	// Logout
	if err := h.authService.Logout(accessToken, req.RefreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Logout failed", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Logout successful", nil))
}

// LogoutAll handles logout from all devices
// @Summary Logout from all devices
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} utils.Response
// @Router /api/auth/logout-all [post]
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	// Get current access token
	authHeader := c.GetHeader("Authorization")
	accessToken := ""
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 {
			accessToken = parts[1]
		}
	}

	// Logout from all devices
	if err := h.authService.LogoutAll(userID.(string), accessToken); err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to logout from all devices", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Logged out from all devices", nil))
}

// GetMe returns the current authenticated user's info
// @Summary Get current user
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Router /api/auth/me [get]
func (h *AuthHandler) GetMe(c *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	// Get user details
	user, err := h.authService.GetUserByID(userID.(string))
	if err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse("User not found", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("User retrieved successfully", user.ToPublic()))
}

// GetSessions returns all active sessions for the current user
// @Summary Get active sessions
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} utils.Response
// @Router /api/auth/sessions [get]
func (h *AuthHandler) GetSessions(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	// Get sessions
	sessions, err := h.authService.GetUserSessions(userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to retrieve sessions", err))
		return
	}

	// Convert to response format
	sessionResponses := make([]dto.SessionResponse, len(sessions))
	for i, session := range sessions {
		sessionResponses[i] = dto.SessionResponse{
			ID:        session.ID,
			IPAddress: session.IPAddress,
			UserAgent: session.UserAgent,
			CreatedAt: session.CreatedAt.Format("2006-01-02 15:04:05"),
			ExpiresAt: session.ExpiresAt.Format("2006-01-02 15:04:05"),
			IsCurrent: false, // TODO: Determine if this is the current session
		}
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Sessions retrieved successfully", sessionResponses))
}

// RevokeSession revokes a specific session
// @Summary Revoke a session
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Param sessionId path string true "Session ID"
// @Success 200 {object} utils.Response
// @Router /api/auth/sessions/{sessionId} [delete]
func (h *AuthHandler) RevokeSession(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	// Get session ID from URL
	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse("Session ID is required"))
		return
	}

	// Revoke session
	if err := h.authService.RevokeSession(userID.(string), sessionID); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Failed to revoke session", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Session revoked successfully", nil))
}
