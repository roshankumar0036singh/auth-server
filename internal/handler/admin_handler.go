package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

type AdminHandler struct {
	authService *service.AuthService
}

func NewAdminHandler(authService *service.AuthService) *AdminHandler {
	return &AdminHandler{
		authService: authService,
	}
}

// GetUsers lists all users (Note: Pagination should be added for production)
// @Summary List all users
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Success 200 {object} utils.Response
// @Router /api/admin/users [get]
func (h *AdminHandler) GetUsers(c *gin.Context) {
	// TODO: Implement GetAllUsers in AuthService/UserRepository with pagination
	// For now, returning placeholder
	c.JSON(http.StatusOK, utils.SuccessResponse("List of users", []string{"user1", "user2"}))
}

// LockUser locks a user account
// @Summary Lock user
// @Tags admin
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} utils.Response
// @Router /api/admin/users/{id}/lock [post]
func (h *AdminHandler) LockUser(c *gin.Context) {
	userID := c.Param("id")
	// TODO: Implement LockUser in AuthService
	c.JSON(http.StatusOK, utils.SuccessResponse("User locked successfully", map[string]string{"userID": userID}))
}

// UnlockUser unlocks a user account
// @Summary Unlock user
// @Tags admin
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} utils.Response
// @Router /api/admin/users/{id}/unlock [post]
func (h *AdminHandler) UnlockUser(c *gin.Context) {
	userID := c.Param("id")
	// TODO: Implement UnlockUser in AuthService
	c.JSON(http.StatusOK, utils.SuccessResponse("User unlocked successfully", map[string]string{"userID": userID}))
}

// DeleteUser deletes a user account (admin override)
// @Summary Delete user
// @Tags admin
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} utils.Response
// @Router /api/admin/users/{id} [delete]
func (h *AdminHandler) DeleteUser(c *gin.Context) {
	userID := c.Param("id")
	if err := h.authService.DeleteAccount(userID); err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to delete user", err))
		return
	}
	c.JSON(http.StatusOK, utils.SuccessResponse("User deleted successfully", nil))
}
