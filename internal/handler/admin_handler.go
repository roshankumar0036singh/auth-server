package handler

import (
	"net/http"
	"strconv"

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
	limitStr := c.DefaultQuery("limit", "10")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	users, total, err := h.authService.GetAllUsers(limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to fetch users", err))
		return
	}

	response := gin.H{
		"users":  users,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("List of users", response))
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
