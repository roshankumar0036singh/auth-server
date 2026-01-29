package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

// RequireRole checks if the user has the required role
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
			c.Abort()
			return
		}

		roleStr, ok := userRole.(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Invalid role format", nil))
			c.Abort()
			return
		}

		for _, role := range roles {
			if role == roleStr {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, utils.ForbiddenResponse("Insufficient permissions"))
		c.Abort()
	}
}
