package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/roshankumar0036singh/auth-server/internal/service"
)

// APIKeyMiddleware authenticates server-to-server requests carrying an API key
// in the Authorization header as `Api-Key <key>` (#169). Requests are rejected
// for unknown or revoked keys. This is intentionally distinct from bearer JWT
// auth and is exempt from user-facing rate limits.
func APIKeyMiddleware(apiKeyService *service.APIKeyService) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Api-Key ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "missing_api_key",
				"message": "Authorization header must be 'Api-Key <key>'",
			})
			return
		}

		key, err := apiKeyService.Authenticate(strings.TrimSpace(strings.TrimPrefix(auth, "Api-Key ")))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_api_key",
				"message": "the api key is unknown or revoked",
			})
			return
		}

		c.Set("apiKeyID", key.ID)
		c.Set("apiKeyName", key.Name)
		c.Next()
	}
}