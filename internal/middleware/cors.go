package middleware

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/config"
)

// CORSMiddleware configures CORS for the application
func CORSMiddleware(cfg *config.Config) gin.HandlerFunc {
	// Default fallbacks if config is somehow nil
	allowOrigins := []string{"http://localhost:3000", "http://localhost:5173"}

	// Use the cleanly validated, deduplicated origins from our config load setup
	if cfg != nil && len(cfg.Security.AllowedOrigins) > 0 {
		allowOrigins = cfg.Security.AllowedOrigins
	}

	return cors.New(cors.Config{
		AllowOrigins:     allowOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	})
}
