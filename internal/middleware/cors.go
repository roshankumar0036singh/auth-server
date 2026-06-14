package middleware

import (
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/config"
)

// CORSMiddleware configures CORS for the application
func CORSMiddleware(cfg *config.Config) gin.HandlerFunc {
	var allowOrigins []string

	// Check for environment variable
	if envOrigins := os.Getenv("CORS_ALLOWED_ORIGINS"); envOrigins != "" {
		// Split comma-separated values
		origins := strings.Split(envOrigins, ",")
		for _, origin := range origins {
			trimmed := strings.TrimSpace(origin)
			if trimmed != "" {
				allowOrigins = append(allowOrigins, trimmed)
			}
		}
	}

	// Fallback to defaults if env variable is empty or parsed to nothing
	if len(allowOrigins) == 0 {
		allowOrigins = []string{"http://localhost:3000", "http://localhost:5173"}
	}

	// Always append the configured App URL if present
	if cfg != nil && cfg.App.URL != "" {
		allowOrigins = append(allowOrigins, cfg.App.URL)
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