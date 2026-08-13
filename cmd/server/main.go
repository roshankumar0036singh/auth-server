package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gorm.io/gorm"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/metrics"
	"github.com/roshankumar0036singh/auth-server/internal/middleware"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/routes"
)

// @title Auth Server API
// @version 1.0
// @description Production-ready Authentication Server in Go
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.email support@authserver.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /
// @schemes http https

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize database
	db := config.InitDatabase(cfg)

	// Pre-migration backfill for refresh_tokens.family_id
	// Add column as nullable first to allow backfill
	if err := db.Exec("ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS family_id uuid").Error; err != nil {
		log.Printf("Warning: Could not add family_id column (may already exist): %v", err)
	}
	// Backfill existing tokens using their own ID as the family ID
	if err := db.Exec("UPDATE refresh_tokens SET family_id = id WHERE family_id IS NULL").Error; err != nil {
		log.Fatal("Failed to backfill family_id for existing refresh tokens:", err)
	}

	// Auto-migrate database models
	err := config.AutoMigrate(db, &models.User{},
		&models.RefreshToken{},
		&models.VerificationToken{},
		&models.PasswordResetToken{},
		&models.AuditLog{},
		// OAuth 2.0 Provider models
		&models.OAuthClient{},
		&models.AuthorizationCode{},
		&models.OAuthAccessToken{},
		&models.UserConsent{},
	)
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// Initialize Redis
	redisClient := config.InitRedis(cfg)

	// Setup Gin
	if cfg.App.Env == "production" {

		gin.SetMode(gin.ReleaseMode)
	}

	tokenRepo := repository.NewTokenRepository(db)

	metrics.Register(tokenRepo)

	// Background token cleanup (issue #72): purges expired refresh, verification,
	// password-reset and OAuth tokens on a schedule. Interval configurable via
	// TOKEN_CLEANUP_INTERVAL (default 1h).
	cleanupInterval := 1 * time.Hour
	if v := os.Getenv("TOKEN_CLEANUP_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cleanupInterval = d
		}
	}
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	defer cleanupCancel()
	startTokenCleanup(db, cleanupInterval, cleanupCtx)

	router := gin.Default()

	router.Use(middleware.PrometheusMiddleware())

	// Prometheus metrics endpoint

	metricsAddr := os.Getenv("METRICS_ADDR")
	if metricsAddr == "" {
		metricsAddr = "127.0.0.1:9090"
	}

	metricsServer := &http.Server{
		Addr:              metricsAddr,
		Handler:           promhttp.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {

		log.Printf("📊 Prometheus metrics exposed on http://%s/metrics", metricsAddr)

		if err := metricsServer.ListenAndServe(); err != nil &&
			err != http.ErrServerClosed {
			log.Printf("Metrics server error: %v", err)
		}
	}()

	// Load HTML templates for OAuth consent
	router.LoadHTMLGlob("templates/*")

	// Setup routes
	routes.SetupRoutes(router, db, redisClient, cfg)

	// Configure HTTP server
	addr := fmt.Sprintf(":%d", cfg.App.Port)
	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	// Start server in goroutine
	go func() {
		log.Printf(" Server starting on %s", addr)
		log.Printf(" Environment: %s", cfg.App.Env)

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server:", err)
		}
	}()

	// Start self-pinger to keep the server active
	go func() {
		pingURL := os.Getenv("PING_URL")
		if pingURL == "" {
			pingURL = fmt.Sprintf("http://localhost:%d/health", cfg.App.Port)
		}

		// Ping every 10 minutes (Heroku/Render typically sleep after 15-30m)
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			resp, err := http.Get(pingURL)
			if err != nil {
				log.Printf("Self-ping failed: %v", err)
			} else {
				resp.Body.Close()
				log.Printf("Self-ping successful: %d", resp.StatusCode)
			}
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	// Accept SIGINT (Ctrl+C) and SIGTERM (docker stop)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("🛑 Shutting down server...")

	// Graceful shutdown with 5 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	// Shutdown metrics server
	metricsCtx, metricsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer metricsCancel()
	if err := metricsServer.Shutdown(metricsCtx); err != nil {
		log.Printf("Metrics server forced to shutdown: %v", err)
	}

	// Close database connection
	sqlDB, err := db.DB()
	if err == nil {
		if err := sqlDB.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		} else {
			log.Println(" Database connection closed")
		}
	}

	// Close Redis connection
	if err := redisClient.Close(); err != nil {
		log.Printf("Error closing Redis: %v", err)
	} else {
		log.Println(" Redis connection closed")
	}

	log.Println(" Server exited gracefully")
}

// startTokenCleanup runs periodic purges of expired tokens. A first pass runs
// shortly after startup, then every interval until ctx is cancelled. Failures
// are logged and retried on the next tick.
func startTokenCleanup(db *gorm.DB, interval time.Duration, ctx context.Context) {
	run := func() {
		jobs := []struct {
			name string
			fn   func() error
		}{
			{"refresh_tokens", func() error {
				_, err := repository.NewTokenRepository(db).DeleteExpiredTokens()
				return err
			}},
			{"verification_tokens", repository.NewVerificationRepository(db).DeleteExpired},
			{"password_reset_tokens", repository.NewPasswordResetRepository(db).DeleteExpired},
			{"oauth_tokens", repository.NewOAuthTokenRepository(db).DeleteExpired},
		}
		for _, job := range jobs {
			if err := job.fn(); err != nil {
				log.Printf("⚠️ token cleanup failed for %s: %v", job.name, err)
				continue
			}
			log.Printf("🧹 token cleanup: purged expired %s", job.name)
		}
	}

	go func() {
		// Small delay so cleanup never competes with startup queries.
		time.Sleep(15 * time.Second)
		run()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				run()
			case <-ctx.Done():
				log.Println("🧹 token cleanup job stopped")
				return
			}
		}
	}()
}
