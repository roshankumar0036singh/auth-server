package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/roshankumar0036singh/auth-server/internal/middleware"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
)

func SetupRoutes(router *gin.Engine, db *gorm.DB, redisClient *redis.Client, cfg *config.Config) {
	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(db)
	verificationRepo := repository.NewVerificationRepository(db)
	passwordResetRepo := repository.NewPasswordResetRepository(db)
	auditRepo := repository.NewAuditRepository(db)

	// Initialize services
	tokenService := service.NewTokenService(cfg)
	cacheService := service.NewCacheService(redisClient)
	emailService := service.NewEmailService(cfg)
	auditService := service.NewAuditService(auditRepo)
	oauthService := service.NewOAuthService(cfg)
	mfaService := service.NewMFAService(cfg)
	
	authService := service.NewAuthService(
		userRepo,
		tokenRepo,
		verificationRepo,
		passwordResetRepo,
		tokenService,
		cacheService,
		emailService,
		auditService,
		mfaService,
		cfg,
	)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authService, oauthService)
	adminHandler := handler.NewAdminHandler(authService)

	// Apply global middleware
	router.Use(middleware.CORSMiddleware())
	router.Use(middleware.SecurityMiddleware()) // Security headers
	
	// Rate limiting (global)
	// We apply it here to all routes. Alternatively, apply to specific groups.
	// For now, global protection is safer.
	router.Use(middleware.RateLimitMiddleware(cacheService, cfg))

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"message": "Auth server is running",
		})
	})

	// API routes
	api := router.Group("/api")
	{
		// Auth routes (public)
		auth := api.Group("/auth")
		{
			// Public endpoints
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/login/mfa", authHandler.LoginMFA) // MFA Login
			auth.POST("/refresh", authHandler.RefreshToken)
			auth.GET("/verify-email", authHandler.VerifyEmail)
			auth.POST("/resend-verification", authHandler.ResendVerification)
			auth.POST("/forgot-password", authHandler.ForgotPassword)
			auth.POST("/reset-password", authHandler.ResetPassword)
			
			// OAuth Routes
			auth.GET("/google/login", authHandler.GoogleLogin)
			auth.GET("/google/callback", authHandler.GoogleCallback)
			auth.GET("/github/login", authHandler.GitHubLogin)
			auth.GET("/github/callback", authHandler.GitHubCallback)

			// Protected routes
			protected := auth.Group("")
			protected.Use(middleware.AuthMiddleware(tokenService))
			{
				protected.GET("/me", authHandler.GetMe)
				protected.PUT("/profile", authHandler.UpdateProfile)
				protected.POST("/logout", authHandler.Logout)
				protected.POST("/logout-all", authHandler.LogoutAll)
				protected.GET("/sessions", authHandler.GetSessions)
				protected.DELETE("/sessions/:sessionId", authHandler.RevokeSession)
				protected.POST("/password", authHandler.ChangePassword)
				protected.DELETE("/me", authHandler.DeleteAccount)
				protected.GET("/audit-logs", authHandler.GetAuditLogs)
				
				// MFA Routes (Protected)
				protected.POST("/mfa/enable", authHandler.EnableMFA)
				protected.POST("/mfa/verify", authHandler.VerifyMFA)
			}
		}

		// Admin routes (Protected + RBAC)
		admin := api.Group("/admin")
		admin.Use(middleware.AuthMiddleware(tokenService))
		admin.Use(middleware.RequireRole("admin"))
		{
			admin.GET("/users", adminHandler.GetUsers)
			admin.POST("/users/:id/lock", adminHandler.LockUser)
			admin.POST("/users/:id/unlock", adminHandler.UnlockUser)
			admin.DELETE("/users/:id", adminHandler.DeleteUser)
		}
	}
}
