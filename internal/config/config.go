package config

import (
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	App      AppConfig
	Database DatabaseConfig
	Redis    RedisConfig
	JWT      JWTConfig
	OAuth    OAuthConfig
	Email    EmailConfig
	Security SecurityConfig
}

type AppConfig struct {
	Port int
	Env  string
	URL  string
}

type DatabaseConfig struct {
	URL     string
	PoolMin int
	PoolMax int
}

type RedisConfig struct {
	URL string
	TTL int
}

type JWTConfig struct {
	AccessSecret  string
	RefreshSecret string
	AccessExpiry  string
	RefreshExpiry string
}

type OAuthConfig struct {
	Google GoogleOAuthConfig
	GitHub GitHubOAuthConfig
}

type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
}

type GitHubOAuthConfig struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
}

type SecurityConfig struct {
	BcryptRounds           int
	RateLimitWindow        int
	RateLimitMax           int
	AccountLockMaxAttempts int
	AccountLockDuration    int // in minutes
	EncryptionKey          string
	AllowedOrigins         []string // Added to store validated, deduplicated origins
}

func LoadConfig() *Config {
	// Load .env file (ignore error if file doesn't exist)
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	port, _ := strconv.Atoi(getEnv("PORT", "3000"))
	poolMin, _ := strconv.Atoi(getEnv("DB_POOL_MIN", "2"))
	poolMax, _ := strconv.Atoi(getEnv("DB_POOL_MAX", "10"))
	redisTTL, _ := strconv.Atoi(getEnv("REDIS_TTL", "3600"))
	bcryptRounds, _ := strconv.Atoi(getEnv("BCRYPT_ROUNDS", "12"))
	rateLimitWindow, _ := strconv.Atoi(getEnv("RATE_LIMIT_WINDOW", "900000"))
	rateLimitMax, _ := strconv.Atoi(getEnv("RATE_LIMIT_MAX", "5"))
	accountLockMax, _ := strconv.Atoi(getEnv("ACCOUNT_LOCK_MAX_ATTEMPTS", "5"))
	accountLockDuration, _ := strconv.Atoi(getEnv("ACCOUNT_LOCK_DURATION", "30")) // Minutes

	appURL := getEnv("APP_URL", "http://localhost:3000")

	encKey := getEnv("ENCRYPTION_KEY", "")
	if encKey == "" || encKey == "0123456789abcdef0123456789abcdef" {
		log.Fatal("ENCRYPTION_KEY must be set to a unique secret")
	}

	// 1. Fetch, Split, Trim, and Validate CORS allowed origins
	rawOrigins := getEnv("CORS_ALLOWED_ORIGINS", "")
	var originList []string
	originMap := make(map[string]bool)

	if rawOrigins != "" {
		for _, rawOrigin := range strings.Split(rawOrigins, ",") {
			trimmed := strings.TrimSpace(rawOrigin)
			if trimmed == "" {
				continue
			}

			// Validate if it is a structurally valid URL
			parsedURL, err := url.ParseRequestURI(trimmed)
			if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
				log.Printf("Warning: Skipping invalid CORS origin configuration: %s", trimmed)
				continue
			}

			// Add to unique map tracking to avoid duplicates
			if !originMap[trimmed] {
				originMap[trimmed] = true
				originList = append(originList, trimmed)
			}
		}
	}

	// 2. Safely append appURL if it doesn't already exist to avoid duplicate issues
	if !originMap[appURL] {
		originMap[appURL] = true
		originList = append(originList, appURL)
	}

	// 3. Log out what was successfully configured
	log.Printf("Configured CORS Allowed Origins: %v", originList)

	return &Config{
		App: AppConfig{
			Port: port,
			Env:  getEnv("APP_ENV", "development"),
			URL:  appURL,
		},
		Database: DatabaseConfig{
			URL:     getEnv("DATABASE_URL", ""),
			PoolMin: poolMin,
			PoolMax: poolMax,
		},
		Redis: RedisConfig{
			URL: getEnv("REDIS_URL", ""),
			TTL: redisTTL,
		},
		JWT: JWTConfig{
			AccessSecret:  getEnv("JWT_SECRET", ""),
			RefreshSecret: getEnv("JWT_REFRESH_SECRET", ""),
			AccessExpiry:  getEnv("JWT_ACCESS_EXPIRY", "15m"),
			RefreshExpiry: getEnv("JWT_REFRESH_EXPIRY", "168h"),
		},
		OAuth: OAuthConfig{
			Google: GoogleOAuthConfig{
				ClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
				ClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
				CallbackURL:  appURL + "/api/oauth/google/callback",
			},
			GitHub: GitHubOAuthConfig{
				ClientID:     getEnv("GITHUB_CLIENT_ID", ""),
				ClientSecret: getEnv("GITHUB_CLIENT_SECRET", ""),
				CallbackURL:  appURL + "/api/oauth/github/callback",
			},
		},
		Email: LoadEmailConfig(),
		Security: SecurityConfig{
			BcryptRounds:           bcryptRounds,
			RateLimitWindow:        rateLimitWindow,
			RateLimitMax:           rateLimitMax,
			AccountLockMaxAttempts: accountLockMax,
			AccountLockDuration:    accountLockDuration,
			EncryptionKey:          encKey,
			AllowedOrigins:         originList, // Pass the processed slice cleanly here
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
