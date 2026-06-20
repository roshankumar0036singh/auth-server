package config

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"os"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
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
	PrivateKey         *rsa.PrivateKey
	PublicKey          *rsa.PublicKey
	KeyID              string
	AccessExpiry       string
	RefreshExpiry      string
	RefreshGracePeriod string
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

	LoginRateLimitMax    int
	LoginRateLimitWindow int

	RegisterRateLimitMax    int
	RegisterRateLimitWindow int

	ForgotRateLimitMax    int
	ForgotRateLimitWindow int
}

func mustAtoi(key string, defaultValue int) int {
	v, err := strconv.Atoi(getEnv(key, strconv.Itoa(defaultValue)))
	if err != nil || v <= 0 {
		return defaultValue
	}
	return v
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

	loginRateLimitMax := mustAtoi("LOGIN_RATE_LIMIT_MAX", 5)
	loginRateLimitWindow := mustAtoi("LOGIN_RATE_LIMIT_WINDOW", 900000)

	registerRateLimitMax := mustAtoi("REGISTER_RATE_LIMIT_MAX", 3)
	registerRateLimitWindow := mustAtoi("REGISTER_RATE_LIMIT_WINDOW", 3600000)

	forgotRateLimitMax := mustAtoi("FORGOT_RATE_LIMIT_MAX", 3)
	forgotRateLimitWindow := mustAtoi("FORGOT_RATE_LIMIT_WINDOW", 3600000)

	appURL := getEnv("APP_URL", "http://localhost:3000")

	privKey, pubKey := loadRSAKeys()
	keyID := getEnv("JWT_KEY_ID", "default-key-1")

	encKey := getEnv("ENCRYPTION_KEY", "")
	if encKey == "" || encKey == "0123456789abcdef0123456789abcdef" {
		log.Fatal("ENCRYPTION_KEY must be set to a unique secret")
	}

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
			PrivateKey:         privKey,
			PublicKey:          pubKey,
			KeyID:              keyID,
			AccessExpiry:       getEnv("JWT_ACCESS_EXPIRY", "15m"),
			RefreshExpiry:      getEnv("JWT_REFRESH_EXPIRY", "168h"),
			RefreshGracePeriod: getEnv("JWT_REFRESH_GRACE_PERIOD", "10s"),
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

			LoginRateLimitMax:    loginRateLimitMax,
			LoginRateLimitWindow: loginRateLimitWindow,

			RegisterRateLimitMax:    registerRateLimitMax,
			RegisterRateLimitWindow: registerRateLimitWindow,

			ForgotRateLimitMax:    forgotRateLimitMax,
			ForgotRateLimitWindow: forgotRateLimitWindow,
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func loadRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	privPath := getEnv("JWT_PRIVATE_KEY_PATH", "private.pem")
	pubPath := getEnv("JWT_PUBLIC_KEY_PATH", "public.pem")

	privBytes, err1 := os.ReadFile(privPath)
	pubBytes, err2 := os.ReadFile(pubPath)

	if os.IsNotExist(err1) || os.IsNotExist(err2) {
		log.Println("RSA keys not found at provided paths, generating temporary in-memory keys for development/testing...")
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Failed to generate temp RSA key: %v", err)
		}
		return privKey, &privKey.PublicKey
	} else if err1 != nil || err2 != nil {
		log.Fatalf("Failed to read RSA keys: privErr=%v, pubErr=%v", err1, err2)
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privBytes)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubBytes)
	if err != nil {
		log.Fatalf("Failed to parse public key: %v", err)
	}

	return privKey, pubKey
}
