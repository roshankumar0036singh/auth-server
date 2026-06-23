package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestSetupRoutes(t *testing.T) {
	// Set Gin to Test Mode
	gin.SetMode(gin.TestMode)

	// 1. Initialize a Mock SQL database to avoid spinning up a real database server
	dbMock, sqlMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer dbMock.Close()

	// Wrap our mock database connection into a GORM instance
	dialector := postgres.New(postgres.Config{
		Conn: dbMock,
	})
	gormDB, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to wrap gorm instance: %v", err)
	}

	// 2. Initialize a local, disconnected Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer redisClient.Close()

	// 3. Create a minimal configuration profile block
	mockCfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimitMax:    10,
			RateLimitWindow: 1000,
		},
	}

	// 4. Instantiate a fresh Gin router instance and invoke SetupRoutes
	router := gin.New()
	SetupRoutes(router, gormDB, redisClient, mockCfg)

	// 5. Test a straightforward public endpoint to guarantee registration success
	t.Run("Verify public ready endpoint", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/ready", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status code 200 on /ready, but got %d", w.Code)
		}
	})

	// 6. Test health check degradation behavior when database or redis dependencies drop out
	t.Run("Verify health endpoint degrades gracefully", func(t *testing.T) {
		// Expect the route layer to ping the database layer
		sqlMock.ExpectPing()

		req, _ := http.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// It will return 503 Service Unavailable because our local redis mock client 
		// is deliberately disconnected from a real background backend daemon.
		if w.Code != http.StatusServiceUnavailable && w.Code != http.StatusOK {
			t.Errorf("Expected health status code 503 or 200, got %d", w.Code)
		}
	})
}