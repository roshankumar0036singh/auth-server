package middleware_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/middleware"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/stretchr/testify/assert"
)

func setupRateLimitTest(t *testing.T) (*gin.Engine, *service.CacheService, *miniredis.Miniredis, *config.Config) {
	gin.SetMode(gin.TestMode)
	mr, err := miniredis.Run()
	assert.NoError(t, err)

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimitMax:            2,
			RateLimitWindow:         60000, // 60 seconds in ms
			LoginRateLimitMax:       2,
			LoginRateLimitWindow:    60000,
			ForgotRateLimitMax:      1,
			ForgotRateLimitWindow:   60000,
		},
	}
	cacheService := service.NewCacheService(rdb)
	router := gin.New()

	return router, cacheService, mr, cfg
}

func TestRateLimitMiddleware_GeneralEndpoint(t *testing.T) {
	router, cacheService, mr, cfg := setupRateLimitTest(t)
	defer mr.Close()

	router.Use(middleware.RateLimitMiddleware(cacheService, cfg))
	router.GET("/api/general", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// First request: Allowed
	req1 := httptest.NewRequest("GET", "/api/general", nil)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Second request: Allowed
	req2 := httptest.NewRequest("GET", "/api/general", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)

	// Third request: Rejected (limit is 2)
	req3 := httptest.NewRequest("GET", "/api/general", nil)
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusTooManyRequests, w3.Code)
}

func TestRateLimitMiddleware_LoginEndpoint(t *testing.T) {
	router, cacheService, mr, cfg := setupRateLimitTest(t)
	defer mr.Close()

	router.Use(middleware.RateLimitMiddleware(cacheService, cfg))
	router.POST("/api/auth/login", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "login ok"})
	})

	req1 := httptest.NewRequest("POST", "/api/auth/login", nil)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	req2 := httptest.NewRequest("POST", "/api/auth/login", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)

	req3 := httptest.NewRequest("POST", "/api/auth/login", nil)
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusTooManyRequests, w3.Code)
}

func TestRateLimitMiddleware_ForgotPasswordEndpoint(t *testing.T) {
	router, cacheService, mr, cfg := setupRateLimitTest(t)
	defer mr.Close()

	router.Use(middleware.RateLimitMiddleware(cacheService, cfg))
	router.POST("/api/auth/forgot-password", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "forgot ok"})
	})

	bodyPayload := dto.ForgotPasswordRequest{Email: "user@example.com"}
	bodyBytes, _ := json.Marshal(bodyPayload)

	req1 := httptest.NewRequest("POST", "/api/auth/forgot-password", bytes.NewReader(bodyBytes))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Second request should exceed limit of 1
	req2 := httptest.NewRequest("POST", "/api/auth/forgot-password", bytes.NewReader(bodyBytes))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code)
}
