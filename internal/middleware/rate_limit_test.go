package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/config"
)

func TestRateLimitMiddleware_AbortsOnMissingKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockCfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimitMax:    100,
			RateLimitWindow: 60000,
		},
	}

	// Passing a completely nil CacheService pointer will let us test the early key-binding failure branch.
	// We hit the forgot-password path with an invalid payload string to trigger an early validation failure.
	r := gin.New()
	r.POST("/api/auth/forgot-password", RateLimitMiddleware(nil, mockCfg), func(c *gin.Context) {
		c.String(http.StatusOK, "passed")
	})

	req, _ := http.NewRequest("POST", "/api/auth/forgot-password", bytes.NewBufferString("invalid-json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Body.String() == "passed" {
		t.Errorf("Expected request to abort early, but it successfully executed the endpoint handler")
	}
}

func TestGetLimits(t *testing.T) {
	mockCfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimitMax:            10,
			RateLimitWindow:         1000,
			LoginRateLimitMax:       1,
			LoginRateLimitWindow:    2000,
			RegisterRateLimitMax:    2,
			RegisterRateLimitWindow: 3000,
			ForgotRateLimitMax:      3,
			ForgotRateLimitWindow:   4000,
		},
	}

	tests := []struct {
		path           string
		expectedMax    int
		expectedWindow int
	}{
		{"/api/auth/login", 1, 2000},
		{"/api/auth/google/login", 1, 2000},
		{"/api/auth/github/login", 1, 2000},
		{"/api/auth/register", 2, 3000},
		{"/api/auth/forgot-password", 3, 4000},
		{"/api/auth/other-random-route", 10, 1000},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			max, window := getLimits(mockCfg, tt.path)
			if max != tt.expectedMax {
				t.Errorf("For path %s expected max %d, got %d", tt.path, tt.expectedMax, max)
			}
			if int(window.Milliseconds()) != tt.expectedWindow {
				t.Errorf("For path %s expected window %dms, got %v", tt.path, tt.expectedWindow, window)
			}
		})
	}
}