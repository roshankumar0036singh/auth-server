package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/config"
)

func TestCORSMiddleware(t *testing.T) {
	// Set Gin to Test Mode so it doesn't log unneeded output during execution
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		cfg            *config.Config
		requestOrigin  string
		expectedOrigin string
	}{
		{
			name:           "Should allow default origin localhost:3000 when config is nil",
			cfg:            nil,
			requestOrigin:  "http://localhost:3000",
			expectedOrigin: "http://localhost:3000",
		},
		{
			name:           "Should allow default origin localhost:5173 when config is nil",
			cfg:            nil,
			requestOrigin:  "http://localhost:5173",
			expectedOrigin: "http://localhost:5173",
		},
		{
			name: "Should append and allow custom App URL from config",
			cfg: &config.Config{
				App: config.AppConfig{
					URL: "https://myproductionapp.com",
				},
			},
			requestOrigin:  "https://myproductionapp.com",
			expectedOrigin: "https://myproductionapp.com",
		},
		{
			name:           "Should block untrusted origin",
			cfg:            nil,
			requestOrigin:  "https://untrusted-hacker-site.com",
			expectedOrigin: "", // Should not return an Access-Control-Allow-Origin header
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 1. Setup a minimal Gin router instance
			r := gin.New()
			r.Use(CORSMiddleware(tt.cfg))

			// Add a simple test endpoint that our request hits
			r.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "success")
			})

			// 2. Draft an HTTP request with the specific Origin header
			req, _ := http.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.requestOrigin)

			// 3. Create a ResponseRecorder to capture the server's output response
			w := httptest.NewRecorder()

			// 4. Perform the request execution
			r.ServeHTTP(w, req)

			// 5. Assertions
			actualOrigin := w.Header().Get("Access-Control-Allow-Origin")
			if actualOrigin != tt.expectedOrigin {
				t.Errorf("Expected Access-Control-Allow-Origin to be %q, got %q", tt.expectedOrigin, actualOrigin)
			}
		})
	}
}