package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestGetAuthToken isolates and explicitly exercises the token extraction logic branches
func TestGetAuthToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		setupHeaders  func(req *http.Request)
		setupCookies  func(req *http.Request)
		expectedToken string
	}{
		{
			name: "Should extract token successfully from valid Authorization Bearer header",
			setupHeaders: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer valid-header-jwt-string")
			},
			setupCookies:  func(req *http.Request) {},
			expectedToken: "valid-header-jwt-string",
		},
		{
			name: "Should ignore malformed or non-Bearer Authorization headers",
			setupHeaders: func(req *http.Request) {
				req.Header.Set("Authorization", "Basic credentials-string-here")
			},
			setupCookies:  func(req *http.Request) {},
			expectedToken: "",
		},
		{
			name:         "Should fallback and extract token from fallback browser cookie successfully",
			setupHeaders: func(req *http.Request) {},
			setupCookies: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "auth_token", Value: "valid-cookie-jwt-string"})
			},
			expectedToken: "valid-cookie-jwt-string",
		},
		{
			name:          "Should return empty string if no authentication vector is provided",
			setupHeaders:  func(req *http.Request) {},
			setupCookies:  func(req *http.Request) {},
			expectedToken: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			req, _ := http.NewRequest("GET", "/test", nil)
			
			tt.setupHeaders(req)
			tt.setupCookies(req)
			c.Request = req

			token := getAuthToken(c)
			if token != tt.expectedToken {
				t.Errorf("Expected token string %q, got %q", tt.expectedToken, token)
			}
		})
	}
}

// TestStrictAuthMiddlewareMissingToken tests the early-abort branch of the strict AuthMiddleware
func TestStrictAuthMiddlewareMissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	// Pass nil for token service since it should abort early before ever calling it
	r.GET("/protected", AuthMiddleware(nil), func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	req, _ := http.NewRequest("GET", "/protected", nil) // No headers or cookies
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code 401 Unauthorized, got %d", w.Code)
	}
}

// TestOptionalAuthMiddlewareMissingToken checks that optional auth proceeds cleanly when no token is sent
func TestOptionalAuthMiddlewareMissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/optional", OptionalAuthMiddleware(nil), func(c *gin.Context) {
		c.String(http.StatusOK, "public-content")
	})

	req, _ := http.NewRequest("GET", "/optional", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code 200 OK for missing optional token, got %d", w.Code)
	}
}