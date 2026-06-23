package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSecurityMiddleware(t *testing.T) {
	// Set Gin to Test Mode
	gin.SetMode(gin.TestMode)

	// 1. Setup a minimal Gin router instance and apply the middleware
	r := gin.New()
	r.Use(SecurityMiddleware())

	// Add a dummy endpoint to process the request execution
	r.GET("/test-security", func(c *gin.Context) {
		c.String(http.StatusOK, "secure content")
	})

	// 2. Draft an HTTP request to hit the endpoint
	// Note: The 'secure' package often expects an HTTPS request or an explicit configuration 
	// to trigger HSTS (Strict-Transport-Security). We'll use an https:// URL context here.
	req, _ := http.NewRequest("GET", "https://localhost/test-security", nil)
	w := httptest.NewRecorder()

	// 3. Perform the request execution
	r.ServeHTTP(w, req)

	// 4. Verify HTTP Status code
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}

	// 5. Define assertions for expected security headers
	expectedHeaders := map[string]string{
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"X-XSS-Protection":          "1; mode=block",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Strict-Transport-Security": "max-age=315360000; includeSubdomains",
	}

	for header, expectedVal := range expectedHeaders {
		actualVal := w.Header().Get(header)
		if actualVal != expectedVal {
			t.Errorf("Expected header %q to be %q, got %q", header, expectedVal, actualVal)
		}
	}

	// 6. Separately check Content-Security-Policy prefix to avoid massive string match fragile failures
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Errorf("Expected Content-Security-Policy header to be present, but got empty string")
	}
}