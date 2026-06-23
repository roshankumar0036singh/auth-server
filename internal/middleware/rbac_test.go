package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequireRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		allowedRoles   []string
		setContext     func(c *gin.Context)
		expectedStatus int
	}{
		{
			name:         "Should return 401 if role does not exist in context",
			allowedRoles: []string{"admin"},
			setContext: func(c *gin.Context) {
				// Do nothing to simulate a completely missing role key
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:         "Should return 500 if role value in context is not a string",
			allowedRoles: []string{"admin"},
			setContext: func(c *gin.Context) {
				c.Set("role", 12345) // Set as integer to fail type assertion
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:         "Should return 200 if user possesses an explicitly allowed role",
			allowedRoles: []string{"admin", "moderator"},
			setContext: func(c *gin.Context) {
				c.Set("role", "moderator")
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:         "Should return 403 if user role doesn't match allowed criteria",
			allowedRoles: []string{"admin"},
			setContext: func(c *gin.Context) {
				c.Set("role", "user")
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()

			// Inject a structural helper middleware to attach contextual values before checking RBAC rules
			r.GET("/test-rbac", func(c *gin.Context) {
				tt.setContext(c)
				c.Next()
			}, RequireRole(tt.allowedRoles...), func(c *gin.Context) {
				c.String(http.StatusOK, "authorized")
			})

			req, _ := http.NewRequest("GET", "/test-rbac", nil)
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Test %q failed: expected status code %d, but got %d", tt.name, tt.expectedStatus, w.Code)
			}
		})
	}
}