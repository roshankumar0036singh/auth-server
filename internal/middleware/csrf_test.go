package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupCSRFRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CSRFMiddleware())
	r.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	return r
}

func TestCSRFMiddleware_SafeMethodsAllowed(t *testing.T) {
	r := setupCSRFRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRFMiddleware_NoSessionCookieSkipsBearerFlow(t *testing.T) {
	r := setupCSRFRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/test", nil)
	// No auth_token cookie — Bearer token (or unauthenticated) flow, should pass
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRFMiddleware_SessionCookiePresentButNoCSRFCookie(t *testing.T) {
	// Regression test: a stale/expired csrf_token cookie must not let a
	// cookie-authenticated request bypass CSRF validation just because the
	// CSRF cookie itself is gone. auth_token (7d) outlives csrf_token (24h).
	r := setupCSRFRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/test", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: "sometoken"})
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRFMiddleware_MissingHeader(t *testing.T) {
	r := setupCSRFRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/test", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: "sometoken"})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "sometoken"})
	// Cookies present but no header
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRFMiddleware_InvalidToken(t *testing.T) {
	r := setupCSRFRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/test", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: "sometoken"})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "correcttoken"})
	req.Header.Set("X-CSRF-Token", "wrongtoken")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRFMiddleware_ValidToken(t *testing.T) {
	r := setupCSRFRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/test", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: "sometoken"})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "validtoken123"})
	req.Header.Set("X-CSRF-Token", "validtoken123")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGenerateCSRFToken(t *testing.T) {
	token1, err1 := generateCSRFToken()
	token2, err2 := generateCSRFToken()
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.Len(t, token1, 64) // 32 bytes = 64 hex chars
	assert.NotEqual(t, token1, token2)
}
