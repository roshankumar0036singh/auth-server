package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/middleware"
	"github.com/stretchr/testify/assert"
)

func setupRequestIDTest() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.RequestIDMiddleware())
	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, middleware.RequestIDFromContext(c.Request.Context()))
	})
	return r
}

func TestRequestIDMiddlewarePropagatesIncomingID(t *testing.T) {
	r := setupRequestIDTest()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("X-Request-ID", "client-request-abc-123")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "client-request-abc-123", rec.Header().Get("X-Request-ID"))
	assert.Equal(t, "client-request-abc-123", rec.Body.String())
}

func TestRequestIDMiddlewareGeneratesWhenMissing(t *testing.T) {
	r := setupRequestIDTest()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	generated := rec.Header().Get("X-Request-ID")
	assert.Len(t, generated, 32)
	assert.Regexp(t, `^[0-9a-f]{32}$`, generated)
	assert.Equal(t, generated, rec.Body.String())
}

func TestRequestIDMiddlewareRejectsUnsafeIncomingID(t *testing.T) {
	r := setupRequestIDTest()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("X-Request-ID", "../evil\r\nX-Injected: 1")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	received := rec.Header().Get("X-Request-ID")
	assert.NotEqual(t, "../evil\r\nX-Injected: 1", received)
	assert.Regexp(t, `^[0-9a-f]{32}$`, received)
}

func TestRequestIDMiddlewareRejectsOversizedIncomingID(t *testing.T) {
	r := setupRequestIDTest()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("X-Request-ID", string(make([]byte, 100))+"a")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Len(t, rec.Header().Get("X-Request-ID"), 32)
}

func TestValidRequestID(t *testing.T) {
	assert.True(t, middleware.ValidRequestID("abc-123_DEF.456"))
	assert.False(t, middleware.ValidRequestID(""))
	assert.False(t, middleware.ValidRequestID("  "))
	assert.False(t, middleware.ValidRequestID("a b"))
	assert.False(t, middleware.ValidRequestID("a;b"))
	assert.False(t, middleware.ValidRequestID("a\nb"))
	assert.False(t, middleware.ValidRequestID(string(make([]byte, 65))))
}

func TestNewRequestIDIsBounded(t *testing.T) {
	for i := 0; i < 100; i++ {
		id := middleware.NewRequestID()
		assert.Len(t, id, 32)
		assert.Regexp(t, `^[0-9a-f]{32}$`, id)
	}
}

func TestRequestIDFromContextMissing(t *testing.T) {
	assert.Equal(t, "", middleware.RequestIDFromContext(nil))
	assert.Equal(t, "", middleware.RequestIDFromContext(t.Context()))
}
