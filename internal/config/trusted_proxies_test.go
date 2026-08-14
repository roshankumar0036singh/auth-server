package config

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestApplyTrustedProxiesDefaultsToRemoteAddrOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	cfg := &Config{Security: SecurityConfig{}}

	got := ApplyTrustedProxies(router, cfg)
	assert.Nil(t, got)
	assert.Equal(t, "", router.TrustedPlatform)

	// A spoofed X-Forwarded-For must NOT override the remote address.
	router.GET("/ip", func(c *gin.Context) { c.String(200, c.ClientIP()) })
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	req.Header.Set("X-Forwarded-For", "10.0.0.99")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, "1.2.3.4", rec.Body.String())
}

func TestApplyTrustedProxiesTrustsCIDR(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	cfg := &Config{Security: SecurityConfig{TrustedProxies: []string{"10.0.0.0/8"}}}

	got := ApplyTrustedProxies(router, cfg)
	assert.Equal(t, []string{"10.0.0.0/8"}, got)

	// The trusted LB (10.0.0.0/8) is the direct peer; XFF carries the real client.
	router.GET("/ip", func(c *gin.Context) { c.String(200, c.ClientIP()) })
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = "10.0.0.99:5555"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, "1.2.3.4", rec.Body.String())
}

func TestApplyTrustedProxiesInvalidCIDRFallsBack(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	cfg := &Config{Security: SecurityConfig{TrustedProxies: []string{"not-a-cidr"}}}

	got := ApplyTrustedProxies(router, cfg)
	assert.Nil(t, got)

	router.GET("/ip", func(c *gin.Context) { c.String(200, c.ClientIP()) })
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	req.Header.Set("X-Forwarded-For", "10.0.0.99")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, "1.2.3.4", rec.Body.String())
}

func TestIsTrusted(t *testing.T) {
	trusted := []string{"10.0.0.0/8", "203.0.113.5"}
	assert.True(t, IsTrusted("10.1.2.3", trusted))
	assert.True(t, IsTrusted("203.0.113.5", trusted))
	assert.False(t, IsTrusted("8.8.8.8", trusted))
	assert.False(t, IsTrusted("nope", trusted))
}
