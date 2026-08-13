package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/roshankumar0036singh/auth-server/internal/service"
)

func TestJWKSEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// no RSA configured -> empty key set, still 200 with cache headers
	r.GET("/.well-known/jwks.json", handler.NewWellKnownHandler(service.NewJWKSService(&config.Config{})).JWKS)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "public, max-age=3600", w.Header().Get("Cache-Control"))

	var body struct {
		Keys []map[string]string `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Empty(t, body.Keys)
}
