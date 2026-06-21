package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/stretchr/testify/assert"
)

func TestWebAuthnHandler_BeginRegistration_NoSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Since we are not providing a full mock AuthService and WebAuthnService,
	// we just test that the handler enforces authentication (via middleware or user presence).
	// In the actual code, BeginRegistration expects a user context.
	router := gin.New()
	
	// Stub handler initialization with nil services just to test structure or basics
	h := handler.NewWebAuthnHandler(nil, nil)

	router.GET("/api/auth/webauthn/register/begin", func(c *gin.Context) {
		// To simulate the required auth middleware missing
		h.BeginRegistration(c)
	})

	req, _ := http.NewRequest(http.MethodGet, "/api/auth/webauthn/register/begin", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should fail because user is not in context
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
