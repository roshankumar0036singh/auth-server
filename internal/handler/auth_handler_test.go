package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/roshankumar0036singh/auth-server/internal/middleware"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func SetupRouter(t *testing.T) (*gin.Engine, *handler.AuthHandler) {
	authService, _, mr := testutils.SetupIntegrationTest(t)
	// mock OAuth service or pass nil if not needed for these tests
	authHandler := handler.NewAuthHandler(authService, nil)

	t.Cleanup(func() { mr.Close() }) // Ensure mr is closed after tests in this Setup config

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())

	// Register routes manually or use a helper that doesn't require full server setup
	// For testing, we just register what we need
	return r, authHandler
}

func TestAuthHandler_Register(t *testing.T) {
	r, h := SetupRouter(t)
	r.POST("/api/auth/register", h.Register)

	reqBody := dto.RegisterRequest{
		Email:     "api_test@example.com",
		Password:  "Password123!",
		FirstName: "API",
		LastName:  "Test",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	// Assert response body contains success
}

func TestAuthHandler_Login(t *testing.T) {
	r, h := SetupRouter(t)
	r.POST("/api/auth/register", h.Register)
	r.POST("/api/auth/login", h.Login)

	// 1. Register first
	regBody := dto.RegisterRequest{
		Email:     "login_api@example.com",
		Password:  "Password123!",
		FirstName: "Login",
		LastName:  "Test",
	}
	b, _ := json.Marshal(regBody)
	regReq, _ := http.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewBuffer(b))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	r.ServeHTTP(regW, regReq)
	assert.Equal(t, http.StatusCreated, regW.Code)

	// 2. Login
	loginBody := dto.LoginRequest{
		Email:    "login_api@example.com",
		Password: "Password123!",
	}
	b2, _ := json.Marshal(loginBody)
	req, _ := http.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBuffer(b2))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Check for token
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp["success"].(bool))
	data := resp["data"].(map[string]interface{})
	assert.NotEmpty(t, data["accessToken"])
}

// TODO: Add tests for Protected Routes using middleware

func TestAuthHandler_GetSessions_CurrentSessionFlag(t *testing.T) {
	authService, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	authHandler := handler.NewAuthHandler(authService, nil)

	cfg := &config.Config{
		JWT: config.JWTConfig{
			AccessSecret:  "secret",
			RefreshSecret: "refresh-secret",
		},
	}
	tokenService := service.NewTokenService(cfg)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.AuthMiddleware(tokenService))

	r.GET("/api/auth/sessions", authHandler.GetSessions)

	// Create user
	regReq := &dto.RegisterRequest{
		Email:     "sessions@example.com",
		Password:  "Password123!",
		FirstName: "Session",
		LastName:  "Test",
	}

	_, err := authService.Register(regReq)
	assert.NoError(t, err)

	// Create a session via login
	loginResp, err := authService.Login(
		&dto.LoginRequest{
			Email:    "sessions@example.com",
			Password: "Password123!",
		},
		"127.0.0.1",
		"test-agent",
	)

	assert.NoError(t, err)

	claims, err := tokenService.ValidateAccessToken(loginResp.AccessToken)
	assert.NoError(t, err)

	expectedSessionID := claims.SessionID

	// Call sessions endpoint using the access token
	req, _ := http.NewRequest(
		http.MethodGet,
		"/api/auth/sessions",
		nil,
	)

	req.Header.Set(
		"Authorization",
		"Bearer "+loginResp.AccessToken,
	)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)

	data := resp["data"].([]interface{})

	foundExpectedSession := false

	for _, item := range data {
		session := item.(map[string]interface{})

		sessionID := session["id"].(string)
		isCurrent := session["isCurrent"].(bool)

		if sessionID == expectedSessionID {
			assert.True(t, isCurrent, "expected session used by request token to be current")
			foundExpectedSession = true
		}
	}

	assert.True(t, foundExpectedSession, "expected session ID not found in response")

}

func TestAuthHandler_GetSessions_NoSessionIDInContext(t *testing.T) {
	authService, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	authHandler := handler.NewAuthHandler(authService, nil)

	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Register user
	regReq := &dto.RegisterRequest{
		Email:     "nosession@example.com",
		Password:  "Password123!",
		FirstName: "No",
		LastName:  "Session",
	}

	user, err := authService.Register(regReq)
	assert.NoError(t, err)

	userID := user.ID

	// Intentionally set only userID, not sessionID
	r.GET("/api/auth/sessions", func(c *gin.Context) {
		c.Set("userID", userID)
		authHandler.GetSessions(c)
	})

	// Create a session
	_, err = authService.Login(
		&dto.LoginRequest{
			Email:    regReq.Email,
			Password: regReq.Password,
		},
		"127.0.0.1",
		"test-agent",
	)
	assert.NoError(t, err)

	req, _ := http.NewRequest(
		http.MethodGet,
		"/api/auth/sessions",
		nil,
	)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)

	data := resp["data"].([]interface{})
	assert.NotEmpty(t, data, "expected at least one session after login")

	for _, item := range data {
		session := item.(map[string]interface{})

		assert.False(
			t,
			session["isCurrent"].(bool),
			"expected no session to be marked current when sessionID is missing",
		)
	}
}

// # standardize error response format in auth and oauth handlers
func TestAuthHandler_ErrorResponse_InvalidRequest(t *testing.T) {
	r, h := SetupRouter(t)
	r.POST("/api/auth/register", h.Register)

	// Test invalid JSON body
	req, _ := http.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)

	// Verify standardized error response format
	assert.False(t, resp["success"].(bool))
	errorField := resp["error"].(map[string]interface{})
	assert.Equal(t, "VALIDATION_ERROR", errorField["code"])
	assert.NotEmpty(t, errorField["message"])
}

func TestAuthHandler_ErrorResponse_LoginFailed(t *testing.T) {
	r, h := SetupRouter(t)
	r.POST("/api/auth/register", h.Register)
	r.POST("/api/auth/login", h.Login)

	// Register user first
	regBody := dto.RegisterRequest{
		Email:     "login_error@example.com",
		Password:  "Password123!",
		FirstName: "Login",
		LastName:  "Error",
	}
	b, _ := json.Marshal(regBody)
	regReq, _ := http.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewBuffer(b))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	r.ServeHTTP(regW, regReq)
	assert.Equal(t, http.StatusCreated, regW.Code)

	// Try to login with wrong password
	loginBody := dto.LoginRequest{
		Email:    "login_error@example.com",
		Password: "WrongPassword123!",
	}
	b2, _ := json.Marshal(loginBody)
	req, _ := http.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBuffer(b2))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)

	// Verify standardized error response format
	assert.False(t, resp["success"].(bool))
	errorField := resp["error"].(map[string]interface{})
	assert.Equal(t, "LOGIN_FAILED", errorField["code"])
	assert.NotEmpty(t, errorField["message"])
}

func TestAuthHandler_ErrorResponse_VerifyEmail_MissingToken(t *testing.T) {
	r, h := SetupRouter(t)
	r.GET("/api/auth/verify-email", h.VerifyEmail)

	req, _ := http.NewRequest(http.MethodGet, "/api/auth/verify-email", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)

	// Verify standardized error response format
	assert.False(t, resp["success"].(bool))
	errorField := resp["error"].(map[string]interface{})
	assert.Equal(t, "MISSING_TOKEN", errorField["code"])
	assert.NotEmpty(t, errorField["message"])
}

func TestAuthHandler_ErrorResponse_ResetPassword_InvalidRequest(t *testing.T) {
	r, h := SetupRouter(t)
	r.POST("/api/auth/reset-password", h.ResetPassword)

	// Test invalid JSON body
	req, _ := http.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)

	// Verify standardized error response format
	assert.False(t, resp["success"].(bool))
	errorField := resp["error"].(map[string]interface{})
	assert.Equal(t, "VALIDATION_ERROR", errorField["code"])
	assert.NotEmpty(t, errorField["message"])
}
