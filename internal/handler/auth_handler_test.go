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

	user, err := authService.Register(regReq)
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

	foundCurrent := false

	for _, item := range data {
		session := item.(map[string]interface{})

		if isCurrent, ok := session["isCurrent"].(bool); ok && isCurrent {
			foundCurrent = true
			break
		}
	}

	assert.True(t, foundCurrent, "expected one session to be marked as current")

	_ = user
}
