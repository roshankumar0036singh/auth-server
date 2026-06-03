package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestAuthHandler_ProtectedRoutes(t *testing.T) {
	// Custom setup for protected route testing middleware
	authService, _, mr := testutils.SetupIntegrationTest(t)
	
	authHandler := handler.NewAuthHandler(authService, nil)
	cfg := &config.Config{JWT: config.JWTConfig{AccessSecret: testutils.TestJWTSecret}}
	tokenService := service.NewTokenService(cfg)
	
	t.Cleanup(func() { mr.Close() })

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.AuthMiddleware(tokenService))
	r.GET("/api/auth/me", authHandler.GetMe)

	// Register user
	regReq := &dto.RegisterRequest{Email: "protect_me@example.com", Password: "Password123!", FirstName: "Me", LastName: "Test"}
	user, err := authService.Register(regReq)
	if err != nil {
		t.Fatalf("failed to register user: %v", err)
	}
	
	// Generate Token
	validToken, err := tokenService.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	expiredToken, err := tokenService.GenerateTokenWithExpiry(user, -15*time.Minute)
	if err != nil {
		t.Fatalf("failed to generate expired token: %v", err)
	}

	tests := []struct {
		name         string
		token        string
		expectedCode int
		expectedMsg  string
	}{
		{
			name:         "Missing Token",
			token:        "",
			expectedCode: http.StatusUnauthorized,
			expectedMsg:  "Authentication required",
		},
		{
			name:         "Invalid Token",
			token:        "invalid.token.here",
			expectedCode: http.StatusUnauthorized,
			expectedMsg:  "Invalid or expired token",
		},
		{
			name:         "Expired Token",
			token:        expiredToken,
			expectedCode: http.StatusUnauthorized,
			expectedMsg:  "Invalid or expired token",
		},
		{
			name:         "Valid Token",
			token:        validToken,
			expectedCode: http.StatusOK,
			expectedMsg:  "User retrieved successfully", 
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/api/auth/me", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedCode, w.Code)
			
			var resp map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			assert.NoError(t, err)

			// Safely verify message
			msg, msgOk := resp["message"].(string)
			assert.True(t, msgOk, "expected message field to be a string")
			assert.Equal(t, tc.expectedMsg, msg)

			if tc.expectedCode == http.StatusUnauthorized {
				assert.Equal(t, false, resp["success"])
			} else {
				assert.Equal(t, true, resp["success"])
				data, ok := resp["data"].(map[string]interface{})
				if assert.True(t, ok, "expected data object in response") {
					assert.Equal(t, "protect_me@example.com", data["email"])
				}
			}
		})
	}
}
