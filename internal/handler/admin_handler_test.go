package handler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/roshankumar0036singh/auth-server/internal/middleware"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/stretchr/testify/assert"
)

func TestAdminHandler_GetUsers(t *testing.T) {
	authService, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	adminHandler := handler.NewAdminHandler(authService)
	cfg := &config.Config{JWT: config.JWTConfig{AccessSecret: "secret"}}
	tokenService := service.NewTokenService(cfg)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.AuthMiddleware(tokenService))
	r.Use(middleware.RequireRole("admin"))
	r.GET("/api/admin/users", adminHandler.GetUsers)

	// Create an admin user to generate tokens
	adminReq := &dto.RegisterRequest{
		Email:     "admin@example.com",
		Password:  "Password123!",
		FirstName: "Admin",
		LastName:  "User",
	}
	adminUser, err := authService.Register(adminReq)
	assert.NoError(t, err)

	// Update role to admin manually in DB
	err = db.Model(adminUser).Update("role", "admin").Error
	assert.NoError(t, err)

	// Create 15 regular users to test pagination
	for i := 1; i <= 15; i++ {
		userReq := &dto.RegisterRequest{
			Email:     fmt.Sprintf("user%d@example.com", i),
			Password:  "Password123!",
			FirstName: fmt.Sprintf("User%d", i),
			LastName:  "Test",
		}
		_, err := authService.Register(userReq)
		assert.NoError(t, err)
	}

	// Generate Admin token
	token, err := tokenService.GenerateAccessToken(adminUser)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	t.Run("Default Pagination (limit=10, offset=0)", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/users", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.True(t, resp["success"].(bool))

		data := resp["data"].(map[string]interface{})
		assert.Equal(t, float64(10), data["limit"])
		assert.Equal(t, float64(0), data["offset"])
		// Total should be 16 (1 admin + 15 regular users)
		assert.Equal(t, float64(16), data["total"])

		users := data["users"].([]interface{})
		assert.Len(t, users, 10)
	})

	t.Run("Custom Pagination (limit=5, offset=12)", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/users?limit=5&offset=12", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)

		data := resp["data"].(map[string]interface{})
		assert.Equal(t, float64(5), data["limit"])
		assert.Equal(t, float64(12), data["offset"])
		assert.Equal(t, float64(16), data["total"])

		users := data["users"].([]interface{})
		assert.Len(t, users, 4) // 16 total - 12 offset = 4 remaining
	})

	t.Run("Invalid Parameters should fallback to defaults", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/users?limit=-5&offset=-2", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)

		data := resp["data"].(map[string]interface{})
		assert.Equal(t, float64(10), data["limit"])
		assert.Equal(t, float64(0), data["offset"])
	})

	t.Run("Limit Capped at 100", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/users?limit=200", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)

		data := resp["data"].(map[string]interface{})
		assert.Equal(t, float64(100), data["limit"])
	})

	t.Run("Non-Admin User should get 403 Forbidden", func(t *testing.T) {
		nonAdminReq := &dto.RegisterRequest{
			Email:     "regular@example.com",
			Password:  "Password123!",
			FirstName: "Regular",
			LastName:  "User",
		}
		nonAdminUser, err := authService.Register(nonAdminReq)
		assert.NoError(t, err)

		nonAdminToken, err := tokenService.GenerateAccessToken(nonAdminUser)
		assert.NoError(t, err)
		assert.NotEmpty(t, nonAdminToken)

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/users", nil)
		req.Header.Set("Authorization", "Bearer "+nonAdminToken)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}
