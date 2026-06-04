package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/roshankumar0036singh/auth-server/internal/middleware"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupAdminLockRouter(t *testing.T) (
	*gin.Engine,
	*service.AuthService,
	*service.TokenService,
	*repository.UserRepository,
) {
	t.Helper()

	authSvc, db, mr := testutils.SetupIntegrationTest(t)
	t.Cleanup(func() { mr.Close() })

	userRepo := repository.NewUserRepository(db)

	cfg := &config.Config{
		JWT: config.JWTConfig{
			AccessSecret:  "test-access-secret",
			RefreshSecret: "test-refresh-secret",
		},
	}

	tokenSvc := service.NewTokenService(cfg)
	adminHandler := handler.NewAdminHandler(authSvc)

	gin.SetMode(gin.TestMode)
	r := gin.New()

	admin := r.Group("/api/admin")
	admin.Use(middleware.AuthMiddleware(tokenSvc))
	admin.Use(middleware.RequireRole("admin"))

	admin.POST("/users/:id/lock", adminHandler.LockUser)
	admin.POST("/users/:id/unlock", adminHandler.UnlockUser)

	return r, authSvc, tokenSvc, userRepo
}

func TestAdminHandler_LockUser_Errors(t *testing.T) {
	r, authSvc, tokenSvc, userRepo := setupAdminLockRouter(t)

	admin, err := authSvc.Register(&dto.RegisterRequest{
		Email:    "lock-admin@test.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	require.NoError(t,
		userRepo.Update(admin.ID, map[string]interface{}{"role": "admin"}))

	admin.Role = "admin"

	user, err := authSvc.Register(&dto.RegisterRequest{
		Email:    "lock-user@test.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	otherAdmin, err := authSvc.Register(&dto.RegisterRequest{
		Email:    "lock-other-admin@test.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	require.NoError(t,
		userRepo.Update(otherAdmin.ID, map[string]interface{}{"role": "admin"}))

	require.NoError(t,
		authSvc.LockUser(user.ID, admin.ID, "", ""))

	token, err := tokenSvc.GenerateAccessToken(admin)
	require.NoError(t, err)

	tests := []struct {
		name   string
		userID string
		status int
	}{
		{"user not found", "00000000-0000-0000-0000-000000000000", http.StatusNotFound},
		{"self lock", admin.ID, http.StatusBadRequest},
		{"admin account", otherAdmin.ID, http.StatusForbidden},
		{"already locked", user.ID, http.StatusConflict},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"/api/admin/users/"+tt.userID+"/lock",
				nil,
			)

			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.status, w.Code)
		})
	}
}

func TestAdminHandler_UnlockUser_Errors(t *testing.T) {
	r, authSvc, tokenSvc, userRepo := setupAdminLockRouter(t)

	admin, err := authSvc.Register(&dto.RegisterRequest{
		Email:    "unlock-admin@test.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	require.NoError(t,
		userRepo.Update(admin.ID, map[string]interface{}{"role": "admin"}))

	admin.Role = "admin"

	unlockedUser, err := authSvc.Register(&dto.RegisterRequest{
		Email:    "unlock-user@test.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	lockedUser, err := authSvc.Register(&dto.RegisterRequest{
		Email:    "unlock-user-locked@test.com",
		Password: "Password123!",
	})
	require.NoError(t, err)

	require.NoError(t,
		authSvc.LockUser(lockedUser.ID, admin.ID, "", ""))

	token, err := tokenSvc.GenerateAccessToken(admin)
	require.NoError(t, err)

	tests := []struct {
		name   string
		userID string
		status int
	}{
		{"user not found", "00000000-0000-0000-0000-000000000000", http.StatusNotFound},
		{"not locked", unlockedUser.ID, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"/api/admin/users/"+tt.userID+"/unlock",
				nil,
			)

			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.status, w.Code)
		})
	}
}
