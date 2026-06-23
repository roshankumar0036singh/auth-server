package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupOAuthAdminRouter(t *testing.T) (*gin.Engine, *repository.OAuthClientRepository) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	t.Cleanup(func() { mr.Close() })

	clientRepo := repository.NewOAuthClientRepository(db)
	oauthProviderService := service.NewOAuthProviderService(
		clientRepo,
		repository.NewAuthorizationCodeRepository(db),
		repository.NewOAuthTokenRepository(db),
		repository.NewUserConsentRepository(db),
		repository.NewOAuthProviderConfigRepository(db),
		service.NewTokenService(&config.Config{
			JWT: config.JWTConfig{AccessSecret: "secret", RefreshSecret: "refresh"},
		}),
		&config.Config{},
	)

	gin.SetMode(gin.TestMode)
	r := gin.New()

	h := handler.NewOAuthClientHandler(oauthProviderService)

	// Routes wrapped with a simple authentication context injector where needed
	r.POST("/api/auth/oauth/clients", func(c *gin.Context) {
		if token := c.GetHeader("Authorization"); token == "valid-user" {
			c.Set("userID", "user-uuid-123")
		}
		c.Next()
	}, h.CreateOAuthClient)

	r.GET("/api/auth/oauth/clients", func(c *gin.Context) {
		if token := c.GetHeader("Authorization"); token == "valid-user" {
			c.Set("userID", "user-uuid-123")
		}
		c.Next()
	}, h.ListOAuthClients)

	r.DELETE("/api/auth/oauth/clients/:clientId", func(c *gin.Context) {
		if token := c.GetHeader("Authorization"); token == "valid-user" {
			c.Set("userID", "user-uuid-123")
		}
		c.Next()
	}, h.DeleteOAuthClient)

	return r, clientRepo
}

func TestOAuthClientHandler_Create_Success(t *testing.T) {
	r, _ := setupOAuthAdminRouter(t)

	reqBody, _ := json.Marshal(handler.CreateOAuthClientRequest{
		Name:         "My App",
		RedirectURIs: []string{"https://example.com/callback"},
		Scopes:       []string{"read:profile"},
		IsPublic:     false,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/oauth/clients", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "valid-user")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	
	var resp handler.CreateOAuthClientResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.Equal(t, "My App", resp.Data.Name)
	assert.NotEmpty(t, resp.Data.ClientSecret)
}

func TestOAuthClientHandler_Create_InvalidBody(t *testing.T) {
	r, _ := setupOAuthAdminRouter(t)

	// Missing structural requirements to force binding validation failure
	reqBody := []byte(`{"name": ""}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/oauth/clients", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "valid-user")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOAuthClientHandler_Create_Unauthenticated(t *testing.T) {
	r, _ := setupOAuthAdminRouter(t)

	reqBody, _ := json.Marshal(handler.CreateOAuthClientRequest{
		Name:         "App",
		RedirectURIs: []string{"http://localhost"},
		Scopes:       []string{"openid"},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/oauth/clients", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	// Leaving out the token to trigger authentication check failure
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOAuthClientHandler_List_Success(t *testing.T) {
	r, clientRepo := setupOAuthAdminRouter(t)

	// Pre-seed an active application entry
	err := clientRepo.Create(&models.OAuthClient{
		ID:           uuid.NewString(),
		Name:         "Owned App",
		ClientID:     uuid.NewString(),
		ClientSecret: "hash",
		OwnerID:      "user-uuid-123",
		IsActive:     true,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/oauth/clients", nil)
	req.Header.Set("Authorization", "valid-user")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	
	var resp handler.ListOAuthClientsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.Len(t, resp.Data, 1)
	assert.Equal(t, "Owned App", resp.Data[0].Name)
}

func TestOAuthClientHandler_List_Unauthenticated(t *testing.T) {
	r, _ := setupOAuthAdminRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/oauth/clients", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOAuthClientHandler_Delete_Success(t *testing.T) {
	r, clientRepo := setupOAuthAdminRouter(t)

	id := uuid.NewString()
	err := clientRepo.Create(&models.OAuthClient{
		ID:           id,
		Name:         "App to delete",
		ClientID:     uuid.NewString(),
		ClientSecret: "hash",
		OwnerID:      "user-uuid-123",
		IsActive:     true,
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/oauth/clients/"+id, nil)
	req.Header.Set("Authorization", "valid-user")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOAuthClientHandler_Delete_Unauthenticated(t *testing.T) {
	r, _ := setupOAuthAdminRouter(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/oauth/clients/some-id", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOAuthClientHandler_Delete_NotFoundOrWrongOwner(t *testing.T) {
	r, _ := setupOAuthAdminRouter(t)

	// Requesting an unknown target ID to execute error path return statements
	req := httptest.NewRequest(http.MethodDelete, "/api/auth/oauth/clients/"+uuid.NewString(), nil)
	req.Header.Set("Authorization", "valid-user")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}