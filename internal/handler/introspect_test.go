package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

// return the service deps too so tests can issue/blacklist tokens
func newIntrospectRouter(t *testing.T) (*gin.Engine, *service.OAuthProviderService, *service.TokenService, *service.CacheService) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	t.Cleanup(func() { mr.Close() })
	gin.SetMode(gin.TestMode)

	oid := service.NewOAuthProviderService(
		repository.NewOAuthClientRepository(db),
		repository.NewAuthorizationCodeRepository(db),
		repository.NewOAuthTokenRepository(db),
		repository.NewUserConsentRepository(db),
		repository.NewOAuthProviderConfigRepository(db),
		service.NewTokenService(&config.Config{JWT: config.JWTConfig{AccessSecret: "secret", RefreshSecret: "refresh"}}),
		&config.Config{Security: config.SecurityConfig{BcryptRounds: 4}},
	)
	userRepo := repository.NewUserRepository(db)
	ts := service.NewTokenService(&config.Config{JWT: config.JWTConfig{AccessSecret: "secret"}})
	cs := service.NewCacheService(redis.NewClient(&redis.Options{Addr: mr.Addr()}))

	oh := handler.NewOAuthHandler(oid, userRepo, ts, cs)
	r := gin.New()
	r.POST("/oauth/introspect", oh.Introspect)
	return r, oid, ts, cs
}

func mustMakeClient(t *testing.T, oid *service.OAuthProviderService) (string, string) {
	t.Helper()
	name := "introspect-client"
	client, secret, err := oid.CreateClient(name, []string{"http://localhost/cb"}, []string{"read:profile"}, "owner", false)
	require.NoError(t, err)
	require.NotEmpty(t, client.ClientID)
	return client.ClientID, secret
}

func introspectRequest(r *gin.Engine, params url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestIntrospectActiveToken(t *testing.T) {
	r, oid, ts, _ := newIntrospectRouter(t)
	clientID, secret := mustMakeClient(t, oid)

	// issue a real access token
	token, err := ts.GenerateAccessToken(
		&models.User{ID: "user-1", Email: "u@example.com"}, "sess-1",
	)
	require.NoError(t, err)

	rec := introspectRequest(r, url.Values{
		"client_id":     {clientID},
		"client_secret": {secret},
		"token":         {token},
	})
	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, true, body["active"])
	assert.Equal(t, "user-1", body["sub"])
	assert.Equal(t, "u@example.com", body["username"])
	assert.Equal(t, "access_token", body["token_type"])
	assert.NotNil(t, body["exp"])
	assert.NotNil(t, body["iat"])
	assert.Equal(t, clientID, body["client_id"])
}

func TestIntrospectBlacklistedTokenIsInactive(t *testing.T) {
	r, oid, ts, cs := newIntrospectRouter(t)
	clientID, secret := mustMakeClient(t, oid)

	token, err := ts.GenerateAccessToken(&models.User{ID: "user-1"}, "sess-1")
	require.NoError(t, err)
	require.NoError(t, cs.BlacklistToken(context.Background(), token, time.Hour))

	rec := introspectRequest(r, url.Values{
		"client_id":     {clientID},
		"client_secret": {secret},
		"token":         {token},
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, false, body["active"])
}

func TestIntrospectInvalidTokenIsInactive(t *testing.T) {
	r, oid, _, _ := newIntrospectRouter(t)
	clientID, secret := mustMakeClient(t, oid)

	rec := introspectRequest(r, url.Values{
		"client_id":     {clientID},
		"client_secret": {secret},
		"token":         {"garbage.invalid.token"},
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, false, body["active"])
}

func TestIntrospectRequiresClientAuth(t *testing.T) {
	r, _, _, _ := newIntrospectRouter(t)
	rec := introspectRequest(r, url.Values{"token": {"anything"}})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestIntrospectMissingTokenBadRequest(t *testing.T) {
	r, oid, _, _ := newIntrospectRouter(t)
	clientID, secret := mustMakeClient(t, oid)
	rec := introspectRequest(r, url.Values{"client_id": {clientID}, "client_secret": {secret}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
