package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

func newCredentialsRouter(t *testing.T) (*gin.Engine, *service.OAuthProviderService) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	t.Cleanup(func() { mr.Close() })
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		JWT: config.JWTConfig{AccessSecret: "secret", RefreshSecret: "refresh"},
	}
	oid := service.NewOAuthProviderService(
		repository.NewOAuthClientRepository(db),
		repository.NewAuthorizationCodeRepository(db),
		repository.NewOAuthTokenRepository(db),
		repository.NewUserConsentRepository(db),
		repository.NewOAuthProviderConfigRepository(db),
		service.NewTokenService(cfg),
		cfg,
	)
	ts := service.NewTokenService(cfg)
	oh := handler.NewOAuthHandler(oid, repository.NewUserRepository(db), ts, nil)

	r := gin.New()
	r.POST("/oauth/token", oh.Token)
	return r, oid
}

func credsRequest(r *gin.Engine, params url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestClientCredentialsIssuesM2MToken(t *testing.T) {
	r, oid := newCredentialsRouter(t)
	client, secret, err := oid.CreateClient("m2m", []string{"http://cb"}, []string{"read:profile"}, "owner", false)
	require.NoError(t, err)

	rec := credsRequest(r, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientID},
		"client_secret": {secret},
		"scope":         {"read:profile"},
	})
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.NotEmpty(t, body.AccessToken)
	assert.Equal(t, "Bearer", body.TokenType)
	assert.Equal(t, "read:profile", body.Scope)
	assert.Greater(t, body.ExpiresIn, 0)

	// the JWT represents the application itself: client_id claim, no user sub
	parsed, err := jwt.Parse(body.AccessToken, func(tok *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, client.ClientID, claims["client_id"])
	assert.Equal(t, "read:profile", claims["scope"])
	sub, hasSub := claims["sub"]
	assert.True(t, hasSub, "RegisteredClaims always carries sub")
	assert.Empty(t, sub, "M2M tokens must not carry a user identity")
}

func TestClientCredentialsRejectsPublicClient(t *testing.T) {
	r, oid := newCredentialsRouter(t)
	client, secret, err := oid.CreateClient("public-m2m", []string{"http://cb"}, []string{"read:profile"}, "owner", true)
	require.NoError(t, err)
	_ = secret

	rec := credsRequest(r, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientID},
		"client_secret": {"secret"},
		"scope":         {"read:profile"},
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestClientCredentialsRejectsDisallowedScope(t *testing.T) {
	r, oid := newCredentialsRouter(t)
	client, secret, err := oid.CreateClient("m2m-scope", []string{"http://cb"}, []string{"read:profile"}, "owner", false)
	require.NoError(t, err)

	rec := credsRequest(r, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientID},
		"client_secret": {secret},
		"scope":         {"admin:users"},
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestClientCredentialsRejectsBadSecret(t *testing.T) {
	r, oid := newCredentialsRouter(t)
	client, _, err := oid.CreateClient("m2m-bad", []string{"http://cb"}, []string{"read:profile"}, "owner", false)
	require.NoError(t, err)

	rec := credsRequest(r, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientID},
		"client_secret": {"wrong-secret"},
		"scope":         {"read:profile"},
	})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestTokenStillRejectsUnknownGrantType(t *testing.T) {
	r, oid := newCredentialsRouter(t)
	client, secret, err := oid.CreateClient("m2m-g", []string{"http://cb"}, []string{"read:profile"}, "owner", false)
	require.NoError(t, err)

	rec := credsRequest(r, url.Values{
		"grant_type":    {"implicit"},
		"client_id":     {client.ClientID},
		"client_secret": {secret},
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
