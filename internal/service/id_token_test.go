package service_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/service"
)

func TestGenerateIDTokenClaims(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{URL: "https://auth.example.com"},
		JWT: config.JWTConfig{AccessSecret: "hs-secret"},
	}
	oauthService := service.NewOAuthProviderService(
		nil, nil, nil, nil, nil,
		service.NewTokenService(cfg),
		cfg,
	)

	user := &models.User{ID: "u-1", Email: "oidc@example.com", EmailVerified: true}
	tokenStr, err := oauthService.GenerateIDToken(user, "client-42", "nonce-xyz", time.Now().Add(-2*time.Minute))
	require.NoError(t, err)

	claims := &service.OIDCClaims{}
	_, err = jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("hs-secret"), nil
	})
	require.NoError(t, err)

	assert.Equal(t, "https://auth.example.com", claims.Issuer)
	assert.Equal(t, "u-1", claims.Subject)
	assert.Equal(t, "client-42", claims.Audience)
	assert.Equal(t, "nonce-xyz", claims.Nonce)
	assert.Equal(t, "oidc@example.com", claims.Email)
	require.NotNil(t, claims.EmailVerified)
	assert.True(t, *claims.EmailVerified)
	exp := time.Until(claims.ExpiresAt.Time)
	assert.Greater(t, exp, 4*time.Minute)
	assert.Less(t, exp, 6*time.Minute)
}

func TestGenerateIDTokenRS256(t *testing.T) {
	key, pemValue := rsaKeyForTest(t)
	cfg := &config.Config{
		App: config.AppConfig{URL: "https://auth.example.com"},
		JWT: config.JWTConfig{AccessSecret: "hs-secret", RSAPrivateKey: pemValue},
	}
	oauthService := service.NewOAuthProviderService(
		nil, nil, nil, nil, nil,
		service.NewTokenService(cfg),
		cfg,
	)

	tokenStr, err := oauthService.GenerateIDToken(&models.User{ID: "u-2", Email: "rsa@example.com"}, "client-7", "", time.Now())
	require.NoError(t, err)

	claims := &service.OIDCClaims{}
	_, err = jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	require.NoError(t, err)
	assert.Equal(t, "u-2", claims.Subject)
}

func rsaKeyForTest(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, string(pemBytes)
}
