package service_test

import (
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/service"
)

func rsaKeyForTest(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, string(pemBytes)
}

func TestJWKSWithoutRSAKey(t *testing.T) {
	svc := service.NewJWKSService(&config.Config{JWT: config.JWTConfig{RSAPrivateKey: ""}})
	require.NotNil(t, svc)
	assert.Empty(t, svc.Document().Keys, "HS256 mode must not publish keys")
	assert.Nil(t, svc.PrivateKey())
}

func TestJWKSWithRSAKey(t *testing.T) {
	_, pemValue := rsaKeyForTest(t)
	svc := service.NewJWKSService(&config.Config{JWT: config.JWTConfig{RSAPrivateKey: pemValue}})
	require.NotNil(t, svc.PrivateKey())

	keys := svc.Document().Keys
	require.Len(t, keys, 1)
	assert.Equal(t, "RSA", keys[0].Kty)
	assert.Equal(t, "RS256", keys[0].Alg)
	assert.Equal(t, "sig", keys[0].Use)
	assert.NotEmpty(t, keys[0].N)
	assert.Equal(t, "AQAB", keys[0].E)
	assert.NotEmpty(t, svc.KeyID())
}

func TestJWKSBase64EncodedKey(t *testing.T) {
	_, pemValue := rsaKeyForTest(t)
	b64 := "base64:" + base64.StdEncoding.EncodeToString([]byte(pemValue))
	svc := service.NewJWKSService(&config.Config{JWT: config.JWTConfig{RSAPrivateKey: b64}})
	require.NotNil(t, svc.PrivateKey())
	assert.Len(t, svc.Document().Keys, 1)
}

func TestJWKSInvalidKeyPanics(t *testing.T) {
	assert.Panics(t, func() {
		service.NewJWKSService(&config.Config{JWT: config.JWTConfig{RSAPrivateKey: "not-a-pem"}})
	})
}

func testUser() *models.User {
	return &models.User{ID: "u-test-1", Email: "rsa@example.com", Role: "user"}
}

func splitJWT(raw string) (map[string]interface{}, []byte, []byte, error) {
	parts := strings.Split(raw, ".")
	b64 := func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
	headerBytes, err := b64(parts[0])
	if err != nil {
		return nil, nil, nil, err
	}
	_, err = b64(parts[1])
	if err != nil {
		return nil, nil, nil, err
	}
	signature, err := b64(parts[2])
	if err != nil {
		return nil, nil, nil, err
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, nil, err
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	return header, signingInput, signature, nil
}

func TestRS256TokenSigningAndVerification(t *testing.T) {
	key, pemValue := rsaKeyForTest(t)
	cfg := &config.Config{JWT: config.JWTConfig{
		AccessSecret:  "hs-secret",
		RefreshSecret: "hs-refresh",
		RSAPrivateKey: pemValue,
	}}
	tokenService := service.NewTokenService(cfg)

	user := testUser()
	access, err := tokenService.GenerateAccessToken(user, "session-1")
	require.NoError(t, err)
	claims, err := tokenService.ValidateAccessToken(access)
	require.NoError(t, err)
	assert.Equal(t, user.ID, claims.UserID)

	// the token is RS256 with a kid header and verifies with the public key alone
	header, payload, signature, err := splitJWT(access)
	require.NoError(t, err)
	assert.Equal(t, "RS256", header["alg"])
	assert.Equal(t, service.JWKSKeyID(), header["kid"])
	digest := sha256.Sum256(payload)
	require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature))
	claimsBody, err := base64.RawURLEncoding.DecodeString(strings.Split(access, ".")[1])
	require.NoError(t, err)
	assert.Contains(t, string(claimsBody), user.ID)

	// refresh tokens also RS256
	refresh, err := tokenService.GenerateRefreshToken(user)
	require.NoError(t, err)
	_, err = tokenService.ValidateRefreshToken(refresh)
	require.NoError(t, err)

	// an HS256-signed token is still accepted (mixed-mode backward compat)
	tokenServiceHS := service.NewTokenService(&config.Config{JWT: config.JWTConfig{AccessSecret: "hs-secret"}})
	legacy, err := tokenServiceHS.GenerateAccessToken(user, "session-legacy")
	require.NoError(t, err)
	_, err = tokenService.ValidateAccessToken(legacy)
	require.NoError(t, err)
}