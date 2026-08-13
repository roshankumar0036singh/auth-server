package service_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

func newOAuthServiceForTest(t *testing.T, db interface{ MigrateWithCount() }) *service.OAuthProviderService {
	return nil
}

func TestUpdateClientSessionTTL(t *testing.T) {
	authService, db, _ := testutils.SetupIntegrationTest(t)

	owner, err := authService.Register(&dto.RegisterRequest{Email: "ttl-owner@example.com", Password: "StrongPass123!"})
	require.NoError(t, err)

	oauthService := service.NewOAuthProviderService(
		repository.NewOAuthClientRepository(db),
		repository.NewAuthorizationCodeRepository(db),
		repository.NewOAuthTokenRepository(db),
		repository.NewUserConsentRepository(db),
		repository.NewOAuthProviderConfigRepository(db),
		service.NewTokenService(&config.Config{JWT: config.JWTConfig{AccessSecret: "s", RefreshSecret: "r"}}),
		&config.Config{},
	)

	client, secret, err := oauthService.CreateClient("TTL App", []string{"https://app.example.com/cb"}, []string{"read:profile"}, owner.ID, false)
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	// default stays global
	assert.Equal(t, int64(0), client.AccessTokenTTLSeconds)
	assert.Equal(t, time.Hour, oauthService.EffectiveAccessTokenTTL(client))

	// owner override
	updated, err := oauthService.UpdateClientSessionTTL(client.ClientID, owner.ID, 900, 3600)
	require.NoError(t, err)
	assert.Equal(t, int64(900), updated.AccessTokenTTLSeconds)
	assert.Equal(t, time.Duration(900)*time.Second, oauthService.EffectiveAccessTokenTTL(updated))

	// non-owner cannot modify
	other, err := authService.Register(&dto.RegisterRequest{Email: "ttl-other@example.com", Password: "StrongPass123!"})
	require.NoError(t, err)
	_, err = oauthService.UpdateClientSessionTTL(client.ClientID, other.ID, 60, 60)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized")

	// negative TTL rejected
	_, err = oauthService.UpdateClientSessionTTL(client.ClientID, owner.ID, -5, 0)
	require.Error(t, err)
}

func TestExchangeCodeForTokenUsesClientTTL(t *testing.T) {
	authService, db, _ := testutils.SetupIntegrationTest(t)

	user, err := authService.Register(&dto.RegisterRequest{Email: "ttl-flow@example.com", Password: "StrongPass123!"})
	require.NoError(t, err)

	oauthService := service.NewOAuthProviderService(
		repository.NewOAuthClientRepository(db),
		repository.NewAuthorizationCodeRepository(db),
		repository.NewOAuthTokenRepository(db),
		repository.NewUserConsentRepository(db),
		repository.NewOAuthProviderConfigRepository(db),
		service.NewTokenService(&config.Config{JWT: config.JWTConfig{AccessSecret: "s", RefreshSecret: "r"}}),
		&config.Config{},
	)

	client, _, err := oauthService.CreateClient("TTL Flow", []string{"https://flow.example.com/cb"}, []string{"read:profile"}, user.ID, false)
	require.NoError(t, err)

	_, err = oauthService.UpdateClientSessionTTL(client.ClientID, user.ID, 600, 0)
	require.NoError(t, err)

	code, err := oauthService.GenerateAuthorizationCode(client.ClientID, user.ID, "https://flow.example.com/cb", []string{"read:profile"}, nil, nil)
	require.NoError(t, err)

	tok, err := oauthService.ExchangeCodeForToken(code, client.ClientID, "https://flow.example.com/cb", "", false)
	require.NoError(t, err)
	remain := time.Until(tok.ExpiresAt)
	assert.Greater(t, remain, 9*time.Minute, "TTL override should stretch the expiry toward 10 minutes")
	assert.Less(t, remain, 11*time.Minute)
}
