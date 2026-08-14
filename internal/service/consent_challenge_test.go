package service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/service"
)

func consentTestService() *service.OAuthProviderService {
	cfg := &config.Config{Security: config.SecurityConfig{EncryptionKey: "0123456789abcdef0123456789abcdef"}}
	return service.NewOAuthProviderService(nil, nil, nil, nil, nil, nil, cfg)
}

func TestConsentChallengeBindsScopes(t *testing.T) {
	ps := consentTestService()
	user := "u1"
	client := "c1"
	scopes := []string{"read:profile", "read:email"}

	tok := ps.CreateConsentChallenge(user, client, scopes)
	require.NotEmpty(t, tok)

	assert.True(t, ps.ValidateConsentChallenge(tok, user, client, scopes))
	// order-insensitive
	assert.True(t, ps.ValidateConsentChallenge(tok, user, client, []string{"read:email", "read:profile"}))
}

func TestConsentChallengeRejectsScopeInjection(t *testing.T) {
	ps := consentTestService()
	user, client := "u1", "c1"
	original := []string{"read:profile"}
	tok := ps.CreateConsentChallenge(user, client, original)

	// attacker appends a scope the client is registered for but user never saw
	assert.False(t, ps.ValidateConsentChallenge(tok, user, client, []string{"read:profile", "admin:users"}))
	assert.False(t, ps.ValidateConsentChallenge(tok, user, client, []string{"read:email"}))
	assert.False(t, ps.ValidateConsentChallenge(tok, "u2", client, original), "different user rejected")
	assert.False(t, ps.ValidateConsentChallenge(tok, user, "c2", original), "different client rejected")
}

func TestConsentChallengeToleratesGarbage(t *testing.T) {
	ps := consentTestService()
	assert.False(t, ps.ValidateConsentChallenge("", "u", "c", []string{"read:profile"}))
	assert.False(t, ps.ValidateConsentChallenge("not-hex", "u", "c", []string{"read:profile"}))
}
