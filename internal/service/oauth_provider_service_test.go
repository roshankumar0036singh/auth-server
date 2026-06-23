package service_test

import (
	"testing"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthProviderService(t *testing.T) {
	_, db, _ := testutils.SetupIntegrationTest(t)

	// Preserve your existing inline tables configurations setup
	db.Exec(`CREATE TABLE IF NOT EXISTS oauth_clients (
        id text PRIMARY KEY,
        name text NOT NULL,
        client_id text NOT NULL,
        client_secret text NOT NULL,
        redirect_uris text,
        scopes text,
        owner_id text,
        is_active boolean DEFAULT true,
        created_at datetime,
        updated_at datetime
    )`)
	db.Exec(`CREATE TABLE IF NOT EXISTS oauth_provider_configs (
        id text PRIMARY KEY,
        client_id text NOT NULL,
        provider text NOT NULL,
        provider_client_id text NOT NULL,
        provider_client_secret text NOT NULL,
        created_at datetime,
        updated_at datetime
    )`)

	clientRepo := repository.NewOAuthClientRepository(db)
	codeRepo := repository.NewAuthorizationCodeRepository(db)
	tokenRepo := repository.NewOAuthTokenRepository(db)
	consentRepo := repository.NewUserConsentRepository(db)
	configRepo := repository.NewOAuthProviderConfigRepository(db)

	cfg := &config.Config{
		Security: config.SecurityConfig{
			EncryptionKey: "12345678901234567890123456789012",
			BcryptRounds:  4, // Kept small to speed up execution
		},
	}
	tokenService := service.NewTokenService(cfg)

	providerService := service.NewOAuthProviderService(
		clientRepo, codeRepo, tokenRepo, consentRepo, configRepo, tokenService, cfg,
	)

	ownerID := "user1"
	otherOwnerID := "user2"

	client, plainSecret, err := providerService.CreateClient("test-client", []string{"http://localhost"}, []string{"read:profile"}, ownerID, false)
	assert.NoError(t, err)

	// --- PRESERVED EXISTING USER TESTS ---

	t.Run("CreateOrUpdateProviderConfig - Success", func(t *testing.T) {
		err := providerService.CreateOrUpdateProviderConfig(ownerID, client.ID, "google", "g-id", "g-secret")
		assert.NoError(t, err)

		conf, err := providerService.GetProviderConfig(ownerID, client.ID, "google")
		assert.NoError(t, err)
		assert.Equal(t, "g-id", conf.ProviderClientID)
		assert.NotEqual(t, "g-secret", conf.ProviderClientSecret)
	})

	t.Run("CreateOrUpdateProviderConfig - Unauthorized", func(t *testing.T) {
		err := providerService.CreateOrUpdateProviderConfig(otherOwnerID, client.ID, "google", "g-id", "g-secret")
		assert.ErrorIs(t, err, service.ErrUnauthorized)
	})

	t.Run("GetProviderConfig - Unauthorized", func(t *testing.T) {
		_, err := providerService.GetProviderConfig(otherOwnerID, client.ID, "google")
		assert.ErrorIs(t, err, service.ErrUnauthorized)
	})

	t.Run("DeleteProviderConfig - Success", func(t *testing.T) {
		err := providerService.DeleteProviderConfig(ownerID, client.ID, "google")
		assert.NoError(t, err)

		_, err = providerService.GetProviderConfig(ownerID, client.ID, "google")
		assert.Error(t, err)
	})

	t.Run("DeleteProviderConfig - Unauthorized", func(t *testing.T) {
		providerService.CreateOrUpdateProviderConfig(ownerID, client.ID, "google", "g-id", "g-secret")

		err := providerService.DeleteProviderConfig(otherOwnerID, client.ID, "google")
		assert.ErrorIs(t, err, service.ErrUnauthorized)
	})

	// --- NEW EXPANSION TESTS FOR MAXIMUM STATEMENT COVERAGE ---

	t.Run("ValidateClient Credentials Matrix", func(t *testing.T) {
		// Valid credentials validation lookup pass
		res, err := providerService.ValidateClient(client.ClientID, plainSecret)
		assert.NoError(t, err)
		assert.NotNil(t, res)

		// Invalid credentials error mapping validation
		_, err = providerService.ValidateClient(client.ClientID, "bad-secret-guess")
		assert.ErrorIs(t, err, service.ErrInvalidClientCredentials)

		_, err = providerService.ValidateClient("non-existent-client-id", plainSecret)
		assert.ErrorIs(t, err, service.ErrInvalidClientCredentials)
	})

	t.Run("ResolveClientForToken Confidential vs Public Client Mechanics", func(t *testing.T) {
		// 1. Confidential validation check
		res, err := providerService.ResolveClientForToken(client.ClientID, plainSecret)
		assert.NoError(t, err)
		assert.Equal(t, client.ClientID, res.ClientID)

		_, err = providerService.ResolveClientForToken(client.ClientID, "")
		assert.Error(t, err, "Confidential client missing a payload client secret should throw errors")

		// 2. Build a quick public client model record
		pubClient, _, _ := providerService.CreateClient("public-spa", []string{"http://localhost"}, []string{"read:profile"}, ownerID, true)
		
		resPub, err := providerService.ResolveClientForToken(pubClient.ClientID, "")
		assert.NoError(t, err)
		assert.True(t, resPub.IsPublic)
	})

	t.Run("Public Verification and Inactive Error States", func(t *testing.T) {
		pubClient, _, _ := providerService.CreateClient("temp-spa", []string{"http://localhost"}, []string{"read:profile"}, ownerID, true)
		
		res, err := providerService.GetPublicClient(pubClient.ClientID)
		assert.NoError(t, err)
		assert.NotNil(t, res)

		// Deactivate client manually to check status gate blocks
		pubClient.IsActive = false
		_ = clientRepo.Update(pubClient)

		_, err = providerService.GetPublicClient(pubClient.ClientID)
		assert.ErrorIs(t, err, service.ErrClientInactive)

		_, err = providerService.ResolveClientForToken(pubClient.ClientID, "")
		assert.ErrorIs(t, err, service.ErrClientInactive)
	})

	t.Run("Metadata Utilities: Redirect URIs, Scopes parsing & Client Ownership Filters", func(t *testing.T) {
		// URI validation check
		assert.NoError(t, providerService.ValidateRedirectURI(client, "http://localhost"))
		assert.Error(t, providerService.ValidateRedirectURI(client, "http://malicious-attacker.com"))

		// Scope parsing utilities check
		assert.Equal(t, []string{"read:profile", "read:email"}, service.ParseScopes("read:profile read:email"))
		assert.Empty(t, service.ParseScopes(""))

		// Scope containment array mappings checks
		assert.NoError(t, providerService.ValidateClientScopes(client, []string{"read:profile"}))
		assert.Error(t, providerService.ValidateClientScopes(client, []string{"admin:users"}))

		// Client querying and deletion access controls checks
		clients, err := providerService.GetClientsByOwner(ownerID)
		assert.NoError(t, err)
		assert.NotEmpty(t, clients)

		err = providerService.DeleteClient(client.ID, "FAKE_USER_ID")
		assert.Error(t, err, "Should refuse non-owners from dropping registry mappings")

		// Clean up the client via true identity context
		err = providerService.DeleteClient(client.ID, ownerID)
		assert.NoError(t, err)
	})

	t.Run("ExchangeCodeForToken with Atomic PKCE Replay Checks", func(t *testing.T) {
		cApp, _, _ := providerService.CreateClient("core-exchange", []string{"http://localhost"}, []string{"read:profile"}, ownerID, false)
		
		// Use standard "plain" matching parameters to avoid external dependency requirements
		verifier := "plain-random-pkce-verifier-string-1234567890"
		challenge := "plain-random-pkce-verifier-string-1234567890"
		methodPlain := "plain"

		code, err := providerService.GenerateAuthorizationCode(cApp.ClientID, "user_xyz", "http://localhost", []string{"read:profile"}, &challenge, &methodPlain)
		require.NoError(t, err)

		// Reject mismatched redirect identity payloads
		_, err = providerService.ExchangeCodeForToken(code, cApp.ClientID, "http://wrong-uri", verifier, false)
		assert.Error(t, err)

		// Validate standard token swap execution mapping path
		tokenRecord, err := providerService.ExchangeCodeForToken(code, cApp.ClientID, "http://localhost", verifier, false)
		require.NoError(t, err) 
		require.NotNil(t, tokenRecord)
		assert.NotEmpty(t, tokenRecord.RawToken)

		// Verify structural lookups against the token engine
		activeParsed, err := providerService.ValidateAccessToken(tokenRecord.RawToken)
		assert.NoError(t, err)
		assert.Equal(t, utils.HashToken(tokenRecord.RawToken), activeParsed.Token)

		// Replay Attack protection verification check: code cannot be consumed twice
		_, err = providerService.ExchangeCodeForToken(code, cApp.ClientID, "http://localhost", verifier, false)
		assert.Error(t, err)
	})

	t.Run("User Authorization Consent Management Pipeline Loop", func(t *testing.T) {
		hasConsent, err := providerService.CheckConsent("u1", "c1", []string{"read:profile"})
		assert.NoError(t, err)
		assert.False(t, hasConsent)

		err = providerService.SaveConsent("u1", "c1", []string{"read:profile"})
		assert.NoError(t, err)

		hasConsent, err = providerService.CheckConsent("u1", "c1", []string{"read:profile"})
		assert.True(t, hasConsent)

		// Check updates work cleanly against the existing relational composite primary keys
		err = providerService.SaveConsent("u1", "c1", []string{"read:profile", "write:profile"})
		assert.NoError(t, err)
	})
}