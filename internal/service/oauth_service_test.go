package service_test

import (
	"context"
	"testing"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func setupOAuthServiceInfrastructure(t *testing.T) (*service.OAuthService, *repository.OAuthProviderConfigRepository, *config.Config) {
	_, db, _ := testutils.SetupIntegrationTest(t)

	// Ensure we have a valid 32-byte key for AES decryption logic
	encryptionKey := "this-is-a-32-byte-long-key-12345"

	cfg := &config.Config{
		Security: config.SecurityConfig{
			EncryptionKey: encryptionKey,
		},
	}

	// Dynamically inject fields directly to bypass struct definition mismatches
	cfg.OAuth.Google.ClientID = "global-google-id"
	cfg.OAuth.Google.ClientSecret = "global-google-secret"
	cfg.OAuth.Google.CallbackURL = "http://localhost:8080/callback/google"

	cfg.OAuth.GitHub.ClientID = "global-github-id"
	cfg.OAuth.GitHub.ClientSecret = "global-github-secret"
	cfg.OAuth.GitHub.CallbackURL = "http://localhost:8080/callback/github"

	providerRepo := repository.NewOAuthProviderConfigRepository(db)
	oauthService := service.NewOAuthService(cfg, providerRepo)

	return oauthService, providerRepo, cfg
}

func TestOAuthService_GenerateState(t *testing.T) {
	s, _, _ := setupOAuthServiceInfrastructure(t)

	state1, err := s.GenerateState()
	assert.NoError(t, err)
	assert.NotEmpty(t, state1)

	state2, err := s.GenerateState()
	assert.NoError(t, err)
	assert.NotEqual(t, state1, state2, "State strings must be randomly distinct")
}

func TestOAuthService_GetConfig_FallbackAndOverrides(t *testing.T) {
	s, providerRepo, cfg := setupOAuthServiceInfrastructure(t)

	t.Run("Fall back to global environment variables when clientID is blank", func(t *testing.T) {
		url, err := s.GetGoogleAuthURL("", "random-state")
		assert.NoError(t, err)
		assert.Contains(t, url, "client_id=global-google-id")
		assert.Contains(t, url, "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback%2Fgoogle")

		gitHubUrl, err := s.GetGitHubAuthURL("", "random-state")
		assert.NoError(t, err)
		assert.Contains(t, gitHubUrl, "client_id=global-github-id")
	})

	t.Run("Resolve encrypted custom database overrides when clientID is provided", func(t *testing.T) {
		encryptedSecret, err := utils.Encrypt("db-secret-override", cfg.Security.EncryptionKey)
		require.NoError(t, err)

		overrideRecord := &models.OAuthProviderConfig{
			ClientID:             "client_app_123",
			Provider:             "google",
			ProviderClientID:     "db-google-id",
			ProviderClientSecret: encryptedSecret,
		}
		_ = providerRepo.Create(overrideRecord)

		url, err := s.GetGoogleAuthURL("client_app_123", "random-state")
		assert.NoError(t, err)
		assert.Contains(t, url, "client_id=db-google-id", "Should use the database client identity override")
	})

	t.Run("Return errors cleanly if no credentials exist", func(t *testing.T) {
		cfg.OAuth.Google.ClientID = "" // Strip out fallback values
		blankSvc := service.NewOAuthService(cfg, nil)

		_, err := blankSvc.GetGoogleAuthURL("", "state")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no Google OAuth credentials configured")
	})
}

func TestOAuthService_FetchUserProfile_Mocked(t *testing.T) {
	s, _, _ := setupOAuthServiceInfrastructure(t)
	ctx := context.Background()
	dummyToken := &oauth2.Token{AccessToken: "mock-access-token-123"}

	t.Run("FetchGoogleUser handling network error path safety assertions", func(t *testing.T) {
		// We execute exchange network error path assertions safely since real exchange hits network boundaries
		_, err := s.ExchangeGoogleCode(ctx, "", "code")
		assert.Error(t, err)

		_, err = s.FetchGoogleUser(ctx, "", dummyToken)
		assert.Error(t, err, "Should fall out safely on test environment isolation boundaries")
	})

	t.Run("FetchGitHubUser error fallback validation", func(t *testing.T) {
		_, err := s.ExchangeGitHubCode(ctx, "", "code")
		assert.Error(t, err)

		_, err = s.FetchGitHubUser(ctx, "", dummyToken)
		assert.Error(t, err)
	})
}