package service_test

import (
	"testing"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/stretchr/testify/assert"
)

func TestOAuthService_GenerateState(t *testing.T) {
	cfg := &config.Config{}
	svc := service.NewOAuthService(cfg, nil)

	state1, err := svc.GenerateState()
	assert.NoError(t, err)
	assert.NotEmpty(t, state1)

	state2, err := svc.GenerateState()
	assert.NoError(t, err)
	assert.NotEmpty(t, state2)
	assert.NotEqual(t, state1, state2)
}

func TestOAuthService_GetAuthURL_GlobalConfig(t *testing.T) {
	cfg := &config.Config{
		OAuth: config.OAuthConfig{
			Google: config.GoogleOAuthConfig{
				ClientID:     "google-client-id",
				ClientSecret: "google-secret",
				CallbackURL:  "http://localhost:8080/callback/google",
			},
			GitHub: config.GitHubOAuthConfig{
				ClientID:     "github-client-id",
				ClientSecret: "github-secret",
				CallbackURL:  "http://localhost:8080/callback/github",
			},
		},
	}
	svc := service.NewOAuthService(cfg, nil)

	googleURL, err := svc.GetGoogleAuthURL("", "test-state")
	assert.NoError(t, err)
	assert.Contains(t, googleURL, "client_id=google-client-id")
	assert.Contains(t, googleURL, "state=test-state")
	assert.Contains(t, googleURL, "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback%2Fgoogle")

	githubURL, err := svc.GetGitHubAuthURL("", "test-state-git")
	assert.NoError(t, err)
	assert.Contains(t, githubURL, "client_id=github-client-id")
	assert.Contains(t, githubURL, "state=test-state-git")
}

func TestOAuthService_GetAuthURL_NoCredentials(t *testing.T) {
	cfg := &config.Config{} // empty credentials
	svc := service.NewOAuthService(cfg, nil)

	_, err := svc.GetGoogleAuthURL("", "state")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no google OAuth credentials configured")

	_, err = svc.GetGitHubAuthURL("", "state")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no github OAuth credentials configured")
}
