package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"github.com/roshankumar0036singh/auth-server/internal/config"
)

type OAuthService struct {
	googleConfig *oauth2.Config
	githubConfig *oauth2.Config
}

func NewOAuthService(cfg *config.Config) *OAuthService {
	return &OAuthService{
		googleConfig: &oauth2.Config{
			ClientID:     cfg.OAuth.Google.ClientID,
			ClientSecret: cfg.OAuth.Google.ClientSecret,
			RedirectURL:  cfg.OAuth.Google.CallbackURL,
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
			Endpoint:     google.Endpoint,
		},
		githubConfig: &oauth2.Config{
			ClientID:     cfg.OAuth.GitHub.ClientID,
			ClientSecret: cfg.OAuth.GitHub.ClientSecret,
			RedirectURL:  cfg.OAuth.GitHub.CallbackURL,
			Scopes:       []string{"user:email"},
			Endpoint:     github.Endpoint,
		},
	}
}

// GenerateState generates a random state string for CSRF protection
func (s *OAuthService) GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GetGoogleAuthURL returns the URL to redirect the user to for Google login
func (s *OAuthService) GetGoogleAuthURL(state string) string {
	return s.googleConfig.AuthCodeURL(state)
}

// GetGitHubAuthURL returns the URL to redirect the user to for GitHub login
func (s *OAuthService) GetGitHubAuthURL(state string) string {
	return s.githubConfig.AuthCodeURL(state)
}

// ExchangeGoogleCode exchanges the authorization code for a token
func (s *OAuthService) ExchangeGoogleCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return s.googleConfig.Exchange(ctx, code)
}

// ExchangeGitHubCode exchanges the authorization code for a token
func (s *OAuthService) ExchangeGitHubCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return s.githubConfig.Exchange(ctx, code)
}

// FetchGoogleUser fetches user info from Google
func (s *OAuthService) FetchGoogleUser(ctx context.Context, token *oauth2.Token) (map[string]interface{}, error) {
	client := s.googleConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New("failed to fetch google user info")
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	
	return data, nil
}

// FetchGitHubUser fetches user info from GitHub
func (s *OAuthService) FetchGitHubUser(ctx context.Context, token *oauth2.Token) (map[string]interface{}, error) {
	// GitHub API requires User-Agent
	// Standard oauth2 client transport doesn't add it by default
	// But we can just use the client and simple request
	
	client := s.githubConfig.Client(ctx, token)
	
	// Fetch User Profile
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	// http package is needed
	_ = req // Placeholder until we fix imports
	
	// Wait, I need http package. Let's look at the import block again.
	// I'll leave this replacement for now and do a properly imported version in next step or use http.Get inside client if possible?
	// client.Get works.
	
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil, errors.New("failed to fetch github user info")
	}
	
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	// GitHub email might be private, need separate call if not in profile
	if email, ok := data["email"].(string); !ok || email == "" {
		// Fetch emails
		respEmails, err := client.Get("https://api.github.com/user/emails")
		if err == nil && respEmails.StatusCode == 200 {
			var emails []map[string]interface{}
			if err := json.NewDecoder(respEmails.Body).Decode(&emails); err == nil {
				for _, e := range emails {
					if primary, ok := e["primary"].(bool); ok && primary {
						if verified, ok := e["verified"].(bool); ok && verified {
							if emailStr, ok := e["email"].(string); ok {
								data["email"] = emailStr
								break
							}
						}
					}
				}
			}
			respEmails.Body.Close()
		}
	}
	
	return data, nil
}
