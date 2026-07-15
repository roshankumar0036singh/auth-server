package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

type OAuthService struct {
	cfg          *config.Config
	providerRepo *repository.OAuthProviderConfigRepository
}

func NewOAuthService(cfg *config.Config, providerRepo *repository.OAuthProviderConfigRepository) *OAuthService {
	return &OAuthService{
		cfg:          cfg,
		providerRepo: providerRepo,
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

func (s *OAuthService) getProviderConfig(clientID, providerName string) (*oauth2.Config, error) {
	var oauthClientID, oauthClientSecret, callbackURL string
	var scopes []string
	var endpoint oauth2.Endpoint

	// 1. Try per-client config from DB first
	if clientID != "" && s.providerRepo != nil {
		providerConf, err := s.providerRepo.FindByClientAndProvider(clientID, providerName)
		if err == nil && providerConf != nil {
			decryptedSecret, err := utils.Decrypt(providerConf.ProviderClientSecret, s.cfg.Security.EncryptionKey)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt %s client secret: %w", providerName, err)
			}
			oauthClientID = providerConf.ProviderClientID
			oauthClientSecret = decryptedSecret
		}
	}

	// 2. Fall back to global .env config and set provider specifics
	switch providerName {
	case "google":
		if oauthClientID == "" {
			oauthClientID = s.cfg.OAuth.Google.ClientID
			oauthClientSecret = s.cfg.OAuth.Google.ClientSecret
		}
		callbackURL = s.cfg.OAuth.Google.CallbackURL
		scopes = []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"}
		endpoint = google.Endpoint
	case "github":
		if oauthClientID == "" {
			oauthClientID = s.cfg.OAuth.GitHub.ClientID
			oauthClientSecret = s.cfg.OAuth.GitHub.ClientSecret
		}
		callbackURL = s.cfg.OAuth.GitHub.CallbackURL
		scopes = []string{"user:email"}
		endpoint = github.Endpoint
	default:
		return nil, fmt.Errorf("unsupported provider: %s", providerName)
	}

	// 3. No credentials available at all
	if oauthClientID == "" {
		return nil, fmt.Errorf("no %s OAuth credentials configured for this client", providerName)
	}

	return &oauth2.Config{
		ClientID:     oauthClientID,
		ClientSecret: oauthClientSecret,
		RedirectURL:  callbackURL,
		Scopes:       scopes,
		Endpoint:     endpoint,
	}, nil
}

func (s *OAuthService) getGoogleConfig(clientID string) (*oauth2.Config, error) {
	return s.getProviderConfig(clientID, "google")
}

func (s *OAuthService) getGitHubConfig(clientID string) (*oauth2.Config, error) {
	return s.getProviderConfig(clientID, "github")
}

// GetGoogleAuthURL returns the URL to redirect the user to for Google login
func (s *OAuthService) GetGoogleAuthURL(clientID, state string) (string, error) {
	conf, err := s.getGoogleConfig(clientID)
	if err != nil {
		return "", err
	}
	return conf.AuthCodeURL(state), nil
}

// GetGitHubAuthURL returns the URL to redirect the user to for GitHub login
func (s *OAuthService) GetGitHubAuthURL(clientID, state string) (string, error) {
	conf, err := s.getGitHubConfig(clientID)
	if err != nil {
		return "", err
	}
	return conf.AuthCodeURL(state), nil
}

// ExchangeGoogleCode exchanges the authorization code for a token
func (s *OAuthService) ExchangeGoogleCode(ctx context.Context, clientID, code string) (*oauth2.Token, error) {
	conf, err := s.getGoogleConfig(clientID)
	if err != nil {
		return nil, err
	}
	return conf.Exchange(ctx, code)
}

// ExchangeGitHubCode exchanges the authorization code for a token
func (s *OAuthService) ExchangeGitHubCode(ctx context.Context, clientID, code string) (*oauth2.Token, error) {
	conf, err := s.getGitHubConfig(clientID)
	if err != nil {
		return nil, err
	}
	return conf.Exchange(ctx, code)
}

func (s *OAuthService) fetchUserFromProvider(ctx context.Context, conf *oauth2.Config, token *oauth2.Token, endpointURL, providerName string) (map[string]interface{}, *http.Client, error) {
	client := conf.Client(ctx, token)
	resp, err := client.Get(endpointURL)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("failed to fetch %s user info", providerName)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, nil, err
	}

	return data, client, nil
}

// FetchGoogleUser fetches user info from Google
func (s *OAuthService) FetchGoogleUser(ctx context.Context, clientID string, token *oauth2.Token) (map[string]interface{}, error) {
	conf, err := s.getGoogleConfig(clientID)
	if err != nil {
		return nil, err
	}
	data, _, err := s.fetchUserFromProvider(ctx, conf, token, "https://www.googleapis.com/oauth2/v2/userinfo", "google")
	return data, err
}

// FetchGitHubUser fetches user info from GitHub
func (s *OAuthService) FetchGitHubUser(ctx context.Context, clientID string, token *oauth2.Token) (map[string]interface{}, error) {
	conf, err := s.getGitHubConfig(clientID)
	if err != nil {
		return nil, err
	}
	data, client, err := s.fetchUserFromProvider(ctx, conf, token, "https://api.github.com/user", "github")
	if err != nil {
		return nil, err
	}

	// GitHub email might be private, need separate call if not in profile
	if email, ok := data["email"].(string); !ok || email == "" {
		if privateEmail := fetchGitHubPrivateEmail(client); privateEmail != "" {
			data["email"] = privateEmail
		}
	}

	return data, nil
}

func fetchGitHubPrivateEmail(client *http.Client) string {
	respEmails, err := client.Get("https://api.github.com/user/emails")
	if err != nil || respEmails.StatusCode != 200 {
		return ""
	}
	defer respEmails.Body.Close()

	var emails []map[string]interface{}
	if err := json.NewDecoder(respEmails.Body).Decode(&emails); err != nil {
		return ""
	}

	for _, e := range emails {
		if primary, ok := e["primary"].(bool); ok && primary {
			if verified, ok := e["verified"].(bool); ok && verified {
				if emailStr, ok := e["email"].(string); ok {
					return emailStr
				}
			}
		}
	}
	return ""
}
