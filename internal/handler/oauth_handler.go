package handler

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/service"
)

type OAuthHandler struct {
	oauthProviderService *service.OAuthProviderService
	userRepo             interface{} // Will need user repository to fetch user data
}

func NewOAuthHandler(oauthProviderService *service.OAuthProviderService) *OAuthHandler {
	return &OAuthHandler{
		oauthProviderService: oauthProviderService,
	}
}

// Authorize handles the OAuth authorization request
// GET /oauth/authorize?client_id=...&redirect_uri=...&response_type=code&scope=...&state=...
func (h *OAuthHandler) Authorize(c *gin.Context) {
	// Extract query parameters
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")

	// Validate required parameters
	if clientID == "" || redirectURI == "" || responseType == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Missing required parameters",
		})
		return
	}

	// Only support authorization_code flow
	if responseType != "code" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Unsupported response_type. Only 'code' is supported",
		})
		return
	}

	// Validate client
	client, err := h.oauthProviderService.ValidateClient(clientID, "")
	if err != nil {
		// For GET request, we don't have client_secret, so we just check if client exists
		// We'll validate the secret during token exchange
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Invalid client_id",
		})
		return
	}

	// Validate redirect URI
	if err := h.oauthProviderService.ValidateRedirectURI(client, redirectURI); err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Invalid redirect_uri",
		})
		return
	}

	// Parse and validate scopes
	scopes := service.ParseScopes(scope)
	if err := h.oauthProviderService.ValidateScopes(scopes); err != nil {
		redirectError(c, redirectURI, "invalid_scope", err.Error(), state)
		return
	}

	// Check if user is authenticated
	userID, exists := c.Get("userID")
	if !exists {
		// Redirect to login with return URL
		loginURL := "/api/auth/login?return_to=" + url.QueryEscape(c.Request.URL.String())
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	// Check if user has previously consented
	hasConsent, err := h.oauthProviderService.CheckConsent(userID.(string), clientID, scopes)
	if err == nil && hasConsent {
		// User has already consented, generate code immediately
		code, err := h.oauthProviderService.GenerateAuthorizationCode(clientID, userID.(string), redirectURI, scopes)
		if err != nil {
			redirectError(c, redirectURI, "server_error", "Failed to generate authorization code", state)
			return
		}

		// Redirect back to client with code
		redirectWithCode(c, redirectURI, code, state)
		return
	}

	// Show consent screen
	scopeDescriptions := make([]string, len(scopes))
	for i, scope := range scopes {
		if desc, ok := service.ValidScopes[scope]; ok {
			scopeDescriptions[i] = desc
		} else {
			scopeDescriptions[i] = scope
		}
	}

	c.HTML(http.StatusOK, "oauth_consent.html", gin.H{
		"ClientName":   client.Name,
		"ClientID":     clientID,
		"RedirectURI":  redirectURI,
		"Scope":        scope,
		"Scopes":       scopeDescriptions,
		"State":        state,
	})
}

// AuthorizePost handles the consent form submission
// POST /oauth/authorize
func (h *OAuthHandler) AuthorizePost(c *gin.Context) {
	action := c.PostForm("action")
	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")
	scope := c.PostForm("scope")
	state := c.PostForm("state")

	// Check if user denied
	if action == "deny" {
		redirectError(c, redirectURI, "access_denied", "User denied authorization", state)
		return
	}

	// Get authenticated user
	userID, exists := c.Get("userID")
	if !exists {
		c.HTML(http.StatusUnauthorized, "error.html", gin.H{
			"error": "User not authenticated",
		})
		return
	}

	// Parse scopes
	scopes := service.ParseScopes(scope)

	// Save consent
	if err := h.oauthProviderService.SaveConsent(userID.(string), clientID, scopes); err != nil {
		redirectError(c, redirectURI, "server_error", "Failed to save consent", state)
		return
	}

	// Generate authorization code
	code, err := h.oauthProviderService.GenerateAuthorizationCode(clientID, userID.(string), redirectURI, scopes)
	if err != nil {
		redirectError(c, redirectURI, "server_error", "Failed to generate authorization code", state)
		return
	}

	// Redirect back to client with code
	redirectWithCode(c, redirectURI, code, state)
}

// Token handles the token exchange
// POST /oauth/token
func (h *OAuthHandler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	code := c.PostForm("code")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	redirectURI := c.PostForm("redirect_uri")

	// Validate grant type
	if grantType != "authorization_code" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Only authorization_code grant type is supported",
		})
		return
	}

	// Validate client credentials
	if _, err := h.oauthProviderService.ValidateClient(clientID, clientSecret); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	// Exchange code for token
	accessToken, err := h.oauthProviderService.ExchangeCodeForToken(code, clientID, redirectURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": err.Error(),
		})
		return
	}

	// Return access token
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken.Token,
		"token_type":   "Bearer",
		"expires_in":   3600, // 1 hour
		"scope":        service.ParseScopes(string(accessToken.Scopes[0])), // TODO: Join scopes properly
	})
}

// UserInfo returns user information based on the access token
// GET /oauth/userinfo
func (h *OAuthHandler) UserInfo(c *gin.Context) {
	// Extract token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "missing_token",
		})
		return
	}

	// Parse Bearer token
	var token string
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_token_format",
		})
		return
	}

	// Validate token
	accessToken, err := h.oauthProviderService.ValidateAccessToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	// TODO: Fetch user data from database based on accessToken.UserID
	// For now, return minimal info
	c.JSON(http.StatusOK, gin.H{
		"sub":    accessToken.UserID,
		"scopes": accessToken.Scopes,
	})
}

// Helper functions
func redirectWithCode(c *gin.Context, redirectURI, code, state string) {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

func redirectError(c *gin.Context, redirectURI, errorCode, errorDesc, state string) {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("error", errorCode)
	q.Set("error_description", errorDesc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}
