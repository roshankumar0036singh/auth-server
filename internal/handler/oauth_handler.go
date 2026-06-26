package handler

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
)

const errTmpl = "error.html"

type OAuthHandler struct {
	oauthProviderService *service.OAuthProviderService
	userRepo             *repository.UserRepository
}

func NewOAuthHandler(oauthProviderService *service.OAuthProviderService, userRepo *repository.UserRepository) *OAuthHandler {
	if userRepo == nil {
		panic("oauth handler requires user repository")
	}

	return &OAuthHandler{
		oauthProviderService: oauthProviderService,
		userRepo:             userRepo,
	}
}

func (h *OAuthHandler) getAndValidateClient(c *gin.Context, clientID, redirectURI, responseType string) (*models.OAuthClient, bool) {
	if clientID == "" || redirectURI == "" || responseType == "" {
		c.HTML(http.StatusBadRequest, errTmpl, gin.H{"error": "Missing required parameters"})
		return nil, false
	}
	if responseType != "code" {
		c.HTML(http.StatusBadRequest, errTmpl, gin.H{"error": "Unsupported response_type. Only 'code' is supported"})
		return nil, false
	}
	client, err := h.oauthProviderService.GetPublicClient(clientID)
	if err != nil {
		c.HTML(http.StatusBadRequest, errTmpl, gin.H{"error": "Invalid client_id"})
		return nil, false
	}
	if err := h.oauthProviderService.ValidateRedirectURI(client, redirectURI); err != nil {
		c.HTML(http.StatusBadRequest, errTmpl, gin.H{"error": "Invalid redirect_uri"})
		return nil, false
	}
	return client, true
}

// Authorize handles the initial authorization request
// @Summary Authorize OAuth client
// @Tags oauth
// @Produce html
// @Param client_id query string true "Client ID"
// @Param redirect_uri query string true "Redirect URI"
// @Param response_type query string true "Response Type (code)"
// @Param scope query string false "Scopes"
// @Param state query string false "State"
// @Param code_challenge query string false "PKCE code challenge (base64url-encoded SHA256 hash)"
// @Param code_challenge_method query string false "PKCE code challenge method (S256 or plain)"
// @Success 302 "Redirect" @header Location {string} "Redirect URL with code or error"
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 401 {object} ErrorResponse "Unauthorized - user must be logged in"
// @Router /oauth/authorize [get]
func (h *OAuthHandler) Authorize(c *gin.Context) {
	// Extract query parameters
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")
	if codeChallenge != "" && codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}

	client, ok := h.getAndValidateClient(c, clientID, redirectURI, responseType)
	if !ok {
		return
	}

	// Parse and validate scopes against the client's registered scopes
	scopes := service.ParseScopes(scope)
	if err := h.oauthProviderService.ValidateClientScopes(client, scopes); err != nil {
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
		// in Authorize GET:
                code, err := h.oauthProviderService.GenerateAuthorizationCode(clientID, userID.(string), redirectURI, scopes, strPtr(codeChallenge), strPtr(codeChallengeMethod))
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
		"ClientName":          client.Name,
		"ClientID":            clientID,
		"RedirectURI":         redirectURI,
		"Scope":               scope,
		"Scopes":              scopeDescriptions,
		"State":               state,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
	})
}

// AuthorizePost handles the consent form submission
// @Summary OAuth Authorization Consent
// @Description User approves or denies the OAuth authorization request
// @Tags OAuth Provider
// @Accept  x-www-form-urlencoded
// @Produce json
// @Param   client_id     formData string true  "OAuth Client ID"
// @Param   redirect_uri  formData string true  "Redirect URI"
// @Param   response_type formData string true  "Response type (code)"
// @Param   scope         formData string false "Requested scopes (space separated)"
// @Param   state         formData string false "OAuth state parameter"
// @Param   action        formData string true  "Consent action (approve/deny)"
// @Success 302 "Redirect" @header Location {string} "Redirect URL with code or error"
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 401 {object} ErrorResponse "Unauthorized"
// @Router /oauth/authorize [post]
func (h *OAuthHandler) AuthorizePost(c *gin.Context) {
	action := c.PostForm("action")
	clientID := c.PostForm("client_id")
        redirectURI := c.PostForm("redirect_uri")
        scope := c.PostForm("scope")
	state := c.PostForm("state")
        codeChallenge := c.PostForm("code_challenge")
        codeChallengeMethod := c.PostForm("code_challenge_method")

	if codeChallenge != "" && codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}

	// Validate the client and that the redirect_uri is registered BEFORE any
	// redirect. The redirect helpers send the browser to redirectURI, so an
	// unvalidated value here (including on the deny path) would be an open
	// redirect / code-exfiltration vector.
	client, err := h.oauthProviderService.GetPublicClient(clientID)
	if err != nil {
		c.HTML(http.StatusBadRequest, errTmpl, gin.H{
			"error": "Invalid client_id",
		})
		return
	}
	if err := h.oauthProviderService.ValidateRedirectURI(client, redirectURI); err != nil {
		c.HTML(http.StatusBadRequest, errTmpl, gin.H{
			"error": "Invalid redirect_uri",
		})
		return
	}

	// Check if user denied (safe to redirect now that redirect_uri is trusted)
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

	// Parse and validate scopes against the client's registered scopes so a
	// tampered consent POST cannot escalate to scopes the client never had.
	scopes := service.ParseScopes(scope)
	if err := h.oauthProviderService.ValidateClientScopes(client, scopes); err != nil {
		redirectError(c, redirectURI, "invalid_scope", err.Error(), state)
		return
	}

	// Save consent
	if err := h.oauthProviderService.SaveConsent(userID.(string), clientID, scopes); err != nil {
		redirectError(c, redirectURI, "server_error", "Failed to save consent", state)
		return
	}

	// Generate authorization code
        code, err := h.oauthProviderService.GenerateAuthorizationCode(clientID, userID.(string), redirectURI, scopes, strPtr(codeChallenge), strPtr(codeChallengeMethod))
	if err != nil {
		redirectError(c, redirectURI, "server_error", "Failed to generate authorization code", state)
		return
	}

	// Redirect back to client with code
	redirectWithCode(c, redirectURI, code, state)
}

// Token handles the token exchange
// @Summary OAuth Token Exchange
// @Description Exchanges authorization code for access token. Public clients must provide code_verifier for PKCE validation.
// @Tags OAuth Provider
// @Accept  x-www-form-urlencoded
// @Produce json
// @Param   grant_type    formData string true  "Grant type (authorization_code)"
// @Param   code          formData string true  "Authorization code"
// @Param   redirect_uri  formData string true  "Redirect URI"
// @Param   client_id     formData string true  "OAuth Client ID"
// @Param   client_secret formData string true  "OAuth Client Secret"
// @Param   code_verifier formData string false "PKCE code verifier (required for public clients)"
// @Success 200 {object} TokenResponse "Access token response"
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 401 {object} ErrorResponse "Invalid client credentials"
// @Router /oauth/token [post]
func (h *OAuthHandler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	code := c.PostForm("code")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	redirectURI := c.PostForm("redirect_uri")
        codeVerifier := c.PostForm("code_verifier")

	// Validate grant type
	if grantType != "authorization_code" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unsupported_grant_type",
			"code":  "UNSUPPORTED_GRANT_TYPE",
		})
		return
	}

	// Validate client credentials
	client, err := h.oauthProviderService.ResolveClientForToken(clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_client",
			"code":  "INVALID_CLIENT",
		})
		return
	}

	// Public clients MUST use PKCE — reject if no verifier was sent at all,
	// independent of whether the stored auth code happens to have a challenge.
	if client.IsPublic && codeVerifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "code_verifier is required for public clients",
			"code":              "INVALID_REQUEST",
		})
		return
	}

	// Exchange code for token
	accessToken, err := h.oauthProviderService.ExchangeCodeForToken(code, clientID, redirectURI, codeVerifier, client.IsPublic)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid_grant",
			"code":  "INVALID_GRANT",
		})
		return
	}

	// Return access token
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken.RawToken,
		"token_type":   "Bearer",
		"expires_in":   3600, // 1 hour
		"scope":        strings.Join(accessToken.Scopes, " "),
	})
}

// UserInfo returns user information based on the access token
// @Summary OAuth User Info
// @Description Returns user profile information for the provided access token
// @Tags OAuth Provider
// @Accept  json
// @Produce json
// @Param   Authorization  header  string  true  "Bearer {access_token}"
// @Success 200 {object} UserInfoResponse "User profile information"
// @Failure 401 {object} ErrorResponse "Invalid or expired token"
// @Failure 404 {object} ErrorResponse "User not found"
// @Router /oauth/userinfo [get]
func (h *OAuthHandler) UserInfo(c *gin.Context) {
	token, err := extractBearerToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Validate token
	accessToken, err := h.oauthProviderService.ValidateAccessToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userRepo.FindByID(accessToken.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user_not_found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_fetch_user"})
		return
	}

	response := buildUserInfoResponse(user, accessToken)
	c.JSON(http.StatusOK, response)
}

func extractBearerToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", errors.New("missing_token")
	}

	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:], nil
	}
	return "", errors.New("invalid_token_format")
}

func buildUserInfoResponse(user *models.User, accessToken *models.OAuthAccessToken) gin.H {
	response := gin.H{
		"sub":    accessToken.UserID,
		"scopes": accessToken.Scopes,
	}

	if slices.Contains(accessToken.Scopes, "read:profile") {
		name := strings.TrimSpace(user.FirstName + " " + user.LastName)
		if name != "" {
			response["name"] = name
		}
		if user.FirstName != "" {
			response["given_name"] = user.FirstName
		}
		if user.LastName != "" {
			response["family_name"] = user.LastName
		}
		if user.ProfileImage != "" {
			response["picture"] = user.ProfileImage
		}
	}

	if slices.Contains(accessToken.Scopes, "read:email") {
		if user.Email != "" {
			response["email"] = user.Email
		}
		response["email_verified"] = user.EmailVerified
	}

	return response
}

func isSafeRedirectURI(u *url.URL) bool {
	scheme := strings.ToLower(u.Scheme)
	// Use an allowlist for secure redirect URI schemes
	return scheme == "http" || scheme == "https"
}

func redirectWithCode(c *gin.Context, redirectURI, code, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil || !isSafeRedirectURI(u) {
		c.HTML(http.StatusBadRequest, errTmpl, gin.H{"error": "Invalid or unsafe redirect_uri format"})
		return
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

func redirectError(c *gin.Context, redirectURI, errorCode, errorDesc, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil || !isSafeRedirectURI(u) {
		c.HTML(http.StatusBadRequest, errTmpl, gin.H{"error": "Invalid or unsafe redirect_uri format"})
		return
	}
	q := u.Query()
	q.Set("error", errorCode)
	q.Set("error_description", errorDesc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

// ErrorResponse represents the standard error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// TokenResponse represents the OAuth token exchange response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// UserInfoResponse represents the OAuth user info response
type UserInfoResponse struct {
	Sub           string   `json:"sub"`
	Name          string   `json:"name,omitempty"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Picture       string   `json:"picture,omitempty"`
	GivenName     string   `json:"given_name,omitempty"`
	FamilyName    string   `json:"family_name,omitempty"`
	Scopes        []string `json:"scopes"`
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
