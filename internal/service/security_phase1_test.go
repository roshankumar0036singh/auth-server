package service_test

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// testCfg mirrors the secrets used by testutils.SetupIntegrationTest so a
// TokenService built here produces tokens the integration AuthService accepts.
func testCfg(t *testing.T) *config.Config {
	priv, pub := testutils.GetTestRSAKeys(t)
	return &config.Config{
		JWT:      config.JWTConfig{PrivateKey: priv, PublicKey: pub, KeyID: "test-key"},
		Security: config.SecurityConfig{RateLimitMax: 10, EncryptionKey: "12345678901234567890123456789012"},
		App:      config.AppConfig{URL: "http://localhost"},
	}
}

func newProviderService(t *testing.T) (*service.OAuthProviderService, *repository.OAuthTokenRepository) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	t.Cleanup(func() { mr.Close() })

	tokenRepo := repository.NewOAuthTokenRepository(db)
	ps := service.NewOAuthProviderService(
		repository.NewOAuthClientRepository(db),
		repository.NewAuthorizationCodeRepository(db),
		tokenRepo,
		repository.NewUserConsentRepository(db),
		repository.NewOAuthProviderConfigRepository(db),
		service.NewTokenService(testCfg(t)),
		testCfg(t),
	)
	return ps, tokenRepo
}

// C1: an authorization code must be single-use, and replaying a consumed code
// must revoke tokens already issued to that user/client pair.
func TestExchangeCodeForToken_ReplayIsRejectedAndRevokes(t *testing.T) {
	ps, tokenRepo := newProviderService(t)

	const redirectURI = "http://localhost/callback"
	client, _, err := ps.CreateClient("c1", []string{redirectURI}, []string{"read:profile"}, "owner-1", false)
	require.NoError(t, err)

	userID := "user-1"
	code, err := ps.GenerateAuthorizationCode(client.ClientID, userID, redirectURI, []string{"read:profile"}, nil, nil)
	require.NoError(t, err)

	// First exchange succeeds.
	tok, err := ps.ExchangeCodeForToken(code, client.ClientID, redirectURI, "", false)
	require.NoError(t, err)
	require.NotNil(t, tok)

	issued, err := tokenRepo.FindByUserAndClient(userID, client.ClientID)
	require.NoError(t, err)
	require.Len(t, issued, 1)

	// Replay of the same code must fail.
	_, err = ps.ExchangeCodeForToken(code, client.ClientID, redirectURI, "", false)
	require.Error(t, err)

	// And the previously-issued token must have been revoked.
	after, err := tokenRepo.FindByUserAndClient(userID, client.ClientID)
	require.NoError(t, err)
	assert.Empty(t, after, "tokens issued from a replayed code must be revoked")
}

// C2: a client may only obtain scopes it is registered for.
func TestValidateClientScopes_RejectsUnregisteredScopes(t *testing.T) {
	ps, _ := newProviderService(t)

	client, _, err := ps.CreateClient("c2", []string{"http://localhost/cb"}, []string{"read:profile"}, "owner-2", false)
	require.NoError(t, err)

	assert.NoError(t, ps.ValidateClientScopes(client, []string{"read:profile"}))
	assert.Error(t, ps.ValidateClientScopes(client, []string{"admin:users"}),
		"client must not be allowed to escalate to a scope it was never granted")
	assert.Error(t, ps.ValidateClientScopes(client, []string{"read:profile", "write:profile"}))
}

// C4: MFA login must require the MFA-pending token from the password step, and
// the raw email must no longer be sufficient to complete login.
func TestVerifyLoginMFA_RequiresPasswordStepToken(t *testing.T) {
	authService, db, mr := testutils.SetupIntegrationTest(t)
	t.Cleanup(func() { mr.Close() })

	userRepo := repository.NewUserRepository(db)

	const (
		email    = "mfa-user@example.com"
		password = "Sup3rSecret!"
		secret   = "JBSWY3DPEHPK3PXP" // valid base32 TOTP secret
	)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	require.NoError(t, userRepo.Create(&models.User{
		Email:         email,
		PasswordHash:  string(hash),
		IsActive:      true,
		EmailVerified: true,
		MFAEnabled:    true,
		MFASecret:     secret,
	}))

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	// Bypass attempt: the old contract passed the email here. It must fail now.
	resp, err := authService.VerifyLoginMFA(email, code, "127.0.0.1", "test")
	assert.Error(t, err, "raw email must not complete MFA login")
	assert.Nil(t, resp)

	// Password step returns an MFA-pending token, no access/refresh tokens yet.
	loginResp, err := authService.Login(&dto.LoginRequest{Email: email, Password: password}, "127.0.0.1", "test")
	require.NoError(t, err)
	require.True(t, loginResp.MFARequired)
	require.NotEmpty(t, loginResp.MFAToken)
	assert.Empty(t, loginResp.AccessToken)

	// Completing MFA with that token and a valid code succeeds.
	final, err := authService.VerifyLoginMFA(loginResp.MFAToken, code, "127.0.0.1", "test")
	require.NoError(t, err)
	require.NotNil(t, final)
	assert.NotEmpty(t, final.AccessToken)
}
