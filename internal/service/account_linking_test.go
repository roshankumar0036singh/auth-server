package service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

func TestOAuthAccountLinking(t *testing.T) {
	authService, db, _ := testutils.SetupIntegrationTest(t)

	// first provider creates the user + identity
	resp, err := authService.LoginWithOAuth("link@example.com", "google-1", "Ann", "One", "google", "1.2.3.4", "ua")
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)

	userID := userIDFrom(resp)
	accounts, err := authService.ListLinkedOAuthAccounts(userID)
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	assert.Equal(t, "google", accounts[0].Provider)

	// second provider links to the SAME user (issue #89)
	resp2, err := authService.LoginWithOAuth("link@example.com", "github-9", "Ann", "One", "github", "1.2.3.5", "ua")
	require.NoError(t, err)
	assert.Equal(t, userID, userIDFrom(resp2))

	accounts, err = authService.ListLinkedOAuthAccounts(userID)
	require.NoError(t, err)
	require.Len(t, accounts, 2)

	// duplicate google login still works and does not duplicate rows
	_, err = authService.LoginWithOAuth("link@example.com", "google-1", "Ann", "One", "google", "1.2.3.6", "ua")
	require.NoError(t, err)
	accounts, err = authService.ListLinkedOAuthAccounts(userID)
	require.NoError(t, err)
	require.Len(t, accounts, 2)

	// unlink github; last identity cannot be removed
	require.NoError(t, authService.UnlinkOAuthAccount(userID, "github"))
	require.Error(t, authService.UnlinkOAuthAccount(userID, "google"))

	// github identity now logs into the account again via the table
	resp3, err := authService.LoginWithOAuth("link@example.com", "github-9", "Ann", "One", "github", "1.2.3.7", "ua")
	require.NoError(t, err)
	assert.Equal(t, userID, userIDFrom(resp3))

	_ = db
}

func TestOAuthLinkingRequiresVerifiedEmail(t *testing.T) {
	authService, db, _ := testutils.SetupIntegrationTest(t)

	// local register leaves the email unverified → linking must fail
	user, err := authService.Register(&dto.RegisterRequest{Email: "local@example.com", Password: "StrongPass123!"})
	require.NoError(t, err)

	_, err = authService.LoginWithOAuth("local@example.com", "google-2", "Local", "User", "google", "9.9.9.9", "ua")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify your email")

	// verify the email and retry → link succeeds, same user
	require.NoError(t, db.Model(user).Update("email_verified", true).Error)
	resp, err := authService.LoginWithOAuth("local@example.com", "google-2", "Local", "User", "google", "9.9.9.10", "ua")
	require.NoError(t, err)
	assert.Equal(t, user.ID, userIDFrom(resp))
}

func userIDFrom(resp *dto.LoginResponse) string {
	switch u := resp.User.(type) {
	case *models.PublicUser:
		return u.ID
	case map[string]interface{}:
		id, _ := u["id"].(string)
		return id
	}
	return ""
}
