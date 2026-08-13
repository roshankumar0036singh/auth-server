package service_test

import (
	"context"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

// mustFindMagicLinkToken extracts the single stored magic-link token.
func mustFindMagicLinkToken(t *testing.T, mr *miniredis.Miniredis) string {
	t.Helper()
	for _, k := range mr.Keys() {
		if strings.HasPrefix(k, "magic_link:") {
			return strings.TrimPrefix(k, "magic_link:")
		}
	}
	t.Fatal("no magic link token found in redis")
	return ""
}

func TestMagicLinkFlow(t *testing.T) {
	authService, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	ctx := context.Background()

	email := "magic@example.com"
	_, err := authService.Register(&dto.RegisterRequest{
		Email:     email,
		Password:  "StrongPass123!",
		FirstName: "Magic",
		LastName:  "Link",
	})
	require.NoError(t, err)

	// unknown email: no error, no email sent
	testutils.LastMockEmail.LastEmail = nil
	require.NoError(t, authService.RequestMagicLink(ctx, "ghost@example.com"))
	assert.NotEqual(t, "ghost@example.com", testutils.LastMockEmail.LastEmail["magic"])

	// known email: link generated and emailed
	require.NoError(t, authService.RequestMagicLink(ctx, email))
	assert.Equal(t, email, testutils.LastMockEmail.LastEmail["magic"], "magic link email should be sent")

	token := mustFindMagicLinkToken(t, mr)

	// verify: full login, no MFA challenge
	loginResp, err := authService.VerifyMagicLink(ctx, token, "203.0.113.5", "magic-test-ua")
	require.NoError(t, err)
	assert.NotEmpty(t, loginResp.AccessToken)
	assert.NotEmpty(t, loginResp.RefreshToken)

	// second redemption must fail (single-use)
	_, err = authService.VerifyMagicLink(ctx, token, "203.0.113.5", "magic-test-ua")
	assert.Error(t, err)

	// unknown token fails
	_, err = authService.VerifyMagicLink(ctx, strings.Repeat("ab", 32), "1.1.1.1", "ua")
	assert.Error(t, err)
}

func TestMagicLinkRateLimit(t *testing.T) {
	authService, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	ctx := context.Background()

	for i := 0; i < 4; i++ {
		err := authService.RequestMagicLink(ctx, "unknown@example.com")
		if i < 3 {
			assert.NoError(t, err)
		} else {
			assert.ErrorIs(t, err, service.ErrMagicLinkRateLimited)
		}
	}
}
