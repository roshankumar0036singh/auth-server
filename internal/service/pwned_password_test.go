package service_test

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

// pwnedStubServer serves a k-Anonymity range response listing `breached` and
// omitting `safe`.
func pwnedStubServer(t *testing.T, breached, safe string) *httptest.Server {
	t.Helper()
	hash := func(pw string) string {
		sum := sha1.Sum([]byte(pw))
		return strings.ToUpper(hex.EncodeToString(sum[:]))
	}
	bDigest := hash(breached)
	_ = hash(safe)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s:3\nD034F:2\n", bDigest[5:])
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPwnedPasswordCheck_KAnonymity(t *testing.T) {
	breached, safe := "P@ssw0rd!", "Tr0ub4dor&3-Pass"
	srv := pwnedStubServer(t, breached, safe)

	check := &service.PwnedPasswordCheck{Endpoint: srv.URL + "/range/"}
	old := service.HTTPClientForPwned
	service.HTTPClientForPwned = srv.Client()
	defer func() { service.HTTPClientForPwned = old }()

	hit, err := check.Check(breached)
	require.NoError(t, err)
	assert.True(t, hit)

	miss, err := check.Check(safe)
	require.NoError(t, err)
	assert.False(t, miss)
}

func TestRegisterRejectsBreachedPassword(t *testing.T) {
	_, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	breached := "P@ssw0rd!"
	safe := "Tr0ub4dor&3-Pass"
	srv := pwnedStubServer(t, breached, safe)
	service.HTTPClientForPwned = srv.Client()
	t.Cleanup(func() { service.HTTPClientForPwned = http.DefaultClient })

	_, db, _ := testutils.SetupIntegrationTest(t) // reset db
	_ = db

	// build an AuthService wired with the stub checker
	authService := testutils.BuildAuthServiceWithPwned(t, &service.PwnedPasswordCheck{Endpoint: srv.URL + "/range/"})

	_, err := authService.Register(&dto.RegisterRequest{
		Email:    "pwned@example.com",
		Password: breached,
	})
	assert.ErrorIs(t, err, service.ErrBreachedPassword)

	_, err = authService.Register(&dto.RegisterRequest{
		Email:    "safe@example.com",
		Password: safe,
	})
	assert.NoError(t, err)
}