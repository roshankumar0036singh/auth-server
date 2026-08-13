package service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

func TestDisposableEmailBlocklist(t *testing.T) {
	svc := service.NewDisposableEmailService()
	assert.True(t, svc.IsDisposable("someone@mailinator.com"))
	assert.True(t, svc.IsDisposable("user@10minutemail.com"))
	assert.False(t, svc.IsDisposable("real@example.com"))
	assert.False(t, svc.IsDisposable("no-at-sign"))
	assert.True(t, svc.IsDisposable("UPper@10MinutEmail.com"), "matching is case-insensitive")

	// dynamic update
	svc.ReplaceBlocklist([]string{"burner.io", "also-burner.io"})
	assert.True(t, svc.IsDisposable("x@burner.io"))
	assert.False(t, svc.IsDisposable("x@mailinator.com"))
}

func TestRegisterRejectsDisposableEmail(t *testing.T) {
	authService, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	_, err := authService.Register(&dto.RegisterRequest{
		Email:    "spammer@yopmail.com",
		Password: "StrongPass123!",
	})
	assert.ErrorIs(t, err, service.ErrDisposableEmail)

	u, err := authService.Register(&dto.RegisterRequest{
		Email:    "normal@example.com",
		Password: "StrongPass123!",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, u.ID)
}
