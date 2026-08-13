package service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

func TestDeviceFingerprintService(t *testing.T) {
	authService, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	_, err := authService.Register(&dto.RegisterRequest{
		Email:     "dev-alert@example.com",
		Password:  "StrongPass123!",
		FirstName: "Dev",
		LastName:  "Alert",
	})
	require.NoError(t, err)

	// First login from device A: alert email sent + fingerprint recorded
	testutils.LastMockEmail.LastEmail = nil
	_, err = authService.Login(&dto.LoginRequest{
		Email:    "dev-alert@example.com",
		Password: "StrongPass123!",
	}, "203.0.113.7", "Mozilla/5.0 (first-device)")
	require.NoError(t, err)
	assert.Equal(t, "dev-alert@example.com", testutils.LastMockEmail.LastEmail["new_device"])

	// Same device again: no new alert
	testutils.LastMockEmail.LastEmail = nil
	_, err = authService.Login(&dto.LoginRequest{
		Email:    "dev-alert@example.com",
		Password: "StrongPass123!",
	}, "203.0.113.7", "Mozilla/5.0 (first-device)")
	require.NoError(t, err)
	assert.Equal(t, "", testutils.LastMockEmail.LastEmail["new_device"])

	// Same UA, different subnet: alert fires again
	testutils.LastMockEmail.LastEmail = nil
	_, err = authService.Login(&dto.LoginRequest{
		Email:    "dev-alert@example.com",
		Password: "StrongPass123!",
	}, "198.51.100.9", "Mozilla/5.0 (first-device)")
	require.NoError(t, err)
	assert.Equal(t, "dev-alert@example.com", testutils.LastMockEmail.LastEmail["new_device"])
}

func TestIPSubnet(t *testing.T) {
	assert.Equal(t, "203.0.113.0/24", service.IPSubnetForTest("203.0.113.7"))
	assert.Equal(t, "198.51.100.0/24", service.IPSubnetForTest("198.51.100.9"))
	assert.Equal(t, "2001:db8::/64", service.IPSubnetForTest("2001:db8::1"))
	assert.Equal(t, "0.0.0.0/0", service.IPSubnetForTest("not-an-ip"))
}
