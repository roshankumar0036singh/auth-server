package service_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/geoip"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

// geoStatus exposes audit metadata written on login for assertions.
func TestLoginAuditGetsLocationWhenEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","city":"London","countryCode":"GB"}`))
	}))
	defer srv.Close()

	// rebuild authService with geoip enabled via cfg — unit path: metadata helper
	cfg := &config.Config{GeoIP: config.GeoIPConfig{Enabled: true}}
	client := geoip.NewClient()
	client.Endpoint = srv.URL + "/%s"
	client.TTL = 0

	authService, _, _ := testutils.SetupIntegrationTest(t)
	_ = cfg
	_ = client

	// metadata helper is exercised through the real service; construct directly
	meta := authService.LoginMetadataForTest(client, cfg, "8.8.8.8", "ua")
	require.NotNil(t, meta)
	assert.Equal(t, "London, GB", meta["location"])

	// disabled → nil
	cfgOff := &config.Config{GeoIP: config.GeoIPConfig{Enabled: false}}
	assert.Nil(t, authService.LoginMetadataForTest(client, cfgOff, "8.8.8.8", "ua"))

	// private IP → nil even when enabled
	assert.Nil(t, authService.LoginMetadataForTest(client, cfg, "127.0.0.1", "ua"))
}

func TestRegisterWithoutGeoipStillWorks(t *testing.T) {
	authService, _, _ := testutils.SetupIntegrationTest(t)
	user, err := authService.Register(&dto.RegisterRequest{Email: "geo@example.com", Password: "StrongPass123!"})
	require.NoError(t, err)
	assert.NotEmpty(t, user.ID)
}

var _ = context.Background
