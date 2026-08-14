package geoip_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/geoip"
)

func TestLocationString(t *testing.T) {
	assert.Equal(t, "London, GB", geoip.Location{City: "London", Country: "GB"}.String())
	assert.Equal(t, "GB", geoip.Location{Country: "GB"}.String())
	assert.Equal(t, "", geoip.Location{}.String())
}

func TestLookupSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"success","city":"London","countryCode":"GB"}`)
	}))
	defer srv.Close()

	client := geoip.NewClient()
	client.Endpoint = srv.URL + "/%s"
	client.TTL = 0

	loc := client.Lookup(context.Background(), "8.8.8.8")
	assert.Equal(t, "London", loc.City)
	assert.Equal(t, "GB", loc.Country)
	assert.Equal(t, "London, GB", loc.String())
}

func TestLookupFailOpen(t *testing.T) {
	// endpoint that 500s → empty location, no error
	client := geoip.NewClient()
	client.Endpoint = "http://127.0.0.1:1/%s"
	client.TTL = 0
	assert.Equal(t, geoip.Location{}, client.Lookup(context.Background(), "8.8.8.8"))
}

func TestLookupSkipsPrivateIPs(t *testing.T) {
	client := geoip.NewClient()
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "::1", "not-an-ip:x"} {
		assert.Equal(t, geoip.Location{}, client.Lookup(context.Background(), ip), "ip=%s", ip)
	}
}

func TestLookupCachesByIP(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"success","city":"Berlin","countryCode":"DE"}`)
	}))
	defer srv.Close()

	client := geoip.NewClient()
	client.Endpoint = srv.URL + "/%s"

	first := client.Lookup(context.Background(), "1.1.1.1")
	second := client.Lookup(context.Background(), "1.1.1.1")
	require.Equal(t, first, second)
	assert.Equal(t, 1, calls, "second lookup must hit the cache")
}

func TestLookupRejectsFailedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"fail","message":"private range"}`)
	}))
	defer srv.Close()

	client := geoip.NewClient()
	client.Endpoint = srv.URL + "/%s"
	client.TTL = 0
	assert.Equal(t, geoip.Location{}, client.Lookup(context.Background(), "8.8.8.8"))
}
