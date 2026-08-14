// Package geoip enriches audit/session events with a human-readable location
// (e.g. "London, UK") using a free, keyless IP-to-location API (issue #167).
//
// Lookups are fail-open: any network/parse error yields an empty location so
// login never blocks on geolocation, and results are cached by IP for 24h.
package geoip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ipAPIHandler points at the keyless ip-api.com free endpoint. Override in
// tests via Client.Endpoint.
const defaultEndpoint = "http://ip-api.com/json/%s?fields=city,countryCode,status,message"

// Location is the human-readable result of an IP lookup.
type Location struct {
	City    string
	Country string
}

// String renders "City, Country" (or just whichever part is known).
func (l Location) String() string {
	switch {
	case l.City != "" && l.Country != "":
		return l.City + ", " + l.Country
	case l.Country != "":
		return l.Country
	case l.City != "":
		return l.City
	default:
		return ""
	}
}

// Client performs and caches IP→location lookups.
type Client struct {
	Endpoint string
	Timeout  time.Duration
	HTTP     *http.Client

	// TTL controls the per-IP cache lifetime. Zero disables caching.
	TTL time.Duration

	mu    sync.Mutex
	cache map[string]cachedLocation
}

type cachedLocation struct {
	loc       Location
	expiresAt time.Time
}

// NewClient builds a fail-open geolocation client.
func NewClient() *Client {
	return &Client{
		Endpoint: defaultEndpoint,
		Timeout:  3 * time.Second,
		TTL:      24 * time.Hour,
		cache:    map[string]cachedLocation{},
	}
}

// Lookup resolves an IP to a Location. Private/reserved addresses and
// failures return an empty Location (never an error that blocks login).
func (c *Client) Lookup(ctx context.Context, ip string) Location {
	ip = normalizeIP(ip)
	if ip == "" {
		return Location{}
	}

	if c.TTL > 0 {
		c.mu.Lock()
		if hit, ok := c.cache[ip]; ok && time.Now().Before(hit.expiresAt) {
			c.mu.Unlock()
			return hit.loc
		}
		c.mu.Unlock()
	}

	loc := c.fetch(ctx, ip)
	if c.TTL > 0 && loc.String() != "" {
		c.mu.Lock()
		c.cache[ip] = cachedLocation{loc: loc, expiresAt: time.Now().Add(c.TTL)}
		c.mu.Unlock()
	}
	return loc
}

func (c *Client) fetch(ctx context.Context, ip string) Location {
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	url := fmt.Sprintf(endpoint, ip)

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: c.Timeout}
	}

	resp, err := httpClient.Get(url)
	if err != nil {
		return Location{}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Location{}
	}

	var payload struct {
		Status      string `json:"status"`
		Message     string `json:"message"`
		City        string `json:"city"`
		CountryCode string `json:"countryCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return Location{}
	}
	if payload.Status != "success" {
		return Location{}
	}
	return Location{City: payload.City, Country: payload.CountryCode}
}

// normalizeIP strips ports and brackets, rejecting private/test/reserved
// ranges (no point geolocating them).
func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	ip = strings.Trim(ip, "[]")
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() ||
		parsed.IsUnspecified() || parsed.IsMulticast() {
		return ""
	}
	return parsed.String()
}

var ErrNoLocation = errors.New("no geolocation available")
