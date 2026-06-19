package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetEnvAsDuration(t *testing.T) {
	tests := []struct {
		name       string
		envValue   string
		defaultVal time.Duration
		expected   time.Duration
	}{
		{"Env not set returns default value", "", 5 * time.Minute, 5 * time.Minute},
		{"Env set to valid duration returns parsed value", "2h30m", 5 * time.Minute, 2*time.Hour + 30*time.Minute},
		{"Env set to invalid duration returns default value", "invalid-duration", 15 * time.Minute, 15 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const key = "TEST_ENV_DURATION"
			t.Setenv(key, tt.envValue)
			val := getEnvAsDuration(key, tt.defaultVal)
			assert.Equal(t, tt.expected, val)
		})
	}
}

func TestLoadConfigDatabasePooling(t *testing.T) {
	// Set required variables to prevent LoadConfig() from calling log.Fatal
	t.Setenv("ENCRYPTION_KEY", "unique-secret-key-for-testing-purposes")
	t.Setenv("JWT_SECRET", "super-secret-key-that-is-at-least-32-bytes-long")
	t.Setenv("JWT_REFRESH_SECRET", "super-secret-refresh-key-that-is-at-least-32-bytes-long")

	tests := []struct {
		name         string
		lifetimeVal  string
		idleVal      string
		expectedLife time.Duration
		expectedIdle time.Duration
	}{
		{"Default pooling values are loaded when env variables are not set", "", "", 1 * time.Hour, 10 * time.Minute},
		{"Custom pooling values are loaded when env variables are set", "45m", "5m", 45 * time.Minute, 5 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DB_CONN_MAX_LIFETIME", tt.lifetimeVal)
			t.Setenv("DB_CONN_MAX_IDLE_TIME", tt.idleVal)

			cfg := LoadConfig()
			assert.Equal(t, tt.expectedLife, cfg.Database.ConnMaxLifetime)
			assert.Equal(t, tt.expectedIdle, cfg.Database.ConnMaxIdleTime)
		})
	}
}
