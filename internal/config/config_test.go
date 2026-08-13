package config

import (
	"os"
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
		{"Env set to zero duration returns default value", "0s", 10 * time.Minute, 10 * time.Minute},
		{"Env set to negative duration returns default value", "-5m", 10 * time.Minute, 10 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const key = "TEST_ENV_DURATION"
			setOrUnsetEnv(t, key, tt.envValue)
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
		minVal       string
		maxVal       string
		lifetimeVal  string
		idleVal      string
		expectedMin  int
		expectedMax  int
		expectedLife time.Duration
		expectedIdle time.Duration
	}{
		{"Default pooling values are loaded when env variables are not set", "", "", "", "", 2, 10, 1 * time.Hour, 10 * time.Minute},
		{"Custom pooling values are loaded when env variables are set", "5", "25", "45m", "5m", 5, 25, 45 * time.Minute, 5 * time.Minute},
		{"Invalid min/max values fall back to defaults", "abc", "xyz", "", "", 2, 10, 1 * time.Hour, 10 * time.Minute},
		{"Zero min/max values fall back to defaults", "0", "0", "", "", 2, 10, 1 * time.Hour, 10 * time.Minute},
		{"Negative min/max values fall back to defaults", "-5", "-3", "", "", 2, 10, 1 * time.Hour, 10 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setOrUnsetEnv(t, "DB_POOL_MIN", tt.minVal)
			setOrUnsetEnv(t, "DB_POOL_MAX", tt.maxVal)
			setOrUnsetEnv(t, "DB_CONN_MAX_LIFETIME", tt.lifetimeVal)
			setOrUnsetEnv(t, "DB_CONN_MAX_IDLE_TIME", tt.idleVal)

			cfg := LoadConfig()
			assert.Equal(t, tt.expectedMin, cfg.Database.PoolMin)
			assert.Equal(t, tt.expectedMax, cfg.Database.PoolMax)
			assert.Equal(t, tt.expectedLife, cfg.Database.ConnMaxLifetime)
			assert.Equal(t, tt.expectedIdle, cfg.Database.ConnMaxIdleTime)
		})
	}
}

func TestLoadConfigDatabasePoolingMaxIdleTime(t *testing.T) {
	// Regression: an unset DB_POOL_MIN/DB_POOL_MAX must never collapse
	// to zero (unbounded) connections when the JSON/config source is
	// missing or malformed.
	t.Setenv("ENCRYPTION_KEY", "unique-secret-key-for-testing-purposes")
	t.Setenv("JWT_SECRET", "super-secret-key-that-is-at-least-32-bytes-long")
	t.Setenv("JWT_REFRESH_SECRET", "super-secret-refresh-key-that-is-at-least-32-bytes-long")

	setOrUnsetEnv(t, "DB_POOL_MIN", "")
	setOrUnsetEnv(t, "DB_POOL_MAX", "")
	cfg := LoadConfig()
	assert.Greater(t, cfg.Database.PoolMin, 0)
	assert.Greater(t, cfg.Database.PoolMax, 0)
}

func setOrUnsetEnv(t *testing.T, key, value string) {
	t.Helper()
	if value != "" {
		t.Setenv(key, value)
	} else {
		orig, ok := os.LookupEnv(key)
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("failed to unset env var %s: %v", key, err)
		}
		if ok {
			t.Cleanup(func() {
				if err := os.Setenv(key, orig); err != nil {
					t.Fatalf("failed to restore env var %s: %v", key, err)
				}
			})
		}
	}
}
