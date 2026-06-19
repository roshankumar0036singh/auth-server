package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetEnvAsDuration(t *testing.T) {
	t.Run("Env not set returns default value", func(t *testing.T) {
		const key = "TEST_ENV_NOT_SET_DURATION"
		t.Setenv(key, "") // Set to empty to simulate unset/empty

		val := getEnvAsDuration(key, 5*time.Minute)
		assert.Equal(t, 5*time.Minute, val)
	})

	t.Run("Env set to valid duration returns parsed value", func(t *testing.T) {
		const key = "TEST_ENV_VALID_DURATION"
		t.Setenv(key, "2h30m")

		val := getEnvAsDuration(key, 5*time.Minute)
		assert.Equal(t, 2*time.Hour+30*time.Minute, val)
	})

	t.Run("Env set to invalid duration returns default value", func(t *testing.T) {
		const key = "TEST_ENV_INVALID_DURATION"
		t.Setenv(key, "invalid-duration")

		val := getEnvAsDuration(key, 15*time.Minute)
		assert.Equal(t, 15*time.Minute, val)
	})
}

func TestLoadConfigDatabasePooling(t *testing.T) {
	// Set required ENCRYPTION_KEY to prevent log.Fatal
	t.Setenv("ENCRYPTION_KEY", "unique-secret-key-for-testing-purposes")

	t.Run("Default pooling values are loaded when env variables are not set", func(t *testing.T) {
		// Ensure any existing env vars are cleared for this run
		t.Setenv("DB_CONN_MAX_LIFETIME", "")
		t.Setenv("DB_CONN_MAX_IDLE_TIME", "")

		cfg := LoadConfig()
		assert.Equal(t, 1*time.Hour, cfg.Database.ConnMaxLifetime)
		assert.Equal(t, 10*time.Minute, cfg.Database.ConnMaxIdleTime)
	})

	t.Run("Custom pooling values are loaded when env variables are set", func(t *testing.T) {
		t.Setenv("DB_CONN_MAX_LIFETIME", "45m")
		t.Setenv("DB_CONN_MAX_IDLE_TIME", "5m")

		cfg := LoadConfig()
		assert.Equal(t, 45*time.Minute, cfg.Database.ConnMaxLifetime)
		assert.Equal(t, 5*time.Minute, cfg.Database.ConnMaxIdleTime)
	})
}
