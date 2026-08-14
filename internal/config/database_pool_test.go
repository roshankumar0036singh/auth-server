package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPoolSizeSanitization(t *testing.T) {
	tests := []struct {
		name     string
		cfg      DatabaseConfig
		wantIdle int
		wantOpen int
	}{
		{"unset defaults to 25 open", DatabaseConfig{PoolMin: 0, PoolMax: 0}, 0, 25},
		{"explicit values honored", DatabaseConfig{PoolMin: 2, PoolMax: 10}, 2, 10},
		{"idle clamped to open", DatabaseConfig{PoolMin: 50, PoolMax: 10}, 10, 10},
		{"negative max uses default", DatabaseConfig{PoolMin: -1, PoolMax: -5}, 0, 25},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idle, open := tt.cfg.PoolSize()
			assert.Equal(t, tt.wantIdle, idle)
			assert.Equal(t, tt.wantOpen, open)
		})
	}
}
