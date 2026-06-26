package metrics_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"

	"github.com/roshankumar0036singh/auth-server/internal/metrics"
)

type mockSessionCounter struct {
	count int64
	err   error
}

func (m *mockSessionCounter) CountActiveSessions() (int64, error) {
	return m.count, m.err
}

func TestRegister(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()

	originalRegisterer := prometheus.DefaultRegisterer
	originalGatherer := prometheus.DefaultGatherer

	prometheus.DefaultRegisterer = registry
	prometheus.DefaultGatherer = registry

	defer func() {
		prometheus.DefaultRegisterer = originalRegisterer
		prometheus.DefaultGatherer = originalGatherer
	}()

	metrics.Register(&mockSessionCounter{count: 5})

	metricFamilies, err := registry.Gather()

	assert.NoError(t, err)
	assert.NotEmpty(t, metricFamilies)

	expectedMetrics := map[string]bool{
		"auth_login_success_total": false,
		"auth_login_failure_total": false,
		"auth_active_sessions":     false,
	}

	for _, mf := range metricFamilies {
		if _, ok := expectedMetrics[mf.GetName()]; ok {
			expectedMetrics[mf.GetName()] = true
		}
	}

	for name, found := range expectedMetrics {
		assert.True(t, found, "metric %s should be registered", name)
	}
}

func TestHTTPMetrics(t *testing.T) {
    metrics.HTTPRequestsTotal.
        WithLabelValues("GET", "/test", "200").
        Inc()

    metrics.AuthHTTPRequestDuration.
        WithLabelValues("GET", "/test").
        Observe(0.1)
}