package config

import (
	"strconv"
	"strings"
	"time"
)

// TracingConfig controls OpenTelemetry distributed tracing (issue #189).
type TracingConfig struct {
	Enabled       bool
	Endpoint      string        // OTLP/HTTP collector host:port (no scheme)
	ServiceName   string
	SamplingRatio float64       // 0..1, share of requests to sample
	ExportTimeout time.Duration // per-batch export deadline
}

// DefaultTracingFromEnv builds a TracingConfig from TRACING_ENABLED,
// TRACING_ENDPOINT, TRACING_SERVICE_NAME and TRACING_SAMPLING_RATIO.
func DefaultTracingFromEnv(getenv func(string) string, getenvDuration func(string, time.Duration) time.Duration) TracingConfig {
	endpoint := getenv("TRACING_ENDPOINT")
	if endpoint == "" {
		endpoint = "localhost:4318"
	}
	return TracingConfig{
		Enabled:       getenv("TRACING_ENABLED") == "true",
		Endpoint:      endpoint,
		ServiceName:   getenv("TRACING_SERVICE_NAME"),
		SamplingRatio: getenvAsFloat(getenv("TRACING_SAMPLING_RATIO"), 1.0),
		ExportTimeout: getenvDuration("TRACING_EXPORT_TIMEOUT", 10*time.Second),
	}
}

func getenvAsFloat(raw string, fallback float64) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return fallback
	}
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}
