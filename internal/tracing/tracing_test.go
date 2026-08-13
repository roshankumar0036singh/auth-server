package tracing_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/middleware"
	"github.com/roshankumar0036singh/auth-server/internal/tracing"
)

func TestInitTracerDisabled(t *testing.T) {
	cfg := &config.Config{Tracing: config.TracingConfig{Enabled: false}}
	shutdown, err := tracing.InitTracer(cfg)
	require.NoError(t, err)
	require.NoError(t, shutdown(context.Background()))
}

func TestInitTracerEnabledWithDummyExporter(t *testing.T) {
	cfg := &config.Config{Tracing: config.TracingConfig{
		Enabled:    true,
		Endpoint:   "127.0.0.1:1", // nothing listening; exporter setup must still succeed
		ServiceName: "auth-server-test",
	}}
	shutdown, err := tracing.InitTracer(cfg)
	require.NoError(t, err)
	defer func() { _ = shutdown(context.Background()) }()
}

func TestSpanIDFromContextValid(t *testing.T) {
	tid, sid := tracing.SpanIDFromContext(context.Background())
	assert.Equal(t, "", tid)
	assert.Equal(t, "", sid)
}

func TestTraceMiddlewarePropagatesTraceparent(t *testing.T) {
	ctx := context.Background()
	// synthesize a child context with a traceparent header carriable carrier
	incoming := map[string][]string{"traceparent": {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}}

	handler := middleware.TraceMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx2 := otel.GetTextMapPropagator().
			Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		spanCtx := trace.SpanContextFromContext(ctx2)
		// span id of the remote parent must be seen as parent's span id
		assert.Equal(t, "00f067aa0ba902b7", spanCtx.SpanID().String())
		assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", spanCtx.TraceID().String())
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)
	for k, v := range incoming {
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}
	_ = ctx
	handler.ServeHTTP(httptest.NewRecorder(), req)
}

func TestDefaultTracingFromEnv(t *testing.T) {
	env := map[string]string{
		"TRACING_ENABLED":          "true",
		"TRACING_ENDPOINT":         "jaeger:4318",
		"TRACING_SERVICE_NAME":     "auth",
		"TRACING_SAMPLING_RATIO":   "0.5",
		"TRACING_EXPORT_TIMEOUT":   "5s",
	}
	get := func(k string) string { return env[k] }
	getDur := func(k string, d time.Duration) time.Duration {
		if v, ok := env[k]; ok {
			if d, err := time.ParseDuration(v); err == nil {
				return d
			}
		}
		return d
	}
	cfg := config.DefaultTracingFromEnv(get, getDur)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, "jaeger:4318", cfg.Endpoint)
	assert.Equal(t, "auth", cfg.ServiceName)
	assert.Equal(t, 0.5, cfg.SamplingRatio)
	assert.Equal(t, 5*time.Second, cfg.ExportTimeout)

	// clamping
	env["TRACING_SAMPLING_RATIO"] = "3.0"
	assert.Equal(t, 1.0, config.DefaultTracingFromEnv(get, getDur).SamplingRatio)
	env["TRACING_SAMPLING_RATIO"] = "-1"
	assert.Equal(t, 0.0, config.DefaultTracingFromEnv(get, getDur).SamplingRatio)
}
