// Package tracing wires OpenTelemetry distributed tracing (issue #189):
// W3C traceparent propagation, context-injected trace IDs for structured
// logs, and OTLP export to Jaeger/Zipkin-compatible collectors.
package tracing

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/roshankumar0036singh/auth-server/internal/config"
)

// SpanIDFromContext returns the hex trace/span IDs from a context, for
// structured log correlation. Empty when tracing is disabled.
func SpanIDFromContext(ctx context.Context) (traceID, spanID string) {
	spanCtx := trace.SpanContextFromContext(ctx)
	if !spanCtx.IsValid() {
		return "", ""
	}
	return spanCtx.TraceID().String(), spanCtx.SpanID().String()
}

// InitTracer builds the OTLP exporter and its trace provider. The returned
// shutdown func flushes spans; call it on graceful shutdown. When tracing is
// disabled it returns a no-op provider and nil shutdown.
func InitTracer(cfg *config.Config) (func(context.Context) error, error) {
	if cfg == nil || !cfg.Tracing.Enabled {
		otel.SetTextMapPropagator(propagators())
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := otlptracehttp.New(context.Background(),
		otlptracehttp.WithEndpoint(cfg.Tracing.Endpoint),
		otlptracehttp.WithTimeout(cfg.Tracing.ExportTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}

	prov := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithSampler(samplingRatio(cfg.Tracing.SamplingRatio)),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.Tracing.ServiceName),
			semconv.ServiceVersion("1.0.0"),
		)),
	)
	otel.SetTracerProvider(prov)
	otel.SetTextMapPropagator(propagators())
	log.Printf("tracing enabled: collecting %d%% of spans -> %s", int(cfg.Tracing.SamplingRatio*100), cfg.Tracing.Endpoint)

	return func(ctx context.Context) error {
		return prov.Shutdown(ctx)
	}, nil
}

func propagators() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
}

func samplingRatio(r float64) sdktrace.Sampler {
	if r <= 0 {
		return sdktrace.NeverSample()
	}
	if r >= 1 {
		return sdktrace.AlwaysSample()
	}
	return sdktrace.TraceIDRatioBased(r)
}
