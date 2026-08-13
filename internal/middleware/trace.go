package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/roshankumar0036singh/auth-server/internal/tracing"
)

// TraceMiddleware wraps the handler in an OpenTelemetry HTTP span honoring
// the W3C traceparent header (issue #189). When tracing is disabled it is a
// no-op passthrough.
func TraceMiddleware(handler http.Handler) http.Handler {
	return otelhttp.NewHandler(handler, "http.request",
		otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)
}

// ginTraceResponse exposes the trace IDs on the gin response so logs and
// error bodies can include them.
type traceIDWriter struct {
	gin.ResponseWriter
}

// TraceIDFromGin returns trace/span IDs from the request context.
func TraceIDFromGin(c *gin.Context) (traceID, spanID string) {
	return tracing.SpanIDFromContext(c.Request.Context())
}
