package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type requestIDContextKey struct{}

const maxIncomingRequestIDLength = 64

// RequestIDMiddleware assigns or propagates a correlation ID for every
// request. A caller-supplied X-Request-ID header is sanitized and kept;
// otherwise a random ID is generated. The ID is echoed back in the
// X-Request-ID response header and available to handlers via
// RequestIDFromContext, so logs and error responses can be correlated
// across services and hops.
//
// The generated format is bounded and hex-only, so it is safe to embed
// in URLs, logs, and response payloads.
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if !ValidRequestID(requestID) {
			requestID = NewRequestID()
		}

		ctx := context.WithValue(c.Request.Context(), requestIDContextKey{}, requestID)
		c.Request = c.Request.WithContext(ctx)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

// RequestIDFromContext returns the correlation ID attached by
// RequestIDMiddleware, or "" when absent.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(requestIDContextKey{}).(string); ok {
		return id
	}
	return ""
}

// ValidRequestID reports whether a caller-supplied X-Request-ID is safe
// to propagate: non-empty, bounded in length, and printable/safe chars
// only (no header/URL injection vectors).
func ValidRequestID(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > maxIncomingRequestIDLength {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

// NewRequestID generates a random 32-char hex correlation ID. If the
// CSPRNG fails (extremely rare), it falls back to a time-based value so
// the request still gets a stable, bounded ID.
func NewRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("%032x", time.Now().UnixNano())
}

// RequestIDHeaderName is the header used for propagation / echo.
const RequestIDHeaderName = "X-Request-ID"
