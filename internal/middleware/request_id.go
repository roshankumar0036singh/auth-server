package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const RequestIDKey = "RequestID"

// RequestIDMiddleware injects a unique correlation ID into each request headers and context
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Check if X-Request-ID header already exists from an external gateway
		requestID := c.GetHeader("X-Request-ID")

		// 2. If missing, generate a new unique random UUID
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// 3. Pass it down to Gin's internal context so downstream handlers/loggers can access it
		c.Set(RequestIDKey, requestID)

		// 4. Expose it in the response headers back to the client
		c.Writer.Header().Set("X-Request-ID", requestID)

		// 5. Continue processing the rest of the request lifecycle
		c.Next()
	}
}