package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/metrics"
)

func PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start).Seconds()

		path := c.FullPath()
		if path == "" {
			path = "unmatched_route"
		}

		status := strconv.Itoa(c.Writer.Status())

		metrics.HTTPRequestsTotal.WithLabelValues(c.Request.Method, path, status).Inc()
		metrics.AuthHTTPRequestDuration.WithLabelValues(c.Request.Method, path).Observe(duration)
	}
}
