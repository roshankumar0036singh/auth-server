package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"

	"github.com/roshankumar0036singh/auth-server/internal/metrics"
	"github.com/roshankumar0036singh/auth-server/internal/middleware"
)

func TestPrometheusMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const (
		method = http.MethodGet
		path   = "/test-prometheus-middleware"
		status = "200"
	)

	before := testutil.ToFloat64(
		metrics.HTTPRequestsTotal.WithLabelValues(
			method,
			path,
			status,
		),
	)

	router := gin.New()
	router.Use(middleware.PrometheusMiddleware())

	router.GET(path, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	after := testutil.ToFloat64(
		metrics.HTTPRequestsTotal.WithLabelValues(
			method,
			path,
			status,
		),
	)

	assert.Equal(t, before+1, after)
}

func TestPrometheusMiddleware_UnmatchedRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const (
		method = http.MethodGet
		path   = "unmatched_route"
		status = "404"
	)

	before := testutil.ToFloat64(
		metrics.HTTPRequestsTotal.WithLabelValues(
			method,
			path,
			status,
		),
	)

	router := gin.New()
	router.Use(middleware.PrometheusMiddleware())

	req := httptest.NewRequest(http.MethodGet, "/does-not-exist-prometheus-test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	after := testutil.ToFloat64(
		metrics.HTTPRequestsTotal.WithLabelValues(
			method,
			path,
			status,
		),
	)

	assert.Equal(t, before+1, after)
}