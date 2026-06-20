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

	before := testutil.ToFloat64(
		metrics.HTTPRequestsTotal.WithLabelValues(
			http.MethodGet,
			"/test",
			"200",
		),
	)

	router := gin.New()
	router.Use(middleware.PrometheusMiddleware())

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	after := testutil.ToFloat64(
		metrics.HTTPRequestsTotal.WithLabelValues(
			http.MethodGet,
			"/test",
			"200",
		),
	)

	assert.Equal(t, before+1, after)
}

func TestPrometheusMiddleware_UnmatchedRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)

	before := testutil.ToFloat64(
		metrics.HTTPRequestsTotal.WithLabelValues(
			http.MethodGet,
			"unmatched_route",
			"404",
		),
	)

	router := gin.New()
	router.Use(middleware.PrometheusMiddleware())

	req := httptest.NewRequest(http.MethodGet, "/does-not-exist", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	after := testutil.ToFloat64(
		metrics.HTTPRequestsTotal.WithLabelValues(
			http.MethodGet,
			"unmatched_route",
			"404",
		),
	)

	assert.Equal(t, before+1, after)
}
