package metrics

import (
	"log"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type SessionCounter interface {
	CountActiveSessions() (int64, error)
}

var registerOnce sync.Once

var (
	LoginSuccessTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "auth_login_success_total",
			Help: "Total number of successful user logins",
		})

	LoginFailureTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "auth_login_failure_total",
			Help: "Total number of failed user login attempts",
		})

	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	AuthHTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_http_request_duration_seconds",
			Help:    "HTTP request latency",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)
)

func Register(counter SessionCounter) {
	registerOnce.Do(func() {
		var (
			lastCount int64
			lastFetch time.Time
			mu        sync.Mutex
		)

		activeSessions := prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "auth_active_sessions",
				Help: "Current number of active user sessions",
			},
			func() float64 {
				mu.Lock()
				defer mu.Unlock()

				if time.Since(lastFetch) < 30*time.Second {
					return float64(lastCount)
				}

				count, err := counter.CountActiveSessions()
				if err != nil {
					log.Printf("metrics: failed to count active sessions: %v", err)
					return -1
				}

				lastCount = count
				lastFetch = time.Now()
				return float64(count)
			},
		)

		prometheus.MustRegister(
			LoginSuccessTotal,
			LoginFailureTotal,
			activeSessions,
			HTTPRequestsTotal,
			AuthHTTPRequestDuration,
		)
	})
}
