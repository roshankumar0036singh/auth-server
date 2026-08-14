package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
)

// WebhookService delivers signed HTTP notifications for lifecycle events
// through an async worker pool so callers never block (issue #163).
type WebhookService struct {
	repo    *repository.WebhookRepository
	client  *http.Client
	workers int
	jobs    chan webhookJob
	mu      sync.RWMutex
	closed  bool
}

type webhookJob struct {
	webhook models.Webhook
	event   string
	payload map[string]interface{}
}

// NewWebhookService starts the dispatcher's worker pool. Call Close() on
// shutdown to drain pending deliveries.
func NewWebhookService(cfg *config.Config, repo *repository.WebhookRepository) *WebhookService {
	workers := cfg.Webhook.Workers
	if workers <= 0 {
		workers = 4
	}
	queueSize := cfg.Webhook.QueueSize
	if queueSize <= 0 {
		queueSize = 100
	}

	s := &WebhookService{
		repo:    repo,
		client:  &http.Client{Timeout: 10 * time.Second},
		workers: workers,
		jobs:    make(chan webhookJob, queueSize),
	}
	for i := 0; i < workers; i++ {
		go s.worker(i)
	}
	return s
}

func (s *WebhookService) worker(id int) {
	for job := range s.jobs {
		if err := s.deliver(job); err != nil {
			log.Printf("webhook worker %d: delivery to %s failed: %v", id, job.webhook.URL, err)
		}
	}
}

// Dispatch enqueues the event to every active webhook subscribed to it.
// Failures are non-blocking: full queues are dropped with a log line.
func (s *WebhookService) Dispatch(ctx context.Context, event string, payload map[string]interface{}) {
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return
	}

	webhooks, err := s.repo.FindAllActive()
	if err != nil {
		log.Printf("webhook: failed to load subscriptions for %s: %v", event, err)
		return
	}

	for _, wh := range webhooks {
		if !subscribesTo(wh, event) {
			continue
		}
		select {
		case s.jobs <- webhookJob{webhook: wh, event: event, payload: payload}:
		default:
			log.Printf("webhook: queue full, dropping %s → %s", event, wh.URL)
		}
	}
}

func subscribesTo(wh models.Webhook, event string) bool {
	for _, e := range wh.Events {
		if e == event || e == "*" {
			return true
		}
	}
	return false
}

// deliver POSTs a signed payload, retrying transient failures with backoff.
func (s *WebhookService) deliver(job webhookJob) error {
	body := webhookEnvelope{
		Event:     job.event,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Payload:   job.payload,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}

	sig := signPayload(job.webhook.Secret, raw)

	backoff := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}
	var lastErr error
	for attempt := 0; attempt <= len(backoff); attempt++ {
		req, err := http.NewRequest(http.MethodPost, job.webhook.URL, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Webhook-Signature", "sha256="+sig)
		req.Header.Set("X-Webhook-Event", job.event)

		resp, err := s.client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		if attempt < len(backoff) {
			time.Sleep(backoff[attempt])
		}
	}
	return lastErr
}

type webhookEnvelope struct {
	Event     string                 `json:"event"`
	Timestamp string                 `json:"timestamp"`
	Payload   map[string]interface{} `json:"payload"`
}

// WebhookEventName maps an audit action to the documented webhook event
// name, falling back to the raw action for unknown lifecycle events.
func WebhookEventName(action string) string {
	switch action {
	case "USER_REGISTERED", "USER_REGISTERED_OAUTH":
		return "user.registered"
	case "ACCOUNT_DELETED":
		return "user.deleted"
	case "ACCOUNT_LOCKED":
		return "account.locked"
	case "PASSWORD_CHANGED", "PASSWORD_RESET_SUCCESS":
		return "password.changed"
	default:
		return action
	}
}

// SignPayload computes the HMAC-SHA256 signature of a webhook body.
func SignPayload(secret string, body []byte) string {
	return signPayload(secret, body)
}

func signPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Close drains and stops the worker pool.
func (s *WebhookService) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	close(s.jobs)
}
