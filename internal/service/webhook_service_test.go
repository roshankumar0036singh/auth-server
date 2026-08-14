package service_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

type receivedDelivery struct {
	signature string
	event     string
	rawBody   []byte
	body      map[string]interface{}
}

// webhookTestSink collects deliveries from a stub receiver.
type webhookTestSink struct {
	mu   sync.Mutex
	got  []receivedDelivery
	code int
}

func (w *webhookTestSink) handler() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var env map[string]interface{}
		_ = json.Unmarshal(raw, &env)
		rawCopy := append([]byte(nil), raw...)
		w.mu.Lock()
		w.got = append(w.got, receivedDelivery{
			signature: r.Header.Get("X-Webhook-Signature"),
			event:     r.Header.Get("X-Webhook-Event"),
			rawBody:   rawCopy,
			body:      env,
		})
		w.mu.Unlock()
		rw.WriteHeader(w.code)
	}
}

func (w *webhookTestSink) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.got)
}

func webhookTestService(t *testing.T, sink *webhookTestSink) (*service.WebhookService, *repository.WebhookRepository, string) {
	_, db, _ := testutils.SetupIntegrationTest(t)
	repo := repository.NewWebhookRepository(db)
	ws := service.NewWebhookService(&config.Config{Webhook: config.WebhookConfig{Workers: 2, QueueSize: 10}}, repo)

	secret := "super-secret-key"
	wh := &models.Webhook{
		OwnerID:  "admin-1",
		URL:      sinkURL(sink),
		Secret:   secret,
		Events:   []string{"user.registered", "account.locked"},
		IsActive: true,
	}
	require.NoError(t, repo.Create(wh))
	t.Cleanup(ws.Close)
	return ws, repo, secret
}

func sinkURL(sink *webhookTestSink) string {
	srv := httptest.NewServer(sink.handler())
	return srv.URL
}

func TestWebhookDeliversSignedPayload(t *testing.T) {
	sink := &webhookTestSink{code: http.StatusOK}
	ws, _, secret := webhookTestService(t, sink)

	ws.Dispatch(t.Context(), "user.registered", map[string]interface{}{"userID": "u1", "email": "a@b.c"})

	require.Eventually(t, func() bool { return sink.count() == 1 }, 3*time.Second, 20*time.Millisecond)

	sink.mu.Lock()
	got := sink.got[0]
	sink.mu.Unlock()

	// signature must verify against the shared secret
	require.True(t, strings.HasPrefix(got.signature, "sha256="), "signature header present")
	sigHex := strings.TrimPrefix(got.signature, "sha256=")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(got.rawBody)
	expected := hex.EncodeToString(mac.Sum(nil))
	assert.Equal(t, expected, sigHex)

	assert.Equal(t, "user.registered", got.event)
	assert.Equal(t, "user.registered", got.body["event"])
	payload := got.body["payload"].(map[string]interface{})
	assert.Equal(t, "u1", payload["userID"])
}

func TestWebhookSkipsUnsubscribedEvents(t *testing.T) {
	sink := &webhookTestSink{code: http.StatusOK}
	ws, _, _ := webhookTestService(t, sink)

	ws.Dispatch(t.Context(), "password.changed", nil)
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, 0, sink.count())
}

func TestWebhookWildcardReceivesEverything(t *testing.T) {
	sink := &webhookTestSink{code: http.StatusOK}
	_, db, _ := testutils.SetupIntegrationTest(t)
	repo := repository.NewWebhookRepository(db)
	ws := service.NewWebhookService(&config.Config{Webhook: config.WebhookConfig{Workers: 2, QueueSize: 10}}, repo)
	t.Cleanup(ws.Close)

	wh := &models.Webhook{OwnerID: "admin-1", URL: sinkURL(sink), Secret: "s", Events: []string{"*"}, IsActive: true}
	require.NoError(t, repo.Create(wh))

	ws.Dispatch(t.Context(), "account.locked", nil)
	require.Eventually(t, func() bool { return sink.count() == 1 }, 3*time.Second, 20*time.Millisecond)
}

func TestWebhookRetriesTransientFailures(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, db, _ := testutils.SetupIntegrationTest(t)
	repo := repository.NewWebhookRepository(db)
	ws := service.NewWebhookService(&config.Config{Webhook: config.WebhookConfig{Workers: 1, QueueSize: 4}}, repo)
	t.Cleanup(ws.Close)

	wh := &models.Webhook{OwnerID: "a", URL: srv.URL, Secret: "s", Events: []string{"*"}, IsActive: true}
	require.NoError(t, repo.Create(wh))

	ws.Dispatch(t.Context(), "user.registered", nil)
	require.Eventually(t, func() bool { return atomic.LoadInt32(&attempts) >= 3 }, 6*time.Second, 50*time.Millisecond)
	assert.Equal(t, int32(3), atomic.LoadInt32(&attempts))
}

func TestWebhookEventNameMapping(t *testing.T) {
	assert.Equal(t, "user.registered", service.WebhookEventName("USER_REGISTERED"))
	assert.Equal(t, "user.registered", service.WebhookEventName("USER_REGISTERED_OAUTH"))
	assert.Equal(t, "user.deleted", service.WebhookEventName("ACCOUNT_DELETED"))
	assert.Equal(t, "account.locked", service.WebhookEventName("ACCOUNT_LOCKED"))
	assert.Equal(t, "password.changed", service.WebhookEventName("PASSWORD_CHANGED"))
	assert.Equal(t, "USER_LOGIN_SUCCESS", service.WebhookEventName("USER_LOGIN_SUCCESS"))
}
