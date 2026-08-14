package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
)

func webhookRouter(t *testing.T) (*gin.Engine, *handler.WebhookHandler, *repository.WebhookRepository) {
	_, db, _ := testutils.SetupIntegrationTest(t)
	gin.SetMode(gin.TestMode)
	repo := repository.NewWebhookRepository(db)
	h := handler.NewWebhookHandler(repo)

	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "admin-1"); c.Next() })
	r.GET("/webhooks", h.ListWebhooks)
	r.POST("/webhooks", h.CreateWebhook)
	r.PATCH("/webhooks/:id", h.ToggleWebhook)
	r.DELETE("/webhooks/:id", h.DeleteWebhook)
	return r, h, repo
}

func TestCreateWebhookValidation(t *testing.T) {
	r, _, _ := webhookRouter(t)

	cases := []struct {
		name string
		body string
		code int
	}{
		{"bad scheme", `{"url":"ftp://x","events":["*"]}`, 400},
		{"no host", `{"url":"https://","events":["*"]}`, 400},
		{"no events", `{"url":"https://hook.example.com/h","events":[]}`, 400},
		{"invalid event", `{"url":"https://hook.example.com/h","events":["user.banana"]}`, 400},
		{"valid", `{"url":"https://hook.example.com/h?x=1","events":["user.registered","*"]}`, 201},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/webhooks", bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			assert.Equal(t, tc.code, rec.Code, tc.name)
		})
	}
}

func TestWebhookLifecycle(t *testing.T) {
	r, _, repo := webhookRouter(t)

	// create
	req := httptest.NewRequest(http.MethodPost, "/webhooks", bytes.NewBufferString(
		`{"url":"https://hooks.example.com/reg","events":["user.registered"]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	var resp struct {
		Data struct {
			ID     string   `json:"id"`
			Events []string `json:"events"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Data.ID)
	assert.Equal(t, []string{"user.registered"}, resp.Data.Events)

	// list shows it
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/webhooks", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	var list struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))

	// toggle off then on
	for _, active := range []bool{false, true} {
		body, _ := json.Marshal(map[string]bool{"isActive": active})
		req = httptest.NewRequest(http.MethodPatch, "/webhooks/"+resp.Data.ID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}

	stored, err := repo.FindByID(resp.Data.ID)
	require.NoError(t, err)
	assert.True(t, stored.IsActive, "toggled back on")
	assert.NotEmpty(t, stored.Secret, "secret never exposed but persisted")

	// delete
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/webhooks/"+resp.Data.ID, nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	_, err = repo.FindByID(resp.Data.ID)
	assert.Error(t, err, "deleted")
}
