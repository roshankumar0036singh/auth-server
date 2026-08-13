package utils_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestErrorCodeForStatus(t *testing.T) {
	cases := []struct {
		status int
		code   string
	}{
		{http.StatusBadRequest, "BAD_REQUEST"},
		{http.StatusUnauthorized, "UNAUTHORIZED"},
		{http.StatusForbidden, "FORBIDDEN"},
		{http.StatusNotFound, "NOT_FOUND"},
		{http.StatusConflict, "CONFLICT"},
		{http.StatusUnprocessableEntity, "VALIDATION_ERROR"},
		{http.StatusTooManyRequests, "RATE_LIMITED"},
		{http.StatusInternalServerError, "INTERNAL_ERROR"},
		{http.StatusTeapot, "ERROR"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.code, utils.ErrorCodeForStatus(tc.status))
	}
}

func TestWriteErrorShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/boom", func(c *gin.Context) {
		utils.WriteError(c, http.StatusNotFound, "User not found", nil)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	var body struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Error   struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Status  int    `json:"status"`
		} `json:"error"`
	}
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.False(t, body.Success)
	assert.Equal(t, "User not found", body.Message)
	assert.Equal(t, "NOT_FOUND", body.Error.Code)
	assert.Equal(t, http.StatusNotFound, body.Error.Status)
	assert.Equal(t, "User not found", body.Error.Message)
}

func TestWriteErrorIncludesUnderlyingError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/boom", func(c *gin.Context) {
		utils.WriteError(c, http.StatusBadRequest, "Bad payload", &errDetail{msg: "field x is invalid"})
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	r.ServeHTTP(rec, req)

	var body map[string]interface{}
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	detail := body["error"].(map[string]interface{})
	assert.Equal(t, "BAD_REQUEST", detail["code"])
	assert.Equal(t, "field x is invalid", detail["message"])
}

type errDetail struct{ msg string }

func (e *errDetail) Error() string { return e.msg }
