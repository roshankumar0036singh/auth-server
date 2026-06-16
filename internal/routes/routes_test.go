package routes_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/routes"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func TestHealthCheck(t *testing.T) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer rdb.Close()

	cfg := &config.Config{
		JWT:      config.JWTConfig{AccessSecret: "secret", RefreshSecret: "refresh"},
		Security: config.SecurityConfig{RateLimitMax: 10, RateLimitWindow: 60},
		App:      config.AppConfig{URL: "http://localhost", Env: "development"},
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	routes.SetupRoutes(router, db, rdb, cfg)

	req, _ := http.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "ok", response["status"])
	assert.Equal(t, "Auth server is running", response["message"])
}

func TestReadyCheck_Success(t *testing.T) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer rdb.Close()

	cfg := &config.Config{
		JWT:      config.JWTConfig{AccessSecret: "secret", RefreshSecret: "refresh"},
		Security: config.SecurityConfig{RateLimitMax: 10, RateLimitWindow: 60},
		App:      config.AppConfig{URL: "http://localhost", Env: "development"},
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	routes.SetupRoutes(router, db, rdb, cfg)

	req, _ := http.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "ok", response["status"])

	components, ok := response["components"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "up", components["database"])
	assert.Equal(t, "up", components["redis"])
}

func TestReadyCheck_RedisDown(t *testing.T) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	// Close miniredis immediately to simulate redis down
	mr.Close()

	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:12345", // closed port
	})
	defer rdb.Close()

	cfg := &config.Config{
		JWT:      config.JWTConfig{AccessSecret: "secret", RefreshSecret: "refresh"},
		Security: config.SecurityConfig{RateLimitMax: 10, RateLimitWindow: 60},
		App:      config.AppConfig{URL: "http://localhost", Env: "development"},
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	routes.SetupRoutes(router, db, rdb, cfg)

	req, _ := http.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "degraded", response["status"])

	components, ok := response["components"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "up", components["database"])
	assert.Equal(t, "down", components["redis"])
}

func TestReadyCheck_DBDown(t *testing.T) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer rdb.Close()

	// Close database connection to simulate DB down
	sqlDB, err := db.DB()
	assert.NoError(t, err)
	err = sqlDB.Close()
	assert.NoError(t, err)

	cfg := &config.Config{
		JWT:      config.JWTConfig{AccessSecret: "secret", RefreshSecret: "refresh"},
		Security: config.SecurityConfig{RateLimitMax: 10, RateLimitWindow: 60},
		App:      config.AppConfig{URL: "http://localhost", Env: "development"},
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	routes.SetupRoutes(router, db, rdb, cfg)

	req, _ := http.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "degraded", response["status"])

	components, ok := response["components"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "down", components["database"])
	assert.Equal(t, "up", components["redis"])
}
