package config_test

import (
	"testing"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roshankumar0036singh/auth-server/internal/config"
)

func TestSplitRedisURIs(t *testing.T) {
	assert.Equal(t, []string{"redis://r1:6379", "redis://r2:6379"},
		config.SplitRedisURIsForTest("redis://r1:6379, redis://r2:6379"))
	assert.Empty(t, config.SplitRedisURIsForTest(" , "))
	assert.Equal(t, []string{"a:6379"}, config.SplitRedisURIsForTest("a:6379"))
}

func TestBuildRedisClientSingle(t *testing.T) {
	cfg := &config.Config{Redis: config.RedisConfig{URL: "redis://localhost:6379/0", Mode: "single"}}
	client, err := config.BuildRedisClient(cfg)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	_, ok := client.(*redis.Client)
	assert.True(t, ok, "single mode must produce a *redis.Client")
}

func TestBuildRedisClientCluster(t *testing.T) {
	cfg := &config.Config{Redis: config.RedisConfig{
		URL:  "redis://r0:6379",
		URIs: []string{"redis://r1:7000", "redis://r2:7000", "redis://r3:7000"},
		Mode: "cluster",
	}}
	client, err := config.BuildRedisClient(cfg)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	cluster, ok := client.(*redis.ClusterClient)
	require.True(t, ok, "cluster mode must produce a *redis.ClusterClient")
	assert.Equal(t, []string{"r1:7000", "r2:7000", "r3:7000"}, cluster.Options().Addrs)
}

func TestBuildRedisClientClusterFromSingleURI(t *testing.T) {
	cfg := &config.Config{Redis: config.RedisConfig{
		URL:  "redis://r0:7000",
		Mode: "cluster",
	}}
	client, err := config.BuildRedisClient(cfg)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	cluster, ok := client.(*redis.ClusterClient)
	require.True(t, ok)
	assert.Equal(t, []string{"r0:7000"}, cluster.Options().Addrs)
}

func TestBuildRedisClientSentinel(t *testing.T) {
	cfg := &config.Config{Redis: config.RedisConfig{
		URL:  "redis://localhost:26379",
		Mode: "sentinel",
	}}
	client, err := config.BuildRedisClient(cfg)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	_, ok := client.(*redis.Client)
	assert.True(t, ok, "sentinel mode must produce a failover-capable client")
}
