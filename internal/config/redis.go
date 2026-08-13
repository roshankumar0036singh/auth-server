package config

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/go-redis/redis/v8"
)

// BuildRedisClient constructs the appropriate go-redis client for the
// configured deployment (issue #191):
//
//   - REDIS_MODE=cluster or multiple REDIS_URLS → redis.ClusterClient
//   - REDIS_MODE=sentinel → redis.FailoverClient (single sentinel DSN)
//   - otherwise → single-instance redis.Client
//
// It never performs I/O, so it is safe to unit test.
func BuildRedisClient(cfg *Config) (redis.UniversalClient, error) {
	if cfg.Redis.Mode == "cluster" || len(cfg.Redis.URIs) > 1 {
		addrs := cfg.Redis.URIs
		if len(addrs) == 0 {
			// a single DSN with cluster mode is also valid
			addrs = []string{cfg.Redis.URL}
		}
		addrs = normalizeAddrs(addrs)
		return redis.NewClusterClient(&redis.ClusterOptions{Addrs: addrs}), nil
	}

	if cfg.Redis.Mode == "sentinel" {
		opt, err := redis.ParseURL(cfg.Redis.URL)
		if err != nil {
			return nil, fmt.Errorf("parse sentinel URL: %w", err)
		}
		return redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    "mymaster",
			SentinelAddrs: []string{opt.Addr},
			Password:      opt.Password,
		}), nil
	}

	opt, err := redis.ParseURL(cfg.Redis.URL)
	if err != nil {
		return nil, fmt.Errorf("parse Redis URL: %w", err)
	}
	return redis.NewClient(opt), nil
}

// normalizeAddrs converts redis:// DSNs into host:port addresses accepted by
// ClusterOptions.
func normalizeAddrs(uris []string) []string {
	addrs := make([]string, 0, len(uris))
	for _, u := range uris {
		if strings.HasPrefix(u, "redis://") || strings.HasPrefix(u, "rediss://") {
			if opt, err := redis.ParseURL(u); err == nil {
				addrs = append(addrs, opt.Addr)
				continue
			}
		}
		addrs = append(addrs, u)
	}
	return addrs
}

// InitRedis builds and pings the Redis client, failing fast on errors.
func InitRedis(cfg *Config) redis.UniversalClient {
	ctx := context.Background()
	client, err := BuildRedisClient(cfg)
	if err != nil {
		log.Fatal("Failed to build Redis client:", err)
	}

	if _, err := client.Ping(ctx).Result(); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}

	log.Printf("Redis connected successfully (mode=%s)", redisModeLabel(cfg))
	return client
}

func redisModeLabel(cfg *Config) string {
	if cfg.Redis.Mode == "cluster" {
		return "cluster"
	}
	if cfg.Redis.Mode == "sentinel" {
		return "sentinel"
	}
	return "single"
}
