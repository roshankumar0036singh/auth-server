package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

func getEnvAsInt(key string, defaultVal int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultVal
}

func getEnvAsBool(key string, defaultVal bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultVal
}

func getEnvAsDuration(key string, defaultVal time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	if d, err := time.ParseDuration(val); err == nil {
		if d > 0 {
			return d
		}
		log.Printf("Warning: %s is invalid (must be > 0), using default: %v", key, defaultVal)
	} else {
		log.Printf("Warning: failed to parse %s as duration (%v), using default: %v", key, err, defaultVal)
	}
	return defaultVal
}
