package utils

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// GenerateRandomString generates a secure random string of given length
func GenerateRandomString(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("length must be greater than 0")
	}

	bytes := make([]byte, length)

	if _, err := rand.Read(bytes); err != nil {
		return "", errors.New("failed to generate random bytes")
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}