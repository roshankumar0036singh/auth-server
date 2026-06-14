package utils

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateRandomString generates a secure random string of given length
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}