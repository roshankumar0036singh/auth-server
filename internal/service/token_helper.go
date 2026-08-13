package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateRandomString generates a random string of specified length.
// It returns an error when the CSPRNG fails, so callers never silently
// produce predictable tokens (password reset, temp passwords, etc.).
func (s *TokenService) GenerateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
