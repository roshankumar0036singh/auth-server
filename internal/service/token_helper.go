package service

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateRandomString generates a random string of specified length
func (s *TokenService) GenerateRandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
