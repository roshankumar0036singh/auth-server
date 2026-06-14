package service

import (
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

// GenerateRandomString generates a random string of specified length
func (s *TokenService) GenerateRandomString(n int) (string, error) {
	return utils.GenerateRandomString(n)
}