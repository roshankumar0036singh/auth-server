package utils

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashToken computes the SHA-256 hash of a token string.
// This is used to securely store and look up access tokens in the database.
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
