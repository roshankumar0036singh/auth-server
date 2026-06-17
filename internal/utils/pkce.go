package utils

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"regexp"
)

var verifierRegex = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)

// VerifyPKCE validates a code_verifier against a stored code_challenge per RFC 7636.
func VerifyPKCE(verifier, challenge, method string) error {
	if !verifierRegex.MatchString(verifier) {
		return errors.New("code_verifier must be 43-128 unreserved characters (RFC 7636 §4.1)")
	}

	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
			return errors.New("code_verifier does not match code_challenge")
		}
	case "plain":
		if subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) != 1 {
			return errors.New("code_verifier does not match code_challenge")
		}
	default:
		return errors.New("unsupported code_challenge_method; use S256")
	}
	return nil
}
