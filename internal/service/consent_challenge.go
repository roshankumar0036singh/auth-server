package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
)

// ConsentChallengePayload carries the exact request parameters the user saw
// on the consent screen (issue #153). The submission handler must use these
// values instead of anything posted by the client.
type ConsentChallengePayload struct {
	ClientID            string   `json:"client_id"`
	UserID              string   `json:"user_id"`
	Scopes              []string `json:"scopes"`
	CodeChallenge       string   `json:"code_challenge,omitempty"`
	CodeChallengeMethod string   `json:"code_challenge_method,omitempty"`
}

func MarshalConsentPayload(p ConsentChallengePayload) (string, error) {
	b, err := json.Marshal(p)
	return string(b), err
}

func UnmarshalConsentPayload(raw string) (ConsentChallengePayload, error) {
	var p ConsentChallengePayload
	err := json.Unmarshal([]byte(raw), &p)
	return p, err
}

// randomHex returns n random bytes hex-encoded.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenChallenge returns a cryptographically random challenge identifier.
func GenChallenge() (string, error) { return randomHex(16) }
