package service

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ErrBreachedPassword is returned when a candidate password appears in a
// known data breach (#150).
var ErrBreachedPassword = errors.New("password has appeared in a data breach; choose a different one")

// httpClientForPwned is overridable in tests.
var httpClientForPwned = &http.Client{Timeout: 5 * time.Second}

// HTTPClientForPwned is an override hook for tests.
var HTTPClientForPwned = httpClientForPwned

// PwnedPasswordCheck performs a HaveIBeenPwned k-Anonymity ranges query:
// only the first five characters of the SHA-1 digest leave this process, and
// the full digest is compared locally against the returned suffix ranges
// (https://haveibeenpwned.com/API/v3#PwnedPasswords).
type PwnedPasswordCheck struct {
	Endpoint string
}

// NewPwnedPasswordCheck returns a checker against the public HIBP API.
func NewPwnedPasswordCheck() *PwnedPasswordCheck {
	return &PwnedPasswordCheck{Endpoint: "https://api.pwnedpasswords.com/range/"}
}

// Check reports whether password has ever appeared in a breach.
func (p *PwnedPasswordCheck) Check(password string) (bool, error) {
	sum := sha1.Sum([]byte(password))
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := digest[:5], digest[5:]

	req, err := http.NewRequest(http.MethodGet, p.Endpoint+prefix, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "auth-server")

	resp, err := httpClientForPwned.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("pwned passwords API returned %d", resp.StatusCode)
	}

	var body strings.Builder
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		body.Write(buf[:n])
		if readErr != nil {
			break
		}
	}

	for _, line := range strings.Split(body.String(), "\n") {
		// line format: <SUFFIX>:<COUNT>
		if parts := strings.SplitN(strings.TrimSpace(line), ":", 2); len(parts) == 2 && parts[0] == suffix {
			return true, nil
		}
	}
	return false, nil
}