package service

import (
	"errors"
	"strings"
	"sync"
)

// DisposableEmailService rejects registrations using known burner email
// domains (issue #164). The domain list is loaded at startup and can be
// dynamically overwritten by admins.
type DisposableEmailService struct {
	mu        sync.RWMutex
	blocklist map[string]struct{}
}

// NewDisposableEmailService seeds the blocklist from the bundled asset.
func NewDisposableEmailService() *DisposableEmailService {
	svc := &DisposableEmailService{blocklist: map[string]struct{}{}}
	svc.loadBundled()
	return svc
}

// IsDisposable reports whether the email's domain is blocked.
func (s *DisposableEmailService) IsDisposable(email string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))

	s.mu.RLock()
	defer s.mu.RUnlock()
	_, hit := s.blocklist[domain]
	return hit
}

// DomainCount returns the number of blocked domains (status/tests).
func (s *DisposableEmailService) DomainCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.blocklist)
}

// ReplaceBlocklist sets the full domain list (admin update path, #164).
func (s *DisposableEmailService) ReplaceBlocklist(domains []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocklist = make(map[string]struct{}, len(domains))
	for _, d := range domains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			s.blocklist[d] = struct{}{}
		}
	}
}

// AddDomain dynamically blocks one more domain.
func (s *DisposableEmailService) AddDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if domain = strings.ToLower(strings.TrimSpace(domain)); domain != "" {
		s.blocklist[domain] = struct{}{}
	}
}

// loadBundled seeds from the package-level builtin so blocking works even
// without any configuration.
func (s *DisposableEmailService) loadBundled() {
	s.ReplaceBlocklist(builtinDisposableDomains())
}

// builtinDisposableDomains is a curated starter list of common burner
// providers. Administrators extend it via config or the admin endpoint.
func builtinDisposableDomains() []string {
	return []string{
		"10minutemail.com", "10minutemails.net", "mailinator.com",
		"mailinator.net", "guerrillamail.com", "guerrillamail.net",
		"guerrillamail.org", "sharklasers.com", "temp-mail.org",
		"tempmail.com", "throwawaymail.com", "yopmail.com", "yopmail.fr",
		"dropmail.me", "getnada.com", "trashmail.com", "trashmail.de",
		"dispostable.com", "maildrop.cc", "mytemp.email", "33mail.com",
		"mailnator.com", "emailondeck.com", "fakeinbox.com", "inboxbear.com",
		"burnermail.io", "spamgourmet.com", "mintemail.com", "mailtemp.net",
		"0-mail.com", "spambox.us", "mailcatch.com", "kickmail.in",
	}
}

// ErrDisposableEmail is returned when registration uses a burner domain
// (issue #164).
var ErrDisposableEmail = errors.New("disposable email domains are not allowed; please use a permanent address")
// Domains returns the current blocklist (unsorted, for admin status).
func (s *DisposableEmailService) Domains() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.blocklist))
	for d := range s.blocklist {
		out = append(out, d)
	}
	return out
}
