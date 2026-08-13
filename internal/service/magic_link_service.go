package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/dto"
)

// magicLinkTTL matches the acceptance criteria: links expire after 15 minutes.
const magicLinkTTL = 15 * time.Minute

// magicLinkRateLimitMax is the number of request attempts allowed per email
// per window before the endpoint refuses further sends.
const magicLinkRateLimitMax = 3

// magicLinkRateLimitWindow is the sliding window for the send rate limit.
const magicLinkRateLimitWindow = 15 * time.Minute

// ErrMagicLinkRateLimited is returned when too many links were requested.
var ErrMagicLinkRateLimited = errors.New("too many magic link requests, please try again later")

// RequestMagicLink generates a single-use, 15-minute magic link and emails it
// to the user. The response is indistinguishable for unknown emails to avoid
// account enumeration (#155).
func (s *AuthService) RequestMagicLink(ctx context.Context, email string) error {
	allowed, err := s.cacheService.AllowRequest(ctx, "magic_link:"+email, magicLinkRateLimitMax, magicLinkRateLimitWindow)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrMagicLinkRateLimited
	}

	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		// Do not reveal whether the account exists.
		return nil
	}
	if !user.IsActive {
		return nil
	}

	token, err := randomHex(32)
	if err != nil {
		return err
	}

	if err := s.cacheService.StoreMagicLink(ctx, token, user.ID, magicLinkTTL); err != nil {
		return err
	}

	appURL := s.config.App.URL
	if appURL == "" {
		appURL = "http://localhost:3000"
	}
	if err := s.emailService.SendMagicLinkEmail(email, token, appURL); err != nil {
		return err
	}

	s.auditService.LogEvent(&user.ID, "MAGIC_LINK_REQUESTED", "USER", user.ID, "", "", nil)
	return nil
}

// VerifyMagicLink redeems a magic-link token and issues a full login session,
// skipping MFA for the passwordless flow (#155). Tokens are single-use.
func (s *AuthService) VerifyMagicLink(ctx context.Context, token, ipAddress, userAgent string) (*dto.LoginResponse, error) {
	if token == "" {
		return nil, errors.New("missing magic link token")
	}

	userID, err := s.cacheService.ConsumeMagicLink(ctx, token)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil || !user.IsActive {
		return nil, errors.New("account no longer available")
	}

	s.auditService.LogEvent(&user.ID, "MAGIC_LINK_LOGIN", "USER", user.ID, ipAddress, userAgent, nil)
	return s.ProcessPostLogin(ctx, user, ipAddress, userAgent, true)
}

// randomHex returns n random bytes hex-encoded.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}