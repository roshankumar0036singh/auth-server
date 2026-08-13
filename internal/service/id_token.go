package service

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/roshankumar0036singh/auth-server/internal/models"
)

// OIDCClaims are the standard id_token claims (issue #85).
type OIDCClaims struct {
	Issuer        string `json:"iss"`
	Subject       string `json:"sub"`
	Audience      string `json:"aud"`
	Nonce         string `json:"nonce,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
	AuthTime      int64  `json:"auth_time,omitempty"`
	jwt.RegisteredClaims
}

// GenerateIDToken mints an OpenID Connect id_token for the authorization-code
// exchange. It is signed with the active token-service key (RS256 when
// JWT_RSA_PRIVATE_KEY is configured, HS256 otherwise) and carries the
// standard iss/sub/aud/exp/iat/nonce claims. Per spec the nonce from the
// authorize request is echoed back unchanged.
func (s *OAuthProviderService) GenerateIDToken(user *models.User, clientID string, nonce string, authTime time.Time) (string, error) {
	if s.tokenService == nil {
		return "", errors.New("id_token signing unavailable")
	}
	issuer := issuerAuthServer
	if s.cfg != nil && s.cfg.App.URL != "" {
		issuer = s.cfg.App.URL
	}
	now := time.Now()
	expires := now.Add(5 * time.Minute) // id_tokens are short-lived by spec

	claims := &OIDCClaims{
		Issuer:   issuer,
		Subject:  user.ID,
		Audience: clientID,
		Nonce:    nonce,
		Email:    user.Email,
		AuthTime: authTime.Unix(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expires),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    issuer,
			Subject:   user.ID,
			Audience:  jwt.ClaimStrings{clientID},
			ID:        uuid.New().String(),
		},
	}
	emailVerified := user.EmailVerified
	claims.EmailVerified = &emailVerified

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if key := s.tokenService.JWKSPrivateKey(); key != nil {
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = s.tokenService.JWKSKeyID()
		return token.SignedString(key)
	}
	// HS256 fallback (no RSA key configured): sign with the access secret.
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWT.AccessSecret))
}
