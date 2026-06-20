package service

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
)

type TokenService struct {
	cfg *config.Config
}

func NewTokenService(cfg *config.Config) *TokenService {
	return &TokenService{cfg: cfg}
}

// JWTClaims custom claims for JWT
type JWTClaims struct {
	UserID    string `json:"sub"`
	SessionID string `json:"session_id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	// Purpose marks special-purpose tokens (e.g. an MFA-pending token).
	// A normal access/refresh token leaves this empty; the access-token
	// validator rejects any token with a non-empty Purpose so a purpose
	// token can never be used as a bearer credential.
	Purpose string `json:"purpose,omitempty"`
	jwt.RegisteredClaims
}

// mfaPendingPurpose is the Purpose value of the short-lived token issued after
// a successful password step, required to complete MFA login.
const mfaPendingPurpose = "mfa_pending"

const (
	issuerAuthServer     = "auth-server"
	errInvalidSignMethod = "invalid signing method"
	errInvalidToken      = "invalid token"
)

func (s *TokenService) signToken(claims *JWTClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.cfg.JWT.KeyID
	return token.SignedString(s.cfg.JWT.PrivateKey)
}

func (s *TokenService) parseToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New(errInvalidSignMethod)
		}
		return s.cfg.JWT.PublicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New(errInvalidToken)
}

// GenerateAccessToken generates a new JWT access token
func (s *TokenService) GenerateAccessToken(user *models.User, sessionID string) (string, error) {
	expirationTime := time.Now().Add(15 * time.Minute) // 15 minutes

	claims := &JWTClaims{
		UserID:    user.ID,
		Email:     user.Email,
		Role:      user.Role,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    issuerAuthServer,
			ID:        uuid.New().String(),
		},
	}

	return s.signToken(claims)
}

// GenerateRefreshToken generates a new refresh token (longer expiry)
func (s *TokenService) GenerateRefreshToken(user *models.User) (string, error) {
	expirationTime := time.Now().Add(7 * 24 * time.Hour) // 7 days

	claims := &JWTClaims{
		UserID: user.ID,
		Email:  user.Email,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    issuerAuthServer,
			ID:        uuid.New().String(),
		},
	}

	return s.signToken(claims)
}

// ValidateAccessToken validates and parses an access token
func (s *TokenService) ValidateAccessToken(tokenString string) (*JWTClaims, error) {
	claims, err := s.parseToken(tokenString)
	if err != nil {
		return nil, err
	}
	
	// Purpose-scoped tokens (e.g. the MFA-pending token) must never be
	// accepted as access tokens.
	if claims.Purpose != "" {
		return nil, errors.New(errInvalidToken)
	}
	
	return claims, nil
}

// GenerateMFAToken issues a short-lived token proving the password step of
// login succeeded. It must be presented to complete MFA login and cannot be
// used as an access token (see Purpose handling in ValidateAccessToken).
func (s *TokenService) GenerateMFAToken(userID string) (string, error) {
	claims := &JWTClaims{
		UserID:  userID,
		Purpose: mfaPendingPurpose,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    issuerAuthServer,
			ID:        uuid.New().String(),
		},
	}

	return s.signToken(claims)
}

// ValidateMFAToken validates an MFA-pending token and returns the user ID it
// was issued for. It rejects any token whose Purpose is not the MFA-pending
// marker, so access/refresh tokens cannot stand in for it.
func (s *TokenService) ValidateMFAToken(tokenString string) (string, error) {
	claims, err := s.parseToken(tokenString)
	if err != nil {
		return "", err
	}
	
	if claims.Purpose != mfaPendingPurpose {
		return "", errors.New("invalid mfa token")
	}
	
	return claims.UserID, nil
}

// ValidateRefreshToken validates and parses a refresh token
func (s *TokenService) ValidateRefreshToken(tokenString string) (*JWTClaims, error) {
	claims, err := s.parseToken(tokenString)
	if err != nil {
		return nil, err
	}
	if claims.Purpose != "" {
		return nil, errors.New("invalid refresh token: has specific purpose")
	}
	return claims, nil
}
