package service

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"

	"github.com/roshankumar0036singh/auth-server/internal/config"
)

// JWKS (issue #171): exposes the active public key so downstream resource
// servers can cryptographically verify access-token signatures without
// contacting the auth server.
//
// When JWT_RSA_PRIVATE_KEY is configured, access/refresh tokens are signed
// with RS256 and the matching public key is published at
// /.well-known/jwks.json. Without it the server keeps its existing HS256
// signing and the endpoint returns an empty key set (HMAC secrets are
// symmetric and must never be published).

const jwksKeyID = "auth-server-rs1"

// JWKSKeyID returns the key identifier used in jwt headers and the JWKS
// document ("" when RS256 is not configured).
func JWKSKeyID() string { return jwksKeyID }

// JWK is a single JSON Web Key per RFC 7517.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSResponse is the top-level document served at /.well-known/jwks.json.
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWKSService builds and caches the public-key document at startup so
// repeated requests do no crypto work.
type JWKSService struct {
	privateKey *rsa.PrivateKey
	document   JWKSResponse
}

// NewJWKSService parses the optional RSA private key from config. A nil
// service (no key configured) is valid: it produces an empty key set.
func NewJWKSService(cfg *config.Config) *JWKSService {
	svc := &JWKSService{document: JWKSResponse{Keys: []JWK{}}}
	if cfg == nil || strings.TrimSpace(cfg.JWT.RSAPrivateKey) == "" {
		return svc
	}

	key, err := parseRSAPrivateKey(cfg.JWT.RSAPrivateKey)
	if err != nil {
		// Fail loudly: if an admin opted into RSA but provided a bad key,
		// silently falling back to HS256 would break signature verification.
		panic("jwks: invalid JWT_RSA_PRIVATE_KEY: " + err.Error())
	}
	svc.privateKey = key
	svc.document = JWKSResponse{Keys: []JWK{fromRSAPublicKey(&key.PublicKey)}}
	return svc
}

// PrivateKey returns the parsed RSA key, or nil when HS256 mode is active.
func (s *JWKSService) PrivateKey() *rsa.PrivateKey {
	if s == nil {
		return nil
	}
	return s.privateKey
}

// Document returns the cached JWKS document.
func (s *JWKSService) Document() JWKSResponse {
	if s == nil {
		return JWKSResponse{Keys: []JWK{}}
	}
	return s.document
}

// KeyID returns the kid of the published key ("" in HS256 mode).
func (s *JWKSService) KeyID() string {
	if s == nil || s.privateKey == nil {
		return ""
	}
	for _, k := range s.document.Keys {
		return k.Kid
	}
	return ""
}

// parseRSAPrivateKey accepts a PEM-encoded PKCS#1 or PKCS#8 RSA key.
func parseRSAPrivateKey(pemValue string) (*rsa.PrivateKey, error) {
	encoded := strings.TrimSpace(pemValue)
	if strings.HasPrefix(encoded, "base64:") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encoded, "base64:"))
		if err != nil {
			return nil, err
		}
		encoded = string(raw)
	}

	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	// PKCS#8 (BEGIN PRIVATE KEY) first, then PKCS#1 (BEGIN RSA PRIVATE KEY)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("key is not RSA")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// fromRSAPublicKey converts an RSA public key into an RFC 7518 JWK.
func fromRSAPublicKey(pub *rsa.PublicKey) JWK {
	e := big.NewInt(int64(pub.E)).Bytes()
	return JWK{
		Kty: "RSA",
		Kid: jwksKeyID,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(e),
	}
}
