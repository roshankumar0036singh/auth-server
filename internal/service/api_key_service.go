package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
)

// APIKeyPrefix marks generated keys so they are instantly recognizable and
// can never collide with bearer tokens or OAuth client IDs.
const APIKeyPrefix = "ask_"

// APIKeyChars is the base62 alphabet used for generated key material.
const APIKeyChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// APIKeyService manages long-lived server-to-server credentials (#169).
type APIKeyService struct {
	keyRepo      *repository.ApiKeyRepository
	auditService *AuditService
}

func NewAPIKeyService(keyRepo *repository.ApiKeyRepository, auditService *AuditService) *APIKeyService {
	return &APIKeyService{keyRepo: keyRepo, auditService: auditService}
}

// GenerateKey creates an API key and persists its sha256 digest (for lookup)
// and bcrypt hash (for verification). The plaintext value is returned only
// once, here, alongside the persisted key identifier.
func (s *APIKeyService) GenerateKey(name, createdBy string) (string, string, error) {
	secret, err := randomString(32)
	if err != nil {
		return "", "", err
	}

	full := APIKeyPrefix + secret
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	key := &models.ApiKey{
		Name:      name,
		Prefix:    secret[:4],
		KeyDigest: digest(full),
		KeyHash:   string(hash),
		CreatedBy: createdBy,
	}
	if err := s.keyRepo.Create(key); err != nil {
		return "", "", err
	}

	s.auditService.LogEvent(nil, "API_KEY_CREATED", "API_KEY", key.ID, "", "", map[string]interface{}{
		"name": name,
	})

	return full, key.ID, nil
}

// Authenticate validates a presented key against its stored hash, rejects
// revoked keys, records last use and audits the access (#169).
func (s *APIKeyService) Authenticate(plaintext string) (*models.ApiKey, error) {
	if len(plaintext) < len(APIKeyPrefix) || plaintext[:len(APIKeyPrefix)] != APIKeyPrefix {
		return nil, errors.New("invalid api key format")
	}
	secret := plaintext[len(APIKeyPrefix):]

	key, err := s.keyRepo.FindByKeyDigest(digest(plaintext))
	if err != nil {
		return nil, errors.New("unknown api key")
	}
	if key.IsRevoked() {
		return nil, errors.New("api key revoked")
	}
	if bcrypt.CompareHashAndPassword([]byte(key.KeyHash), []byte(secret)) != nil {
		return nil, errors.New("api key mismatch")
	}

	now := time.Now()
	if err := s.keyRepo.TouchLastUsed(key.ID, now); err != nil {
		return nil, err
	}
	key.LastUsedAt = &now
	s.auditService.LogEvent(nil, "API_KEY_USED", "API_KEY", key.ID, "", "", nil)

	return key, nil
}

// ListKeys returns all active keys, newest first.
func (s *APIKeyService) ListKeys() ([]models.ApiKey, error) {
	return s.keyRepo.ListActive()
}

// RevokeKey revokes a key by id. Already-revoked keys are a no-op success.
func (s *APIKeyService) RevokeKey(id string) error {
	if err := s.keyRepo.Revoke(id, time.Now()); err != nil {
		return err
	}
	s.auditService.LogEvent(nil, "API_KEY_REVOKED", "API_KEY", id, "", "", nil)
	return nil
}

// digest returns the hex sha256 of s for efficient, collision-free lookup.
func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// randomString returns n base62 characters from a cryptographically secure
// source.
func randomString(n int) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(APIKeyChars)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = APIKeyChars[idx.Int64()]
	}
	return string(out), nil
}