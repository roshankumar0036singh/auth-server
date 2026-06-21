package service

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"gorm.io/gorm"
)

type WebAuthnService struct {
	config       *config.Config
	webAuthn     *webauthn.WebAuthn
	userRepo     *repository.UserRepository
	cacheService *CacheService
	db           *gorm.DB
}

func NewWebAuthnService(cfg *config.Config, userRepo *repository.UserRepository, cacheService *CacheService, db *gorm.DB) (*WebAuthnService, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: cfg.WebAuthn.RPDisplayName,
		RPID:          cfg.WebAuthn.RPID,
		RPOrigins:     cfg.WebAuthn.RPOrigins,
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn instance: %w", err)
	}

	return &WebAuthnService{
		config:       cfg,
		webAuthn:     wa,
		userRepo:     userRepo,
		cacheService: cacheService,
		db:           db,
	}, nil
}

func (s *WebAuthnService) BeginRegistration(ctx context.Context, user *models.User) (*protocol.CredentialCreation, string, error) {
	// Preload passkeys so user.WebAuthnCredentials() has them
	if err := s.db.Model(user).Association("Passkeys").Find(&user.Passkeys); err != nil {
		return nil, "", err
	}

	options, sessionData, err := s.webAuthn.BeginRegistration(user)
	if err != nil {
		return nil, "", err
	}

	// Generate a unique session ID and store sessionData in cache
	sessionID := uuid.New().String()
	if err := s.cacheService.StoreWebAuthnSession(ctx, sessionID, user.ID, *sessionData, 10*time.Minute); err != nil {
		return nil, "", err
	}

	return options, sessionID, nil
}

func (s *WebAuthnService) FinishRegistration(ctx context.Context, user *models.User, sessionID string, r *http.Request) (*models.WebAuthnCredential, error) {
	if err := s.db.Model(user).Association("Passkeys").Find(&user.Passkeys); err != nil {
		return nil, err
	}

	userID, sessionData, err := s.cacheService.GetWebAuthnSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired registration session")
	}
	if userID != user.ID {
		return nil, fmt.Errorf("session user mismatch")
	}

	credential, err := s.webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		return nil, err
	}

	// Clean up session
	s.cacheService.client.Del(ctx, "webauthn_session:"+sessionID)

	// Save credential
	modelCred, err := models.FromWebAuthn(user.ID, credential)
	if err != nil {
		return nil, err
	}

	if err := s.db.Create(modelCred).Error; err != nil {
		return nil, err
	}

	return modelCred, nil
}

func (s *WebAuthnService) BeginLogin(ctx context.Context, user *models.User) (*protocol.CredentialAssertion, string, error) {
	if err := s.db.Model(user).Association("Passkeys").Find(&user.Passkeys); err != nil {
		return nil, "", err
	}

	options, sessionData, err := s.webAuthn.BeginLogin(user)
	if err != nil {
		return nil, "", err
	}

	sessionID := uuid.New().String()
	if err := s.cacheService.StoreWebAuthnSession(ctx, sessionID, user.ID, *sessionData, 10*time.Minute); err != nil {
		return nil, "", err
	}

	return options, sessionID, nil
}

func (s *WebAuthnService) FinishLogin(ctx context.Context, sessionID string, r *http.Request) (*models.User, *webauthn.Credential, error) {
	userID, sessionData, err := s.cacheService.GetWebAuthnSession(ctx, sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid or expired authentication session")
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found")
	}

	if err := s.db.Model(user).Association("Passkeys").Find(&user.Passkeys); err != nil {
		return nil, nil, err
	}

	credential, err := s.webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		return nil, nil, err
	}

	// Clean up session
	s.cacheService.client.Del(ctx, "webauthn_session:"+sessionID)

	modelCred, err := models.FromWebAuthn(user.ID, credential)
	if err != nil {
		return nil, nil, err
	}

	// Update the data blob
	if err := s.db.Model(&models.WebAuthnCredential{}).
		Where("credential_id = ?", credential.ID).
		Update("data", modelCred.Data).Error; err != nil {
		log.Printf("failed to update webauthn signCount for credential %s: %v", credential.ID, err)
	}

	return user, credential, nil
}
