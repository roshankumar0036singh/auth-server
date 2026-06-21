package service

import (
	"context"
	"errors"
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
)

type WebAuthnService struct {
	config       *config.Config
	webAuthn     *webauthn.WebAuthn
	userRepo     *repository.UserRepository
	cacheService *CacheService
}

func NewWebAuthnService(cfg *config.Config, userRepo *repository.UserRepository, cacheService *CacheService) (*WebAuthnService, error) {
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
	}, nil
}

func (s *WebAuthnService) BeginRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, string, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, "", err
	}

	// Preload passkeys so user.WebAuthnCredentials() has them
	if err := s.userRepo.LoadPasskeys(user); err != nil {
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

func (s *WebAuthnService) FinishRegistration(ctx context.Context, userID string, sessionID string, r *http.Request) (*models.WebAuthnCredential, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, err
	}

	if err := s.userRepo.LoadPasskeys(user); err != nil {
		return nil, err
	}

	sessionUserID, sessionData, err := s.cacheService.ConsumeWebAuthnSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired registration session")
	}
	if sessionUserID != user.ID {
		return nil, fmt.Errorf("session user mismatch")
	}

	credential, err := s.webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		return nil, err
	}

	// Save credential
	modelCred, err := models.FromWebAuthn(user.ID, credential)
	if err != nil {
		return nil, err
	}

	if err := s.userRepo.CreateWebAuthnCredential(modelCred); err != nil {
		return nil, err
	}

	return modelCred, nil
}

func (s *WebAuthnService) BeginLogin(ctx context.Context, email string) (*protocol.CredentialAssertion, string, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil, "", err
	}

	if err := s.userRepo.LoadPasskeys(user); err != nil {
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
	userID, sessionData, err := s.cacheService.ConsumeWebAuthnSession(ctx, sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid or expired authentication session")
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, nil, ErrUserNotFound
		}
		return nil, nil, fmt.Errorf("failed to retrieve user: %w", err)
	}

	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, nil, fmt.Errorf("account is locked")
	}
	if !user.IsActive {
		return nil, nil, fmt.Errorf("account is inactive")
	}

	if err := s.userRepo.LoadPasskeys(user); err != nil {
		return nil, nil, err
	}

	credential, err := s.webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		return nil, nil, err
	}

	modelCred, err := models.FromWebAuthn(user.ID, credential)
	if err != nil {
		return nil, nil, err
	}

	// Update the data blob
	if err := s.userRepo.UpdateWebAuthnCredentialData(credential.ID, modelCred.Data); err != nil {
		log.Printf("failed to update webauthn signCount for credential %s: %v", credential.ID, err)
	}

	return user, credential, nil
}
