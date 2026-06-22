package main

import (
	"fmt"
	"log"
	"os"

	"github.com/lib/pq"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func main() {
	cfg := config.LoadConfig()

	// Prevent accidental execution against production databases.
	if cfg.App.Env != "development" && cfg.App.Env != "local" {
		log.Fatal("database seeding is only allowed in development or local environments")
	}

	db := config.InitDatabase(cfg)

	err := config.AutoMigrate(
		db,
		&models.User{},
		&models.RefreshToken{},
		&models.VerificationToken{},
		&models.PasswordResetToken{},
		&models.AuditLog{},
		&models.OAuthClient{},
		&models.AuthorizationCode{},
		&models.OAuthAccessToken{},
		&models.UserConsent{},
	)

	if err != nil {
		log.Fatal(err)
	}

	log.Println("Starting database seed...")

	admin, err := seedUsers(db)
	if err != nil {
		log.Fatal(err)
	}

	if err := seedOAuthClient(db, admin); err != nil {
		log.Fatal(err)
	}

	log.Println("=====================================")
	log.Println("Seed completed successfully")
	log.Println("")
	log.Println("Seeded Users")
	log.Println(" - admin@example.com")
	log.Println(" - demo@example.com")
	log.Println("")
	log.Println("Seeded OAuth Client")
	log.Println(" - Local Development Client")
	log.Println(" - Client ID: dev-client")
	log.Println("")
	log.Println("OAuth client secret configured via SEED_CLIENT_SECRET")
	log.Println("Credentials are intentionally not printed to logs.")
	log.Println("=====================================")
}

// Seed development users and OAuth clients.
// Safe to run multiple times.
func seedUsers(db *gorm.DB) (*models.User, error) {
	userRepo := repository.NewUserRepository(db)

	admin, err := createUserIfNotExists(
		userRepo,
		"admin@example.com",
		"Admin123!",
		"Admin",
		"User",
		"admin",
	)

	if err != nil {
		return nil, err
	}

	_, err = createUserIfNotExists(
		userRepo,
		"demo@example.com",
		"Demo123!",
		"Demo",
		"User",
		"user",
	)

	if err != nil {
		return nil, err
	}

	return admin, nil
}

func createUserIfNotExists(
	userRepo *repository.UserRepository,
	email string,
	password string,
	firstName string,
	lastName string,
	role string,
) (*models.User, error) {

	existing, err := userRepo.FindByEmail(email)

	if err == nil {
		log.Printf("User already exists: %s", email)
		return existing, nil
	}

	if err != repository.ErrUserNotFound {
		return nil, err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)

	if err != nil {
		return nil, err
	}

	user := &models.User{
		Email:         email,
		PasswordHash:  string(hashedPassword),
		FirstName:     firstName,
		LastName:      lastName,
		Role:          role,
		IsActive:      true,
		EmailVerified: true,
		OAuthProvider: "local",
	}

	if err := userRepo.Create(user); err != nil {
		return nil, err
	}

	log.Printf("Created user: %s", email)

	return user, nil
}

func seedOAuthClient(db *gorm.DB, admin *models.User) error {
	clientRepo := repository.NewOAuthClientRepository(db)

	existingClient, err := clientRepo.FindByClientID("dev-client")

	if err == nil && existingClient != nil {
		log.Println("OAuth client already exists")
		return nil
	}

	clientSecret := os.Getenv("SEED_CLIENT_SECRET")
	if clientSecret == "" {
		return fmt.Errorf("SEED_CLIENT_SECRET environment variable is required")
	}

	hashedSecret, err := bcrypt.GenerateFromPassword(
		[]byte(clientSecret),
		bcrypt.DefaultCost,
	)

	if err != nil {
		return err
	}

	client := &models.OAuthClient{
		Name:         "Local Development Client",
		ClientID:     "dev-client",
		ClientSecret: string(hashedSecret),
		RedirectURIs: pq.StringArray{
			"http://localhost:3000/callback",
			"http://localhost:5173/callback",
		},
		Scopes: pq.StringArray{
			"read:profile",
			"write:profile",
			"read:email",
		},
		OwnerID:  admin.ID,
		IsActive: true,
		IsPublic: false,
	}

	if err := clientRepo.Create(client); err != nil {
		return err
	}

	log.Println("Created OAuth client: Local Development Client")

	return nil
}