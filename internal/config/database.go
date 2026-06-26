package config

import (
	"errors"
	"fmt"
	"log"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func InitDatabase(cfg *Config) *gorm.DB {
	var logLevel logger.LogLevel
	if cfg.App.Env == "production" {
		logLevel = logger.Silent
	} else {
		logLevel = logger.Info
	}

	db, err := gorm.Open(postgres.Open(cfg.Database.URL), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})

	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal("Failed to get database instance:", err)
	}

	sqlDB.SetMaxIdleConns(cfg.Database.PoolMin)
	sqlDB.SetMaxOpenConns(cfg.Database.PoolMax)

	log.Println("Database connected successfully")

	return db
}

func RunMigrations(db *gorm.DB) error {
	log.Println("🔄 Checking versioned database migrations...")

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to extract sql instance: %w", err)
	}

	driver, err := postgres.WithInstance(sqlDB, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to initialize migration driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres",
		driver,
	)
	if err != nil {
		return fmt.Errorf("failed to build migration engine wrapper: %w", err)
	}

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			log.Println("✅ Database schema is already fully up to date.")
			return nil
		}
		return fmt.Errorf("critical failure executing migrations: %w", err)
	}

	log.Println("🎉 Versioned database migrations executed successfully!")
	return nil
}
