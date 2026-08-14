package config

import (
	"fmt"
	"log"

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

	// Connection pool settings (issue #187). Sanitize misconfigurations so
	// GORM's "unlimited" defaults can never silently exhaust PG connections:
	//   - max open conns must be > 0 (default 25)
	//   - max idle conns is clamped to max open conns
	//   - idle conns can be 0 (explicitly close when idle)
	maxOpen := cfg.Database.PoolMax
	if maxOpen <= 0 {
		maxOpen = 25
	}
	maxIdle := cfg.Database.PoolMin
	if maxIdle < 0 {
		maxIdle = 0
	}
	if maxIdle > maxOpen {
		maxIdle = maxOpen
	}

	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetMaxIdleConns(maxIdle)
	sqlDB.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(cfg.Database.ConnMaxIdleTime)

	// Fail fast: surface connection/pool problems at startup, not at first
	// request under load.
	if err := sqlDB.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Printf("Database connected successfully (pool min=%d max=%d)", maxIdle, maxOpen)

	return db
}

// PoolSize derives the effective max-open/max-idle sizes, mirroring the
// sanitization applied in InitDatabase. Exported for tests.
func (c DatabaseConfig) PoolSize() (maxIdle, maxOpen int) {
	maxOpen = c.PoolMax
	if maxOpen <= 0 {
		maxOpen = 25
	}
	maxIdle = c.PoolMin
	if maxIdle < 0 {
		maxIdle = 0
	}
	if maxIdle > maxOpen {
		maxIdle = maxOpen
	}
	return maxIdle, maxOpen
}

func AutoMigrate(db *gorm.DB, models ...interface{}) error {
	if err := db.AutoMigrate(models...); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}
	log.Println("Database migration completed successfully")
	return nil
}
