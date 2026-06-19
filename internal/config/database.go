package config

import (
	"database/sql"
	"fmt"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// InitDatabase initializes database with proper connection pool configuration
func InitDatabase(dbConfig DBConfig) error {
    // Build DSN (Data Source Name)
    dsn := fmt.Sprintf(
        "%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
        dbConfig.User,
        dbConfig.Password,
        dbConfig.Host,
        dbConfig.Port,
        dbConfig.Database,
    )

    // Connect to database using GORM
    db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
        Logger: logger.Default.LogMode(logger.Info),
    })
    if err != nil {
        return fmt.Errorf("failed to connect to database: %w", err)
    }

    // Get the underlying *sql.DB instance
    sqlDB, err := db.DB()
    if err != nil {
        return fmt.Errorf("failed to get database instance: %w", err)
    }

    // ============================================
    // Configure Connection Pool (KEY SETTINGS!)
    // ============================================
    sqlDB.SetMaxOpenConns(dbConfig.MaxOpenConns)
    log.Printf("✓ MaxOpenConns set to: %d", dbConfig.MaxOpenConns)

    sqlDB.SetMaxIdleConns(dbConfig.MaxIdleConns)
    log.Printf("✓ MaxIdleConns set to: %d", dbConfig.MaxIdleConns)

    sqlDB.SetConnMaxLifetime(dbConfig.ConnMaxLifetime)
    log.Printf("✓ ConnMaxLifetime set to: %v", dbConfig.ConnMaxLifetime)

    sqlDB.SetConnMaxIdleTime(dbConfig.ConnMaxIdleTime)
    log.Printf("✓ ConnMaxIdleTime set to: %v", dbConfig.ConnMaxIdleTime)

    // Verify the connection
    if err := sqlDB.Ping(); err != nil {
        return fmt.Errorf("failed to ping database: %w", err)
    }

    DB = db
    log.Println("✓ Database connected successfully with optimized connection pooling")
    return nil
}

// GetDBStats returns current database connection pool statistics
func GetDBStats() map[string]interface{} {
    if DB == nil {
        return map[string]interface{}{"error": "database not initialized"}
    }

    sqlDB, _ := DB.DB()
    stats := sqlDB.Stats()

    return map[string]interface{}{
        "open_connections": stats.OpenConnections,
        "in_use":           stats.InUse,
        "idle":             stats.Idle,
        "wait_count":       stats.WaitCount,
        "wait_duration":    stats.WaitDuration.String(),
        "max_idle_closed":  stats.MaxIdleClosed,
        "max_lifetime_closed": stats.MaxLifetimeClosed,
    }
}

// HealthCheckDatabase checks if database connection pool is healthy
func HealthCheckDatabase() map[string]interface{} {
    if DB == nil {
        return map[string]interface{}{
            "healthy": false,
            "message": "database not initialized",
        }
    }

    sqlDB, _ := DB.DB()
    stats := sqlDB.Stats()

    // Check connectivity
    if err := sqlDB.Ping(); err != nil {
        return map[string]interface{}{
            "healthy": false,
            "message": fmt.Sprintf("database unreachable: %v", err),
        }
    }

    // Check if connections are exhausted
    if stats.OpenConnections >= 95 { // 95% of 100
        return map[string]interface{}{
            "healthy": false,
            "message": fmt.Sprintf("connection pool near capacity: %d connections", 
                stats.OpenConnections),
            "stats": GetDBStats(),
        }
    }

    return map[string]interface{}{
        "healthy": true,
        "message": "database connection pool healthy",
        "stats":   GetDBStats(),
    }
}
