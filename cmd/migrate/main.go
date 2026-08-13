// Command migrate executes versioned SQL migrations (issue #190).
//
// Usage:
//
//	DATABASE_URL=postgres://... go run ./cmd/migrate up           # apply pending
//	DATABASE_URL=postgres://... go run ./cmd/migrate down         # rollback all
//	DATABASE_URL=postgres://... go run ./cmd/migrate down 2       # rollback two
//	DATABASE_URL=postgres://... go run ./cmd/migrate status       # show applied versions
//
// The runner tracks history in schema_migrations and executes each migration
// transactionally. Files live in internal/migration/files and are embedded
// into the binary.
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/roshankumar0036singh/auth-server/internal/migration"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
	}
	command := args[0]

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	driver := "postgres"
	if len(dsn) < 9 || dsn[:9] != "postgres:" {
		driver = "sqlite"
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		log.Fatalf("ping database: %v", err)
	}

	runner, err := migration.NewRunner(db, driver)
	if err != nil {
		log.Fatalf("init runner: %v", err)
	}

	switch command {
	case "up":
		applied, err := runner.Up()
		if err != nil {
			log.Fatalf("up: %v", err)
		}
		if len(applied) == 0 {
			fmt.Println("no pending migrations")
			return
		}
		fmt.Printf("applied %d migration(s): %v\n", len(applied), applied)
	case "down":
		n := 0
		if len(args) > 1 {
			n, err = strconv.Atoi(args[1])
			if err != nil || n < 0 {
				log.Fatalf("down: count must be a non-negative integer")
			}
		}
		rolled, err := runner.Down(n)
		if err != nil {
			log.Fatalf("down: %v", err)
		}
		if len(rolled) == 0 {
			fmt.Println("nothing to roll back")
			return
		}
		fmt.Printf("rolled back %d migration(s): %v\n", len(rolled), rolled)
	case "status":
		current, err := runner.CurrentVersion()
		if err != nil {
			log.Fatalf("status: %v", err)
		}
		pending, err := runner.Pending()
		if err != nil {
			log.Fatalf("status: %v", err)
		}
		fmt.Printf("current version: %d\n", current)
		fmt.Printf("pending: %d\n", len(pending))
		for _, m := range pending {
			fmt.Printf("  - %06d %s\n", m.Version, m.Name)
		}
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: DATABASE_URL=<dsn> migrate <up|down [n]|status>`)
	os.Exit(1)
}
