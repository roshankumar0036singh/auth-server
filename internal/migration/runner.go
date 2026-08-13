// Package migration provides a tiny, versioned SQL migration runner
// (issue #190). Unlike GORM AutoMigrate, every schema change is an explicit
// versioned .sql file with an up/down pair, tracked in schema_migrations,
// so production changes are reviewable and reversible.
package migration

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
)

//go:embed files/*.sql
var migrationFiles embed.FS

// Migration is a single versioned, reversible schema change.
type Migration struct {
	Version int
	Name    string
	Up      string
	Down    string
}

// Load reads all embedded migration files, validates that every version has
// both an up and a down script, and returns them sorted by version.
func Load() ([]Migration, error) {
	entries, err := migrationFiles.ReadDir("files")
	if err != nil {
		return nil, err
	}

	byVersion := map[int]*Migration{}
	for _, e := range entries {
		name := e.Name() // e.g. 000001_baseline.up.sql
		var version int
		if _, err := fmt.Sscanf(name, "%d_", &version); err != nil {
			return nil, fmt.Errorf("migration file %q must be named NNNNNN_name.up.sql / .down.sql", name)
		}
		content, err := migrationFiles.ReadFile("files/" + name)
		if err != nil {
			return nil, err
		}
		m := byVersion[version]
		if m == nil {
			m = &Migration{Version: version}
			byVersion[version] = m
		}
		switch {
		case strings.HasSuffix(name, ".up.sql"):
			m.Name = strings.TrimSuffix(strings.TrimPrefix(name, fmt.Sprintf("%06d_", version)), ".up.sql")
			m.Up = string(content)
		case strings.HasSuffix(name, ".down.sql"):
			m.Down = string(content)
		default:
			return nil, fmt.Errorf("unexpected migration file %q", name)
		}
	}

	migs := make([]Migration, 0, len(byVersion))
	for _, m := range byVersion {
		if m.Up == "" || m.Down == "" {
			return nil, fmt.Errorf("migration %d must have both .up.sql and .down.sql", m.Version)
		}
		migs = append(migs, *m)
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].Version < migs[j].Version })
	return migs, nil
}

// Runner applies pending migrations against a database.
type Runner struct {
	db      *sql.DB
	driver  string
	migrate func(m Migration, direction string) error
}

// NewRunner wraps an existing database handle. driver is used only for
// dialects that need special SQL (e.g. sqlite ALTER quirks).
func NewRunner(db *sql.DB, driver string) (*Runner, error) {
	r := &Runner{db: db, driver: driver}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}
	return r, nil
}

// CurrentVersion returns the highest applied version (0 = none).
func (r *Runner) CurrentVersion() (int, error) {
	var v sql.NullInt64
	if err := r.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}

// Pending returns migrations newer than the current version.
func (r *Runner) Pending() ([]Migration, error) {
	migs, err := Load()
	if err != nil {
		return nil, err
	}
	current, err := r.CurrentVersion()
	if err != nil {
		return nil, err
	}
	out := []Migration{}
	for _, m := range migs {
		if m.Version > current {
			out = append(out, m)
		}
	}
	return out, nil
}

// Up applies every pending migration in a transaction, recording each
// version in schema_migrations immediately after success.
func (r *Runner) Up() (applied []int, err error) {
	pending, err := r.Pending()
	if err != nil {
		return nil, err
	}
	for _, m := range pending {
		if err := r.apply(m, true); err != nil {
			return applied, err
		}
		applied = append(applied, m.Version)
	}
	return applied, nil
}

// Down rolls back the n most recently applied migrations (n <= 0 = all).
func (r *Runner) Down(n int) (rolledBack []int, err error) {
	migs, err := Load()
	if err != nil {
		return nil, err
	}
	current, err := r.CurrentVersion()
	if err != nil {
		return nil, err
	}
	count := 0
	for i := len(migs) - 1; i >= 0 && (n <= 0 || count < n); i-- {
		if migs[i].Version <= current {
			if err := r.apply(migs[i], false); err != nil {
				return rolledBack, err
			}
			rolledBack = append(rolledBack, migs[i].Version)
			count++
		}
	}
	return rolledBack, nil
}

func (r *Runner) apply(m Migration, up bool) error {
	script := m.Down
	if up {
		script = m.Up
	}

	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range splitStatements(script) {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("migration %d (%s): %w\nstatement: %s", m.Version, m.Name, err, truncate(stmt))
		}
	}

	if up {
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, m.Version); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(`DELETE FROM schema_migrations WHERE version = ?`, m.Version); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// splitStatements splits a script into individual SQL statements, honoring
// simple '...' string literals so commas/newlines inside values don't split.
func splitStatements(script string) []string {
	statements := []string{}
	var current strings.Builder
	inSingle := false
	prev := byte(0)
	for i := 0; i < len(script); i++ {
		ch := script[i]
		if ch == '\'' && prev != '\\' {
			inSingle = !inSingle
		}
		if ch == ';' && !inSingle {
			statements = append(statements, current.String())
			current.Reset()
		} else {
			current.WriteByte(ch)
		}
		prev = ch
	}
	statements = append(statements, current.String())
	return statements
}

func truncate(s string) string {
	if len(s) > 200 {
		return strings.TrimSpace(s[:200]) + "..."
	}
	return strings.TrimSpace(s)
}

// ErrNoMigrations indicates an empty/unknown state.
var ErrNoMigrations = errors.New("no migrations found")
