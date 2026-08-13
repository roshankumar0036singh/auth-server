package migration_test

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/glebarez/sqlite"
	"github.com/roshankumar0036singh/auth-server/internal/migration"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestLoadValidatesPairs(t *testing.T) {
	migs, err := migration.Load()
	require.NoError(t, err)
	require.NotEmpty(t, migs)
	for _, m := range migs {
		assert.NotEmpty(t, m.Up, "version %d needs .up.sql", m.Version)
		assert.NotEmpty(t, m.Down, "version %d needs .down.sql", m.Version)
	}
	// sorted ascending, contiguous starting at 1
	for i, m := range migs {
		assert.Equal(t, i+1, m.Version)
	}
}

func TestUpTracksHistory(t *testing.T) {
	db := openTestDB(t)
	runner, err := migration.NewRunner(db, "sqlite")
	require.NoError(t, err)

	assert.Equal(t, 0, mustCurrent(t, runner))
	applied, err := runner.Up()
	require.NoError(t, err)
	require.NotEmpty(t, applied)

	// tables created by baseline
	var n int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n))
	assert.Equal(t, 0, n)

	assert.Equal(t, len(applied), mustCurrent(t, runner))
	pending, err := runner.Pending()
	require.NoError(t, err)
	assert.Empty(t, pending, "second Up run must be a no-op")

	// idempotency
	again, err := runner.Up()
	require.NoError(t, err)
	assert.Empty(t, again)
}

func TestDownRollsBack(t *testing.T) {
	db := openTestDB(t)
	runner, err := migration.NewRunner(db, "sqlite")
	require.NoError(t, err)
	applied, err := runner.Up()
	require.NoError(t, err)
	total := len(applied)

	rolled, err := runner.Down(2)
	require.NoError(t, err)
	require.Len(t, rolled, 2)
	assert.Equal(t, total-2, mustCurrent(t, runner))

	// rolled-back tables are gone
	var n int
	err = db.QueryRow("SELECT COUNT(*) FROM api_keys").Scan(&n)
	require.Error(t, err, "api_keys (version 5) must no longer exist")

	// roll back the rest
	rest, err := runner.Down(0)
	require.NoError(t, err)
	require.Len(t, rest, total-2)
	assert.Equal(t, 0, mustCurrent(t, runner))
	require.Error(t, db.QueryRow("SELECT COUNT(*) FROM users").Scan(new(int)), "baseline down must drop users")
}

func TestMigrationUpAppliesColumnChanges(t *testing.T) {
	db := openTestDB(t)
	runner, err := migration.NewRunner(db, "sqlite")
	require.NoError(t, err)
	_, err = runner.Up()
	require.NoError(t, err)

	// oauth_clients has TTL columns (migration 3)
	_, err = db.Exec("INSERT INTO oauth_clients (id, name, client_id, client_secret, access_token_ttl_seconds, refresh_token_ttl_seconds) VALUES ('c1','x','c1x','sec',900,0)")
	require.NoError(t, err)

	// audit_logs has chain columns (migration 2)
	_, err = db.Exec("INSERT INTO audit_logs (id, action, prev_hash, hash) VALUES ('a1','LOGIN','0','abc')")
	require.NoError(t, err)

	// device fingerprints table exists (migration 4)
	_, err = db.Exec("INSERT INTO device_fingerprints (id, user_id, hash) VALUES ('d1','u1','h1')")
	require.NoError(t, err)
}

func mustCurrent(t *testing.T, r *migration.Runner) int {
	t.Helper()
	v, err := r.CurrentVersion()
	require.NoError(t, err)
	return v
}

func tableCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM "+table).Scan(&n))
	return n
}
