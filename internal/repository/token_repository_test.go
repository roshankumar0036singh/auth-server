package repository

import (
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func setupTokenMockDB(t *testing.T) (*gorm.DB, sqlmock.Sqlmock, *TokenRepository) {
	dbMock, sqlMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to open sqlmock: %v", err)
	}

	dialector := postgres.New(postgres.Config{
		Conn: dbMock,
	})
	gormDB, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open gorm instance: %v", err)
	}

	repo := NewTokenRepository(gormDB)
	return gormDB, sqlMock, repo
}

type anyTokenArg struct{}

func (a anyTokenArg) Match(v driver.Value) bool {
	return true
}

func TestCreateRefreshToken(t *testing.T) {
	_, sqlMock, repo := setupTokenMockDB(t)

	token := &models.RefreshToken{
		ID:     "tok-1",
		Token:  "rt-string",
		UserID: "usr-1",
	}

	sqlMock.ExpectBegin()
	sqlMock.ExpectExec(`INSERT INTO "refresh_tokens"`).
		WithArgs(
			anyTokenArg{}, anyTokenArg{}, anyTokenArg{}, anyTokenArg{}, anyTokenArg{},
			anyTokenArg{}, anyTokenArg{}, anyTokenArg{}, anyTokenArg{}, anyTokenArg{},
			anyTokenArg{},
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	sqlMock.ExpectCommit()

	err := repo.CreateRefreshToken(token)
	if err != nil {
		t.Errorf("Expected successful token creation, got %v", err)
	}
}

func TestFindRefreshToken(t *testing.T) {
	t.Run("Success path", func(t *testing.T) {
		_, sqlMock, repo := setupTokenMockDB(t)
		rows := sqlmock.NewRows([]string{"id", "token"}).AddRow("tok-1", "rt-string")

		sqlMock.ExpectQuery(`SELECT \* FROM "refresh_tokens" WHERE token = \$1 ORDER BY "refresh_tokens"\."id" LIMIT \$2`).
			WithArgs("rt-string", 1).
			WillReturnRows(rows)

		token, err := repo.FindRefreshToken("rt-string")
		if err != nil || token.ID != "tok-1" {
			t.Errorf("Expected token lookup success, got err: %v", err)
		}
	})

	t.Run("Not found path", func(t *testing.T) {
		_, sqlMock, repo := setupTokenMockDB(t)
		sqlMock.ExpectQuery(`SELECT \* FROM "refresh_tokens" WHERE token = \$1`).
			WillReturnError(gorm.ErrRecordNotFound)

		_, err := repo.FindRefreshToken("missing")
		if !errors.Is(err, ErrRefreshTokenNotFound) {
			t.Errorf("Expected ErrRefreshTokenNotFound, got %v", err)
		}
	})
}

func TestFindRefreshTokenByID(t *testing.T) {
	_, sqlMock, repo := setupTokenMockDB(t)
	rows := sqlmock.NewRows([]string{"id"}).AddRow("tok-1")

	sqlMock.ExpectQuery(`SELECT \* FROM "refresh_tokens" WHERE id = \$1 ORDER BY "refresh_tokens"\."id" LIMIT \$2`).
		WithArgs("tok-1", 1).
		WillReturnRows(rows)

	token, err := repo.FindRefreshTokenByID("tok-1")
	if err != nil || token.ID != "tok-1" {
		t.Errorf("Expected safe lookup by ID, got %v", err)
	}
}

func TestFindUserRefreshTokens(t *testing.T) {
	_, sqlMock, repo := setupTokenMockDB(t)
	rows := sqlmock.NewRows([]string{"id", "user_id"}).AddRow("tok-1", "usr-1").AddRow("tok-2", "usr-1")

	sqlMock.ExpectQuery(`SELECT \* FROM "refresh_tokens" WHERE user_id = \$1 AND is_revoked = \$2 ORDER BY created_at DESC`).
		WithArgs("usr-1", false).
		WillReturnRows(rows)

	tokens, err := repo.FindUserRefreshTokens("usr-1")
	if err != nil || len(tokens) != 2 {
		t.Errorf("Expected 2 tokens, got %v with error %v", len(tokens), err)
	}
}

func TestRevokeRefreshToken(t *testing.T) {
	t.Run("Success revoke", func(t *testing.T) {
		_, sqlMock, repo := setupTokenMockDB(t)
		sqlMock.ExpectBegin()
		sqlMock.ExpectExec(`UPDATE "refresh_tokens" SET "is_revoked"=\$1,"updated_at"=\$2 WHERE token = \$3`).
			WithArgs(true, anyTokenArg{}, "rt-string").
			WillReturnResult(sqlmock.NewResult(1, 1))
		sqlMock.ExpectCommit()

		err := repo.RevokeRefreshToken("rt-string")
		if err != nil {
			t.Errorf("Expected valid revocation sequence, got %v", err)
		}
	})

	t.Run("Not found revoke", func(t *testing.T) {
		_, sqlMock, repo := setupTokenMockDB(t)
		sqlMock.ExpectBegin()
		sqlMock.ExpectExec(`UPDATE "refresh_tokens" SET "is_revoked"=\$1,"updated_at"=\$2 WHERE token = \$3`).
			WithArgs(true, anyTokenArg{}, "missing-token").
			WillReturnResult(sqlmock.NewResult(0, 0))
		sqlMock.ExpectCommit()

		err := repo.RevokeRefreshToken("missing-token")
		if !errors.Is(err, ErrRefreshTokenNotFound) {
			t.Errorf("Expected ErrRefreshTokenNotFound, got %v", err)
		}
	})
}

func TestRevokeRefreshTokenByID(t *testing.T) {
	_, sqlMock, repo := setupTokenMockDB(t)
	sqlMock.ExpectBegin()
	sqlMock.ExpectExec(`UPDATE "refresh_tokens" SET "is_revoked"=\$1,"updated_at"=\$2 WHERE id = \$3`).
		WithArgs(true, anyTokenArg{}, "tok-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	sqlMock.ExpectCommit()

	err := repo.RevokeRefreshTokenByID("tok-1")
	if err != nil {
		t.Errorf("Expected smooth execution tracking updates, got %v", err)
	}
}

func TestRevokeAllUserTokens(t *testing.T) {
	_, sqlMock, repo := setupTokenMockDB(t)
	sqlMock.ExpectBegin()
	sqlMock.ExpectExec(`UPDATE "refresh_tokens" SET "is_revoked"=\$1,"updated_at"=\$2 WHERE user_id = \$3 AND is_revoked = \$4`).
		WithArgs(true, anyTokenArg{}, "usr-1", false).
		WillReturnResult(sqlmock.NewResult(1, 5))
	sqlMock.ExpectCommit()

	err := repo.RevokeAllUserTokens("usr-1")
	if err != nil {
		t.Errorf("Expected broad database commit scope, got %v", err)
	}
}

func TestRevokeTokenFamily(t *testing.T) {
	t.Run("Empty Family ID Error", func(t *testing.T) {
		_, _, repo := setupTokenMockDB(t)
		err := repo.RevokeTokenFamily("")
		if err == nil {
			t.Errorf("Expected early failure exit validation criteria constraint")
		}
	})

	t.Run("Valid Execution Family Path", func(t *testing.T) {
		_, sqlMock, repo := setupTokenMockDB(t)
		sqlMock.ExpectBegin()
		sqlMock.ExpectExec(`UPDATE "refresh_tokens" SET "is_revoked"=\$1,"updated_at"=\$2 WHERE family_id = \$3 AND is_revoked = \$4`).
			WithArgs(true, anyTokenArg{}, "fam-99", false).
			WillReturnResult(sqlmock.NewResult(1, 2))
		sqlMock.ExpectCommit()

		err := repo.RevokeTokenFamily("fam-99")
		if err != nil {
			t.Errorf("Expected clean batch execution context trace, got %v", err)
		}
	})
}

func TestDeleteExpiredTokens(t *testing.T) {
	_, sqlMock, repo := setupTokenMockDB(t)
	sqlMock.ExpectBegin()
	sqlMock.ExpectExec(`DELETE FROM "refresh_tokens" WHERE expires_at < \$1`).
		WithArgs(anyTokenArg{}).
		WillReturnResult(sqlmock.NewResult(1, 12))
	sqlMock.ExpectCommit()

	count, err := repo.DeleteExpiredTokens()
	if err != nil || count != 12 {
		t.Errorf("Expected 12 records swept, got count: %d, err: %v", count, err)
	}
}

func TestDeleteRevokedTokens(t *testing.T) {
	_, sqlMock, repo := setupTokenMockDB(t)
	sqlMock.ExpectBegin()
	sqlMock.ExpectExec(`DELETE FROM "refresh_tokens" WHERE is_revoked = \$1 AND updated_at < \$2`).
		WithArgs(true, anyTokenArg{}).
		WillReturnResult(sqlmock.NewResult(1, 8))
	sqlMock.ExpectCommit()

	count, err := repo.DeleteRevokedTokens(24 * time.Hour)
	if err != nil || count != 8 {
		t.Errorf("Expected 8 matching records dropped, got %d", count)
	}
}

func TestCountUserActiveSessions(t *testing.T) {
	_, sqlMock, repo := setupTokenMockDB(t)
	rows := sqlmock.NewRows([]string{"count"}).AddRow(int64(3))

	sqlMock.ExpectQuery(`SELECT count\(\*\) FROM "refresh_tokens" WHERE user_id = \$1 AND is_revoked = \$2 AND expires_at > \$3`).
		WithArgs("usr-1", false, anyTokenArg{}).
		WillReturnRows(rows)

	count, err := repo.CountUserActiveSessions("usr-1")
	if err != nil || count != 3 {
		t.Errorf("Expected active session calculation of 3, got %d", count)
	}
}

func TestRotateRefreshToken(t *testing.T) {
	t.Run("Rotation Error on old token not found", func(t *testing.T) {
		_, sqlMock, repo := setupTokenMockDB(t)
		sqlMock.ExpectBegin()
		sqlMock.ExpectExec(`UPDATE "refresh_tokens" SET "is_revoked"=\$1,"updated_at"=\$2 WHERE token = \$3 AND is_revoked = \$4`).
			WithArgs(true, anyTokenArg{}, "old-rt", false).
			WillReturnResult(sqlmock.NewResult(0, 0))
		sqlMock.ExpectRollback()

		newToken := &models.RefreshToken{ID: "tok-new"}
		err := repo.RotateRefreshToken("old-rt", newToken)
		if !errors.Is(err, ErrRefreshTokenNotFound) {
			t.Errorf("Expected ErrRefreshTokenNotFound tracking lifecycle rollback, got %v", err)
		}
	})

	t.Run("Rotation Success full process", func(t *testing.T) {
		_, sqlMock, repo := setupTokenMockDB(t)
		newToken := &models.RefreshToken{ID: "tok-new", Token: "new-rt"}

		sqlMock.ExpectBegin()
		sqlMock.ExpectExec(`UPDATE "refresh_tokens" SET "is_revoked"=\$1,"updated_at"=\$2 WHERE token = \$3 AND is_revoked = \$4`).
			WithArgs(true, anyTokenArg{}, "old-rt", false).
			WillReturnResult(sqlmock.NewResult(1, 1))
		
		sqlMock.ExpectExec(`INSERT INTO "refresh_tokens"`).
			WithArgs(
				anyTokenArg{}, anyTokenArg{}, anyTokenArg{}, anyTokenArg{}, anyTokenArg{},
				anyTokenArg{}, anyTokenArg{}, anyTokenArg{}, anyTokenArg{}, anyTokenArg{},
				anyTokenArg{},
			).
			WillReturnResult(sqlmock.NewResult(1, 1))
		sqlMock.ExpectCommit()

		err := repo.RotateRefreshToken("old-rt", newToken)
		if err != nil {
			t.Errorf("Expected clean atomicity loop commit context, got %v", err)
		}
	})
}