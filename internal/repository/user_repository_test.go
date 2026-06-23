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

func setupMockDB(t *testing.T) (*gorm.DB, sqlmock.Sqlmock, *UserRepository) {
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

	repo := NewUserRepository(gormDB)
	return gormDB, sqlMock, repo
}

type anyArg struct{}

func (a anyArg) Match(v driver.Value) bool {
	return true
}

func TestFindByID(t *testing.T) {
	t.Run("Success path", func(t *testing.T) {
		_, sqlMock, repo := setupMockDB(t)
		rows := sqlmock.NewRows([]string{"id", "email"}).AddRow("usr-123", "test@example.com")
		
		sqlMock.ExpectQuery(`SELECT \* FROM "users" WHERE id = \$1 AND "users"\."deleted_at" IS NULL`).
			WithArgs("usr-123", 1).
			WillReturnRows(rows)

		user, err := repo.FindByID("usr-123")
		if err != nil {
			t.Errorf("Expected nil error, got %v", err)
		}
		if user == nil || user.ID != "usr-123" {
			t.Errorf("Returned wrong user record setup")
		}
	})

	t.Run("Not found path", func(t *testing.T) {
		_, sqlMock, repo := setupMockDB(t)
		sqlMock.ExpectQuery(`SELECT \* FROM "users" WHERE id = \$1 AND "users"\."deleted_at" IS NULL`).
			WillReturnError(gorm.ErrRecordNotFound)

		_, err := repo.FindByID("invalid-id")
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("Expected ErrUserNotFound, got %v", err)
		}
	})
}

func TestFindByEmail(t *testing.T) {
	t.Run("Success path", func(t *testing.T) {
		_, sqlMock, repo := setupMockDB(t)
		rows := sqlmock.NewRows([]string{"id", "email"}).AddRow("usr-123", "test@example.com")
		
		sqlMock.ExpectQuery(`SELECT \* FROM "users" WHERE email = \$1 AND "users"\."deleted_at" IS NULL`).
			WithArgs("test@example.com", 1).
			WillReturnRows(rows)

		user, err := repo.FindByEmail("test@example.com")
		if err != nil || user == nil {
			t.Fatalf("Expected valid user lookup, got error: %v", err)
		}
	})

	t.Run("Not found path", func(t *testing.T) {
		_, sqlMock, repo := setupMockDB(t)
		sqlMock.ExpectQuery(`SELECT \* FROM "users" WHERE email = \$1 AND "users"\."deleted_at" IS NULL`).
			WillReturnError(gorm.ErrRecordNotFound)

		_, err := repo.FindByEmail("missing@example.com")
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("Expected custom error wrapper, got %v", err)
		}
	})
}

func TestCreateUser(t *testing.T) {
	_, sqlMock, repo := setupMockDB(t)

	user := &models.User{
		ID:    "usr-789",
		Email: "new@example.com",
	}

	sqlMock.ExpectBegin()
	// GORM executes a driver Exec command for standard inserts without returning clauses
	sqlMock.ExpectExec(`INSERT INTO "users"`).
		WithArgs(
			user.ID, user.Email, "", "", "", "", false, false, true, "", 
			"local", "", false, "", "user", 0, nil, anyArg{}, anyArg{}, nil, nil,
		).
		WillReturnResult(sqlmock.NewResult(1, 1)) // Return 1 row affected successfully
	sqlMock.ExpectCommit()

	err := repo.Create(user)
	if err != nil {
		t.Errorf("Expected smooth execution creation block, got %v", err)
	}
}

func TestUpdateUser(t *testing.T) {
	t.Run("Success update path", func(t *testing.T) {
		_, sqlMock, repo := setupMockDB(t)
		sqlMock.ExpectBegin()
		sqlMock.ExpectExec(`UPDATE "users" SET "email"=\$1,"updated_at"=\$2 WHERE id = \$3 AND "users"\."deleted_at" IS NULL`).
			WithArgs("updated@example.com", anyArg{}, "usr-123").
			WillReturnResult(sqlmock.NewResult(1, 1))
		sqlMock.ExpectCommit()

		err := repo.Update("usr-123", map[string]interface{}{"email": "updated@example.com"})
		if err != nil {
			t.Errorf("Expected nil error updating, got %v", err)
		}
	})

	t.Run("No rows affected returns not found", func(t *testing.T) {
		_, sqlMock, repo := setupMockDB(t)
		sqlMock.ExpectBegin()
		sqlMock.ExpectExec(`UPDATE "users" SET "email"=\$1,"updated_at"=\$2 WHERE id = \$3 AND "users"\."deleted_at" IS NULL`).
			WithArgs("err@example.com", anyArg{}, "missing-id").
			WillReturnResult(sqlmock.NewResult(0, 0))
		sqlMock.ExpectCommit()

		err := repo.Update("missing-id", map[string]interface{}{"email": "err@example.com"})
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("Expected ErrUserNotFound error response, got %v", err)
		}
	})
}

func TestDeleteUser(t *testing.T) {
	_, sqlMock, repo := setupMockDB(t)

	t.Run("Success delete path", func(t *testing.T) {
		sqlMock.ExpectBegin()
		sqlMock.ExpectExec(`UPDATE "users" SET "deleted_at"=\$1 WHERE id = \$2 AND "users"\."deleted_at" IS NULL`).
			WithArgs(anyArg{}, "usr-123").
			WillReturnResult(sqlmock.NewResult(1, 1))
		sqlMock.ExpectCommit()

		err := repo.Delete("usr-123")
		if err != nil {
			t.Errorf("Expected clean delete pass, got %v", err)
		}
	})
}

func TestEmailExists(t *testing.T) {
	_, sqlMock, repo := setupMockDB(t)

	rows := sqlmock.NewRows([]string{"count"}).AddRow(int64(1))
	sqlMock.ExpectQuery(`SELECT count\(\*\) FROM "users" WHERE email = \$1 AND "users"\."deleted_at" IS NULL`).
		WithArgs("check@example.com").
		WillReturnRows(rows)

	exists, err := repo.EmailExists("check@example.com")
	if err != nil || !exists {
		t.Errorf("Expected true checking existing entity vector pattern values")
	}
}

func TestLockAndUnlockUser(t *testing.T) {
	t.Run("Lock User", func(t *testing.T) {
		_, sqlMock, repo := setupMockDB(t)
		lockTime := time.Now().Add(1 * time.Hour)
		
		sqlMock.ExpectBegin()
		sqlMock.ExpectExec(`UPDATE "users" SET "locked_until"=\$1,"updated_at"=\$2 WHERE id = \$3 AND "users"\."deleted_at" IS NULL`).
			WithArgs(lockTime, anyArg{}, "usr-123").
			WillReturnResult(sqlmock.NewResult(1, 1))
		sqlMock.ExpectCommit()

		err := repo.LockUser("usr-123", lockTime)
		if err != nil {
			t.Errorf("Expected successful account locking execution path, got %v", err)
		}
	})

	t.Run("Unlock User", func(t *testing.T) {
		_, sqlMock, repo := setupMockDB(t)
		sqlMock.ExpectBegin()
		sqlMock.ExpectExec(`UPDATE "users" SET "failed_login_attempts"=\$1,"locked_until"=\$2,"updated_at"=\$3 WHERE id = \$4 AND "users"\."deleted_at" IS NULL`).
			WithArgs(0, nil, anyArg{}, "usr-123").
			WillReturnResult(sqlmock.NewResult(1, 1))
		sqlMock.ExpectCommit()

		err := repo.UnlockUser("usr-123")
		if err != nil {
			t.Errorf("Expected successful unlocking sequence paths, got %v", err)
		}
	})
}