package db_test

import (
	"context"
	"path/filepath"
	"testing"

	"derp-admit/internal/db"

	"gorm.io/gorm"
)

func TestApplyMigrationsSQLite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "migrate.db")
	dbURL := "sqlite://" + dbPath

	conn, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	if err := db.ApplyMigrations(context.Background(), conn, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	expectTableExists(t, conn, "users")
	expectTableExists(t, conn, "enroll_tokens")
	expectTableExists(t, conn, "devices")
	expectTableExists(t, conn, "audit_logs")
}

func expectTableExists(t *testing.T, conn *gorm.DB, table string) {
	t.Helper()

	var count int64
	if err := conn.Raw(`SELECT COUNT(1) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count).Error; err != nil {
		t.Fatalf("query sqlite_master for %s: %v", table, err)
	}
	if count != 1 {
		t.Fatalf("table %s does not exist", table)
	}
}
