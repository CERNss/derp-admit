package policy_test

import (
	"context"
	"path/filepath"
	"testing"

	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/policy"

	"gorm.io/gorm"
)

func TestBootstrapIdempotent(t *testing.T) {
	dbConn := openPolicyTestDB(t)

	engine, err := policy.NewEngine(dbConn, true)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	if err := engine.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap #1: %v", err)
	}
	if err := engine.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap #2: %v", err)
	}

	var count int64
	if err := dbConn.Raw(
		`SELECT COUNT(1) FROM casbin_rule WHERE ptype = ? AND v0 = ? AND v1 = ? AND v2 = ?`,
		"p",
		"role:standard",
		"derp:default",
		"connect",
	).Scan(&count).Error; err != nil {
		t.Fatalf("count baseline policy rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("baseline policy row count=%d want=1", count)
	}
}

func openPolicyTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "policy.db")
	dbURL := "sqlite://" + dbPath

	conn, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.ApplyMigrations(context.Background(), conn, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	return conn
}
