package db_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type bufLogWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *bufLogWriter) Printf(format string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = fmt.Fprintf(&w.buf, format+"\n", args...)
}

func (w *bufLogWriter) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Reset()
}

func (w *bufLogWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func assertDatabaseLogHasNoBoundValues(t *testing.T, dbURL string) {
	t.Helper()

	bufWriter := &bufLogWriter{}
	gormDB, err := db.OpenDatabaseWithLogWriter(dbURL, bufWriter)
	if err != nil {
		t.Fatalf("OpenDatabaseWithLogWriter: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.ApplyMigrations(context.Background(), gormDB, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	// Reset after migrations in case DDL took >= SlowThreshold on a busy host.
	bufWriter.Reset()

	const (
		sentinelNotFound = "SENTINEL_HASH_NOT_FOUND_9f8e7d6c5b4a"
		sentinelSuccess  = "SENTINEL_HASH_SUCCESS_7c6d5e4f3a2b"
		sentinelError    = "SENTINEL_HASH_ERROR_1a2b3c4d5e6f"
	)

	// 1. Unknown-row lookup (ErrRecordNotFound): the default warn-level log must
	//    be completely empty (no "record not found" and no bound sentinel).
	var key model.AdminKey
	err = gormDB.Where("key_hash = ?", sentinelNotFound).First(&key).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("unknown-key lookup err=%v want ErrRecordNotFound", err)
	}
	if afterNotFound := bufWriter.String(); afterNotFound != "" {
		t.Fatalf("expected empty warn-level log on ErrRecordNotFound, got: %q", afterNotFound)
	}

	// 2. Successful statement logged at Info level through the same gorm logger:
	//    the SQL statement IS logged, while its bound sentinel value is absent.
	infoDB := gormDB.Session(&gorm.Session{Logger: gormDB.Logger.LogMode(gormlogger.Info)})
	var count int64
	if err := infoDB.Model(&model.AdminKey{}).Where("key_hash = ?", sentinelSuccess).Count(&count).Error; err != nil {
		t.Fatalf("info-level count query: %v", err)
	}
	afterSuccess := bufWriter.String()
	if !strings.Contains(afterSuccess, "admin_keys") {
		t.Fatalf("expected successful statement to be logged at Info level, got: %q", afterSuccess)
	}
	if strings.Contains(afterSuccess, sentinelSuccess) {
		t.Fatalf("bound sentinel leaked into Info-level SQL log: %q", afterSuccess)
	}
	bufWriter.Reset()

	// 3. Statement forced to fail at default Warn level: the failing statement IS
	//    logged, while the bound sentinel and "record not found" are absent.
	err = gormDB.Where("nonexistent_column_for_test = ?", sentinelError).First(&key).Error
	if err == nil {
		t.Fatalf("expected SQL error for nonexistent column")
	}
	logged := bufWriter.String()
	if !strings.Contains(logged, "nonexistent_column_for_test") {
		t.Fatalf("expected failing statement to be logged, got: %q", logged)
	}
	if strings.Contains(logged, sentinelError) {
		t.Fatalf("bound sentinel leaked into failed SQL log: %q", logged)
	}
	if strings.Contains(strings.ToLower(logged), "record not found") {
		t.Fatalf("unexpected 'record not found' in log: %q", logged)
	}
}

func TestDatabaseLogHasNoBoundValues(t *testing.T) {
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "log-safety.db")
	assertDatabaseLogHasNoBoundValues(t, dbURL)
}

func TestPostgresDatabaseLogHasNoBoundValues(t *testing.T) {
	baseURL := os.Getenv("TEST_POSTGRES_URL")
	if baseURL == "" {
		t.Skip("TEST_POSTGRES_URL is not set")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse TEST_POSTGRES_URL: %v", err)
	}
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("random db suffix: %v", err)
	}
	dbName := "derp_admit_log_" + hex.EncodeToString(raw)

	adminDB, err := db.OpenDatabase(baseURL)
	if err != nil {
		t.Fatalf("open postgres admin db: %v", err)
	}
	if err := adminDB.Exec(fmt.Sprintf(`CREATE DATABASE %s`, dbName)).Error; err != nil {
		t.Fatalf("create database %s: %v", dbName, err)
	}
	t.Cleanup(func() {
		_ = adminDB.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ? AND pid <> pg_backend_pid()`, dbName).Error
		_ = adminDB.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, dbName)).Error
		if sqlAdmin, err := adminDB.DB(); err == nil {
			_ = sqlAdmin.Close()
		}
	})

	testURL := *parsed
	testURL.Path = "/" + dbName
	assertDatabaseLogHasNoBoundValues(t, testURL.String())
}
