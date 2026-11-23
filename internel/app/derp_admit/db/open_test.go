package db_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type bufLogWriter struct {
	buf bytes.Buffer
}

func (w *bufLogWriter) Printf(format string, args ...any) {
	_, _ = fmt.Fprintf(&w.buf, format+"\n", args...)
}

func TestDatabaseLogHasNoBoundValues(t *testing.T) {
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "log-safety.db")
	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.ApplyMigrations(context.Background(), gormDB, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	const (
		sentinelNotFound = "SENTINEL_HASH_NOT_FOUND_9f8e7d6c5b4a"
		sentinelError    = "SENTINEL_HASH_ERROR_1a2b3c4d5e6f"
		sentinelInfo     = "SENTINEL_HASH_INFO_778899aabbcc"
	)

	warnWriter := &bufLogWriter{}
	warnDB := gormDB.Session(&gorm.Session{
		Logger: db.NewLogger(warnWriter, logger.Warn),
	})

	// 1. Unknown-key lookup (ErrRecordNotFound): must NOT be logged and sentinel must be absent.
	var key model.AdminKey
	err = warnDB.Where("key_hash = ?", sentinelNotFound).First(&key).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("unknown-key lookup err=%v want ErrRecordNotFound", err)
	}
	if warnWriter.buf.Len() != 0 {
		t.Fatalf("ErrRecordNotFound was unexpectedly logged: %q", warnWriter.buf.String())
	}
	if strings.Contains(warnWriter.buf.String(), sentinelNotFound) {
		t.Fatalf("not-found sentinel leaked into log: %q", warnWriter.buf.String())
	}

	// 2. Statement forced to fail: error IS logged, but bound sentinel must be absent.
	err = warnDB.Where("nonexistent_column_for_test = ?", sentinelError).First(&key).Error
	if err == nil {
		t.Fatalf("expected SQL error for nonexistent column")
	}
	logged := warnWriter.buf.String()
	if strings.TrimSpace(logged) == "" {
		t.Fatalf("expected failed statement to be logged at warn level")
	}
	if strings.Contains(logged, sentinelError) {
		t.Fatalf("bound sentinel leaked into failed SQL log: %q", logged)
	}

	// 3. Even at Info level, ParameterizedQueries keeps bound values out of SQL logs.
	infoWriter := &bufLogWriter{}
	infoDB := gormDB.Session(&gorm.Session{
		Logger: db.NewLogger(infoWriter, logger.Info),
	})
	var count int64
	if err := infoDB.Model(&model.AdminKey{}).Where("key_hash = ?", sentinelInfo).Count(&count).Error; err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	infoLogged := infoWriter.buf.String()
	if strings.TrimSpace(infoLogged) == "" {
		t.Fatalf("expected info-level logger to emit SQL")
	}
	if strings.Contains(infoLogged, sentinelInfo) {
		t.Fatalf("bound sentinel leaked into info SQL log: %q", infoLogged)
	}
}
