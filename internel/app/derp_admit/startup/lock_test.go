package startup_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/startup"

	"gorm.io/gorm"
)

func aOpenSQLiteFile(t *testing.T, path string) *gorm.DB {
	t.Helper()
	gormDB, err := db.OpenDatabase("sqlite://" + path)
	if err != nil {
		t.Fatalf("open sqlite %s: %v", path, err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return gormDB
}

func TestWithLockSerializesConcurrentCallers(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "lock.db")
	const workers = 6
	dbs := make([]*gorm.DB, workers)
	for i := range dbs {
		dbs[i] = aOpenSQLiteFile(t, dbPath)
	}

	var active atomic.Int32
	var maxActive atomic.Int32
	var ran atomic.Int32
	start := make(chan struct{})
	errCh := make(chan error, workers)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(conn *gorm.DB) {
			defer wg.Done()
			<-start
			errCh <- startup.WithLock(context.Background(), conn, func() error {
				cur := active.Add(1)
				for {
					prev := maxActive.Load()
					if cur <= prev || maxActive.CompareAndSwap(prev, cur) {
						break
					}
				}
				time.Sleep(15 * time.Millisecond)
				ran.Add(1)
				active.Add(-1)
				return nil
			})
		}(dbs[i])
	}
	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("WithLock error: %v", err)
		}
	}
	if maxActive.Load() != 1 {
		t.Fatalf("max concurrent holders=%d want=1", maxActive.Load())
	}
	if ran.Load() != workers {
		t.Fatalf("callbacks executed=%d want=%d", ran.Load(), workers)
	}
}

func TestWithLockReleasesOnError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "release-err.db")
	conn1 := aOpenSQLiteFile(t, dbPath)
	conn2 := aOpenSQLiteFile(t, dbPath)

	boom := errors.New("boom")
	err := startup.WithLock(context.Background(), conn1, func() error {
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err=%v want=%v", err, boom)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	called := false
	if err := startup.WithLock(ctx, conn2, func() error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("second WithLock after error failed: %v", err)
	}
	if !called {
		t.Fatalf("second callback did not run")
	}
}

func TestWithLockRespectsContextCancel(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cancel.db")
	conn1 := aOpenSQLiteFile(t, dbPath)
	conn2 := aOpenSQLiteFile(t, dbPath)

	acquired := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)

	go func() {
		holderDone <- startup.WithLock(context.Background(), conn1, func() error {
			close(acquired)
			<-release
			return nil
		})
	}()

	<-acquired

	waitCtx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	waitErr := startup.WithLock(waitCtx, conn2, func() error {
		return nil
	})
	if !errors.Is(waitErr, context.DeadlineExceeded) {
		t.Fatalf("waiter err=%v want DeadlineExceeded", waitErr)
	}

	close(release)
	if err := <-holderDone; err != nil {
		t.Fatalf("holder err=%v", err)
	}

	// After holder finishes, conn2 can acquire cleanly.
	ctx, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if err := startup.WithLock(ctx, conn2, func() error { return nil }); err != nil {
		t.Fatalf("post-release acquire failed: %v", err)
	}
}

func TestWithLockInMemorySQLite(t *testing.T) {
	gormDB, err := db.OpenDatabase("sqlite://:memory:")
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	var active atomic.Int32
	var maxActive atomic.Int32
	var wg sync.WaitGroup
	errCh := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- startup.WithLock(context.Background(), gormDB, func() error {
				if cur := active.Add(1); cur > maxActive.Load() {
					maxActive.Store(cur)
				}
				time.Sleep(10 * time.Millisecond)
				active.Add(-1)
				return nil
			})
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("WithLock in-memory err: %v", err)
		}
	}
	if maxActive.Load() != 1 {
		t.Fatalf("max concurrent holders=%d want=1", maxActive.Load())
	}
}

func aOpenFreshPostgresDB(t *testing.T) (string, *gorm.DB) {
	t.Helper()

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
		t.Fatalf("random suffix: %v", err)
	}
	dbName := "derp_admit_lock_" + hex.EncodeToString(raw)

	adminDB, err := db.OpenDatabase(baseURL)
	if err != nil {
		t.Fatalf("open postgres admin db: %v", err)
	}
	if err := adminDB.Exec(fmt.Sprintf(`CREATE DATABASE %s`, dbName)).Error; err != nil {
		t.Fatalf("create database %s: %v", dbName, err)
	}

	testURL := *parsed
	testURL.Path = "/" + dbName
	dbURL := testURL.String()

	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		_ = adminDB.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, dbName)).Error
		t.Fatalf("open test database: %v", err)
	}

	t.Cleanup(func() {
		if sqlDB, err := gormDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
		_ = adminDB.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ? AND pid <> pg_backend_pid()`, dbName).Error
		_ = adminDB.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, dbName)).Error
		if sqlAdmin, err := adminDB.DB(); err == nil {
			_ = sqlAdmin.Close()
		}
	})

	return dbURL, gormDB
}

func TestWithLockPostgresAdvisoryLock(t *testing.T) {
	dbURL, conn1 := aOpenFreshPostgresDB(t)
	conn2, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open second postgres pool: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := conn2.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	// 1. Holder acquires lock; waiter cancels while waiting; holder cancels ctx
	//    mid-fn and returns error; lock is still released so conn2 succeeds next.
	acquired := make(chan struct{})
	release := make(chan struct{})
	holderCtx, cancelHolder := context.WithCancel(context.Background())
	holderDone := make(chan error, 1)
	boom := errors.New("fn failed")

	go func() {
		holderDone <- startup.WithLock(holderCtx, conn1, func() error {
			close(acquired)
			<-release
			cancelHolder()
			return boom
		})
	}()

	<-acquired

	waitCtx, cancelWait := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelWait()
	if err := startup.WithLock(waitCtx, conn2, func() error { return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("postgres waiter err=%v want DeadlineExceeded", err)
	}

	close(release)
	if err := <-holderDone; !errors.Is(err, boom) {
		t.Fatalf("holder err=%v want=%v", err, boom)
	}

	// Lock must have been released even though holderCtx was cancelled and fn failed.
	nextCtx, cancelNext := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelNext()
	if err := startup.WithLock(nextCtx, conn2, func() error { return nil }); err != nil {
		t.Fatalf("re-acquire postgres advisory lock after cancel+error failed: %v", err)
	}
}
