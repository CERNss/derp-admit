package startup_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/startup"

	"gorm.io/driver/postgres"
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

type fakePGConnector struct {
	failUnlock atomic.Bool
	opened     atomic.Int64
	closed     atomic.Int64
}

func (c *fakePGConnector) Connect(context.Context) (driver.Conn, error) {
	c.opened.Add(1)
	return &fakePGConn{parent: c}, nil
}

func (c *fakePGConnector) Driver() driver.Driver { return fakePGDriver{} }

type fakePGDriver struct{}

func (fakePGDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

type fakePGConn struct {
	parent *fakePGConnector
	closed atomic.Bool
}

func (c *fakePGConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *fakePGConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }
func (c *fakePGConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.parent.closed.Add(1)
	}
	return nil
}

func (c *fakePGConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "pg_advisory_lock") {
		return driver.RowsAffected(0), nil
	}
	if strings.Contains(query, "pg_advisory_unlock") {
		if c.parent.failUnlock.Load() {
			return nil, errors.New("simulated unlock failure")
		}
		return driver.RowsAffected(0), nil
	}
	return driver.RowsAffected(0), nil
}

func (c *fakePGConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "pg_advisory_unlock") {
		if c.parent.failUnlock.Load() {
			return nil, errors.New("simulated unlock failure")
		}
		return &fakeBoolRows{val: true}, nil
	}
	return &fakeBoolRows{val: true}, nil
}

type fakeBoolRows struct {
	val  bool
	done bool
}

func (r *fakeBoolRows) Columns() []string { return []string{"pg_advisory_unlock"} }
func (r *fakeBoolRows) Close() error      { return nil }
func (r *fakeBoolRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.val
	return nil
}

func TestWithLockPostgresDiscardsConnOnUnlockFailure(t *testing.T) {
	connector := &fakePGConnector{}
	sqlDB := sql.OpenDB(connector)
	t.Cleanup(func() { _ = sqlDB.Close() })

	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn:                 sqlDB,
		PreferSimpleProtocol: true,
	}), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open gorm with fake postgres conn: %v", err)
	}

	// Normal unlock succeeds: connection is returned to the pool (not closed).
	if err := startup.WithLock(context.Background(), gormDB, func() error { return nil }); err != nil {
		t.Fatalf("WithLock healthy unlock: %v", err)
	}
	if gotOpened, gotClosed := connector.opened.Load(), connector.closed.Load(); gotOpened != 1 || gotClosed != 0 {
		t.Fatalf("healthy unlock: opened=%d closed=%d want opened=1 closed=0", gotOpened, gotClosed)
	}

	// Failed unlock: error is returned and the connection is discarded (closed)
	// rather than returned to the pool still holding the session advisory lock.
	connector.failUnlock.Store(true)
	if err := startup.WithLock(context.Background(), gormDB, func() error { return nil }); err == nil {
		t.Fatalf("expected error when pg_advisory_unlock fails")
	}
	if gotClosed := connector.closed.Load(); gotClosed != 1 {
		t.Fatalf("failed unlock must discard connection: closed=%d want=1", gotClosed)
	}

	// Next WithLock must open a fresh connection rather than reusing the discarded one.
	connector.failUnlock.Store(false)
	if err := startup.WithLock(context.Background(), gormDB, func() error { return nil }); err != nil {
		t.Fatalf("WithLock after discard: %v", err)
	}
	if gotOpened := connector.opened.Load(); gotOpened != 2 {
		t.Fatalf("after discard opened=%d want=2", gotOpened)
	}
}
