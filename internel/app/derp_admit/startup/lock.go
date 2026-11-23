package startup

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"gorm.io/gorm"
)

// AdvisoryLockKey is the fixed PostgreSQL session-level advisory lock key
// (ASCII "derpadmi") used to serialize startup migrations, seeding, one-time
// upgrade, and bootstrap key synchronization across replicas.
const AdvisoryLockKey int64 = 0x6465727061646d69

const (
	unlockTimeout   = 5 * time.Second
	flockPollPeriod = 10 * time.Millisecond
)

var (
	sqliteLocksMu sync.Mutex
	sqliteLocks   = make(map[string]chan struct{})
)

// WithLock serializes startup schema migration, seeding, upgrade, and bootstrap
// key sync across instances sharing a database.
//
// On PostgreSQL it acquires a session-level advisory lock on a dedicated
// connection from the pool and releases it on the same connection in a defer
// using a detached timeout context so failure, panic, or cancellation of ctx
// never leaks the lock.
//
// On SQLite it serializes callers per database path in-process and across
// processes via an advisory file lock on "<dbpath>.startup.lock" (or an
// in-process semaphore for in-memory databases), leaving SQLite's own
// _txlock=immediate write transactions free to execute inside fn without
// self-deadlocking.
func WithLock(ctx context.Context, gormDB *gorm.DB, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if gormDB == nil {
		return fn()
	}

	switch gormDB.Dialector.Name() {
	case "postgres":
		return withPostgresLock(ctx, gormDB, fn)
	case "sqlite":
		return withSQLiteLock(ctx, gormDB, fn)
	default:
		return fn()
	}
}

func withPostgresLock(ctx context.Context, gormDB *gorm.DB, fn func() error) (retErr error) {
	sqlDB, err := gormDB.DB()
	if err != nil {
		return fmt.Errorf("startup lock db handle: %w", err)
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("startup lock acquire connection: %w", err)
	}

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", AdvisoryLockKey); err != nil {
		// Guard against the narrow race where ctx cancels right as
		// pg_advisory_lock completes on the server: issue a best-effort
		// unlock on this session, and if unlock cannot be confirmed discard
		// the connection so a locked session never returns to the pool.
		if ctx.Err() != nil {
			unlockCtx, cancel := context.WithTimeout(context.Background(), unlockTimeout)
			_, unlockErr := conn.ExecContext(unlockCtx, "SELECT pg_advisory_unlock($1)", AdvisoryLockKey)
			cancel()
			if unlockErr != nil {
				discardConn(conn)
			}
		} else {
			discardConn(conn)
		}
		_ = conn.Close()
		return fmt.Errorf("acquire startup advisory lock: %w", err)
	}

	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), unlockTimeout)
		defer cancel()

		var unlocked bool
		if err := conn.QueryRowContext(unlockCtx, "SELECT pg_advisory_unlock($1)", AdvisoryLockKey).Scan(&unlocked); err != nil || !unlocked {
			// Drop the session rather than returning a potentially still-locked
			// connection to the pool.
			discardConn(conn)
			if err != nil && retErr == nil {
				retErr = fmt.Errorf("release startup advisory lock: %w", err)
			}
		}
		_ = conn.Close()
	}()

	return fn()
}

func discardConn(conn *sql.Conn) {
	_ = conn.Raw(func(any) error {
		return driver.ErrBadConn
	})
}

type sqliteDBInfo struct {
	Seq  int    `gorm:"column:seq"`
	Name string `gorm:"column:name"`
	File string `gorm:"column:file"`
}

func withSQLiteLock(ctx context.Context, gormDB *gorm.DB, fn func() error) error {
	var infos []sqliteDBInfo
	if err := gormDB.WithContext(ctx).Raw("PRAGMA database_list").Scan(&infos).Error; err != nil {
		return fmt.Errorf("startup lock inspect sqlite database: %w", err)
	}
	var dbFile string
	for _, info := range infos {
		if info.Name == "main" {
			dbFile = info.File
			break
		}
	}

	memKey := dbFile
	if memKey == "" {
		sqlDB, err := gormDB.DB()
		if err != nil {
			return fmt.Errorf("startup lock db handle: %w", err)
		}
		memKey = fmt.Sprintf("memory:%p", sqlDB)
	} else if abs, err := filepath.Abs(dbFile); err == nil {
		memKey = abs
	}

	sem := sqliteSemFor(memKey)
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("acquire startup lock: %w", ctx.Err())
	}
	defer func() { <-sem }()

	if dbFile != "" {
		lockPath := dbFile + ".startup.lock"
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return fmt.Errorf("open sqlite startup lock file %q: %w", lockPath, err)
		}
		if err := acquireFlock(ctx, f); err != nil {
			_ = f.Close()
			return fmt.Errorf("acquire sqlite startup file lock: %w", err)
		}
		defer func() {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
		}()
	}

	return fn()
}

func sqliteSemFor(key string) chan struct{} {
	sqliteLocksMu.Lock()
	defer sqliteLocksMu.Unlock()
	sem, ok := sqliteLocks[key]
	if !ok {
		sem = make(chan struct{}, 1)
		sqliteLocks[key] = sem
	}
	return sem
}

func acquireFlock(ctx context.Context, f *os.File) error {
	fd := int(f.Fd())
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		timer := time.NewTimer(flockPollPeriod)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
