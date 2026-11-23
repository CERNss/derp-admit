package db

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// NewGormLogger constructs the shared gorm logger configuration used by
// OpenDatabase for both backends. When w is nil it writes to os.Stdout.
// ErrRecordNotFound is suppressed and SQL remains parameterized so bound
// secrets and hashes are never logged.
func NewGormLogger(w logger.Writer) logger.Interface {
	if w == nil {
		w = log.New(os.Stdout, "\r\n", log.LstdFlags)
	}
	return logger.New(w, logger.Config{
		SlowThreshold:             200 * time.Millisecond,
		LogLevel:                  logger.Warn,
		IgnoreRecordNotFoundError: true,
		ParameterizedQueries:      true,
		Colorful:                  false,
	})
}

func OpenDatabase(databaseURL string) (*gorm.DB, error) {
	return OpenDatabaseWithLogWriter(databaseURL, nil)
}

// OpenDatabaseWithLogWriter opens databaseURL using the standard gorm logger
// configuration writing to w (or os.Stdout when w is nil).
func OpenDatabaseWithLogWriter(databaseURL string, w logger.Writer) (*gorm.DB, error) {
	gormCfg := &gorm.Config{
		Logger:         NewGormLogger(w),
		TranslateError: true,
	}
	switch {
	case strings.HasPrefix(databaseURL, "sqlite://"):
		path := strings.TrimPrefix(databaseURL, "sqlite://")
		// _txlock=immediate makes every write transaction take the database
		// lock at BEGIN. Deferred transactions that read first and then
		// escalate to a write can deadlock against each other, which sqlite
		// resolves by returning SQLITE_BUSY immediately (bypassing
		// busy_timeout); immediate transactions instead queue on the lock.
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		return gorm.Open(sqlite.Open(path+sep+"_txlock=immediate&_busy_timeout=5000"), gormCfg)
	case strings.HasPrefix(databaseURL, "postgres://"), strings.HasPrefix(databaseURL, "postgresql://"):
		return gorm.Open(postgres.Open(databaseURL), gormCfg)
	default:
		return nil, fmt.Errorf("unsupported DATABASE_URL scheme")
	}
}
