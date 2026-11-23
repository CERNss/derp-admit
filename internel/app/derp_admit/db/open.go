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

// NewLogger constructs a gorm logger that suppresses ErrRecordNotFound noise
// and keeps SQL parameterized so bound secrets/hashes are never printed.
func NewLogger(w logger.Writer, level logger.LogLevel) logger.Interface {
	return logger.New(w, logger.Config{
		SlowThreshold:             200 * time.Millisecond,
		LogLevel:                  level,
		IgnoreRecordNotFoundError: true,
		ParameterizedQueries:      true,
		Colorful:                  false,
	})
}

func OpenDatabase(databaseURL string) (*gorm.DB, error) {
	stdWriter := log.New(os.Stdout, "\r\n", log.LstdFlags)
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
		return gorm.Open(sqlite.Open(path+sep+"_txlock=immediate&_busy_timeout=5000"), &gorm.Config{
			Logger:         NewLogger(stdWriter, logger.Silent),
			TranslateError: true,
		})
	case strings.HasPrefix(databaseURL, "postgres://"), strings.HasPrefix(databaseURL, "postgresql://"):
		return gorm.Open(postgres.Open(databaseURL), &gorm.Config{
			Logger:         NewLogger(stdWriter, logger.Warn),
			TranslateError: true,
		})
	default:
		return nil, fmt.Errorf("unsupported DATABASE_URL scheme")
	}
}
