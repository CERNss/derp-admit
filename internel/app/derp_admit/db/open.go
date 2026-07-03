package db

import (
	"fmt"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func OpenDatabase(databaseURL string) (*gorm.DB, error) {
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
		return gorm.Open(sqlite.Open(path+sep+"_txlock=immediate"), &gorm.Config{
			Logger:         logger.Default.LogMode(logger.Silent),
			TranslateError: true,
		})
	case strings.HasPrefix(databaseURL, "postgres://"), strings.HasPrefix(databaseURL, "postgresql://"):
		return gorm.Open(postgres.Open(databaseURL), &gorm.Config{
			Logger:         logger.Default.LogMode(logger.Warn),
			TranslateError: true,
		})
	default:
		return nil, fmt.Errorf("unsupported DATABASE_URL scheme")
	}
}
