package db

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strings"
	"time"

	"derp-admit/internel/app/derp_admit/model"

	"gorm.io/gorm"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func ApplyMigrations(ctx context.Context, gormDB *gorm.DB, databaseURL string) error {
	if strings.HasPrefix(databaseURL, "sqlite://") {
		return gormDB.WithContext(ctx).AutoMigrate(
			&model.User{},
			&model.EnrollToken{},
			&model.Device{},
			&model.AuditLog{},
		)
	}

	if err := gormDB.WithContext(ctx).Exec(`
CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`).Error; err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	files, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	names := make([]string, 0, len(files))
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sql") {
			continue
		}
		names = append(names, file.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		var count int64
		if err := gormDB.WithContext(ctx).Raw(
			`SELECT COUNT(1) FROM schema_migrations WHERE version = ?`,
			name,
		).Scan(&count).Error; err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if count > 0 {
			continue
		}

		content, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		if err := gormDB.WithContext(ctx).Exec(string(content)).Error; err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if err := gormDB.WithContext(ctx).Exec(
			`INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`,
			name,
			time.Now().UTC(),
		).Error; err != nil {
			return fmt.Errorf("record migration %s: %w", name, err)
		}
	}

	return nil
}
