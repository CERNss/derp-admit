package startup

import (
	"context"

	"gorm.io/gorm"
)

// WithLock serializes startup schema migration, seeding, upgrade, and bootstrap
// key sync across instances sharing a database.
// Stub: runs fn directly until Track A implements database locking.
func WithLock(_ context.Context, _ *gorm.DB, fn func() error) error {
	return fn()
}
