package policy

import (
	"context"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// RunUpgrade is the stub for the one-time policy upgrade (Track A).
func RunUpgrade(_ context.Context, _ *gorm.DB, _ bool, _ *zap.Logger) error {
	return nil
}
