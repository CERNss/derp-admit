package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"derp-admit/internel/app/derp_admit/policy"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Service struct {
	db          *gorm.DB
	policy      *policy.Engine
	tokenPepper string
	dbTimeout   time.Duration
	cache       *VerifyCache
	logger      *zap.Logger
}

func New(db *gorm.DB, policyEngine *policy.Engine, tokenPepper string, dbTimeout time.Duration, cache *VerifyCache, logger *zap.Logger) *Service {
	return &Service{
		db:          db,
		policy:      policyEngine,
		tokenPepper: tokenPepper,
		dbTimeout:   dbTimeout,
		cache:       cache,
		logger:      logger,
	}
}

func loggerWithTrace(logger *zap.Logger, ctx context.Context) *zap.Logger {
	spanCtx := trace.SpanContextFromContext(ctx)
	if !spanCtx.IsValid() {
		return logger
	}

	return logger.With(
		zap.String("trace_id", spanCtx.TraceID().String()),
		zap.String("span_id", spanCtx.SpanID().String()),
	)
}

func (s *Service) Ping(ctx context.Context) error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return fmt.Errorf("get sql db: %w", err)
	}
	return sqlDB.PingContext(ctx)
}

func (s *Service) hashToken(token string) string {
	sum := sha256.Sum256([]byte(token + ":" + s.tokenPepper))
	return hex.EncodeToString(sum[:])
}
