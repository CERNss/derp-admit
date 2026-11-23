package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"derp-admit/internel/app/derp_admit/metrics"
	"derp-admit/internel/app/derp_admit/policy"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Option func(*Service)

func WithMetrics(r metrics.Recorder) Option {
	return func(s *Service) {
		if r != nil {
			s.metrics = r
		}
	}
}

func WithPolicySyncInterval(d time.Duration) Option {
	return func(s *Service) {
		if d > 0 {
			s.policySyncInterval = d
		}
	}
}

type Service struct {
	db                 *gorm.DB
	policy             policy.PolicyEngine
	tokenPepper        string
	dbTimeout          time.Duration
	policySyncInterval time.Duration
	cache              *VerifyCache
	logger             *zap.Logger
	metrics            metrics.Recorder
	sync               *syncer
}

func New(db *gorm.DB, policyEngine policy.PolicyEngine, tokenPepper string, dbTimeout time.Duration, cache *VerifyCache, logger *zap.Logger, opts ...Option) *Service {
	s := &Service{
		db:                 db,
		policy:             policyEngine,
		tokenPepper:        tokenPepper,
		dbTimeout:          dbTimeout,
		policySyncInterval: 2 * time.Second,
		cache:              cache,
		logger:             logger,
		metrics:            metrics.Nop,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	s.sync = newSyncer()
	return s
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
