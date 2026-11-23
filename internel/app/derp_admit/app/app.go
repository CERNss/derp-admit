package app

import (
	"context"
	"fmt"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/metrics"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/server"
	"derp-admit/internel/app/derp_admit/service"
	"derp-admit/internel/app/derp_admit/startup"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Option func(*buildOptions)

type buildOptions struct {
	metrics metrics.Recorder
}

func WithMetrics(r metrics.Recorder) Option {
	return func(o *buildOptions) {
		if r != nil {
			o.metrics = r
		}
	}
}

type App struct {
	DB      *gorm.DB
	Policy  *policy.Engine
	Service *service.Service
	Router  *gin.Engine
	Metrics metrics.Recorder
	cancel  context.CancelFunc
}

func (a *App) Close() {
	if a.cancel != nil {
		a.cancel()
	}
}

// Build initializes the application in the standard startup order:
// startup.WithLock(migrate -> policy.SeedBuiltins -> policy.RunUpgrade ->
// svc.SyncBootstrapKey) -> engine.Reload -> svc.StartSync -> router.
func Build(ctx context.Context, gormDB *gorm.DB, cfg config.Config, logger *zap.Logger, opts ...Option) (*App, error) {
	var defaultMetrics metrics.Recorder = metrics.Nop
	if cfg.MetricsEnabled {
		defaultMetrics = metrics.NewPrometheus()
	}
	bo := buildOptions{metrics: defaultMetrics}
	for _, opt := range opts {
		if opt != nil {
			opt(&bo)
		}
	}

	var policyEngine *policy.Engine
	var svc *service.Service
	verifyCache := service.NewVerifyCache(cfg.VerifyCacheTTL)

	if err := startup.WithLock(ctx, gormDB, func() error {
		if err := db.ApplyMigrations(ctx, gormDB, cfg.DatabaseURL); err != nil {
			return fmt.Errorf("apply migrations: %w", err)
		}

		if err := gormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			_, err := policy.SeedBuiltins(tx)
			return err
		}); err != nil {
			return fmt.Errorf("seed policy built-ins: %w", err)
		}

		if err := policy.RunUpgrade(ctx, gormDB, cfg.LegacyCasbinDisabled, logger); err != nil {
			return fmt.Errorf("run policy upgrade: %w", err)
		}

		var err error
		policyEngine, err = policy.NewEngine(gormDB, true)
		if err != nil {
			return fmt.Errorf("init policy: %w", err)
		}

		svc = service.New(
			gormDB,
			policyEngine,
			cfg.TokenPepper,
			cfg.DBTimeout,
			verifyCache,
			logger,
			service.WithAdminAPIKey(cfg.AdminAPIKey),
			service.WithMetrics(bo.metrics),
			service.WithPolicySyncInterval(cfg.PolicySyncInterval),
		)
		if err := svc.SyncBootstrapKey(ctx, cfg.AdminAPIKey); err != nil {
			return fmt.Errorf("sync bootstrap admin key: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if err := policyEngine.Reload(ctx); err != nil {
		return nil, fmt.Errorf("reload policy: %w", err)
	}

	syncCtx, cancel := context.WithCancel(context.Background())
	svc.StartSync(syncCtx)

	router := server.NewRouter(svc, cfg, logger, server.WithMetrics(bo.metrics))

	return &App{
		DB:      gormDB,
		Policy:  policyEngine,
		Service: svc,
		Router:  router,
		Metrics: bo.metrics,
		cancel:  cancel,
	}, nil
}
