package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/server"
	"derp-admit/internel/app/derp_admit/service"
	"derp-admit/internel/app/derp_admit/telemetry"

	"go.uber.org/zap"
)

func main() {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	logger, err := telemetry.NewLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	shutdownOTel, err := telemetry.SetupOTel(context.Background(), cfg, logger)
	if err != nil {
		logger.Error("init telemetry", zap.Error(err))
		os.Exit(1)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownOTel(ctx); err != nil {
			logger.Warn("shutdown telemetry", zap.Error(err))
		}
	}()

	gormDB, err := db.OpenDatabase(cfg.DatabaseURL)
	if err != nil {
		logger.Error("open database", zap.Error(err))
		os.Exit(1)
	}

	mCtx, mCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer mCancel()
	if err := db.ApplyMigrations(mCtx, gormDB, cfg.DatabaseURL); err != nil {
		logger.Error("apply migrations", zap.Error(err))
		os.Exit(1)
	}

	policyEngine, err := policy.NewEngine(gormDB, cfg.EnableCasbin)
	if err != nil {
		logger.Error("init policy", zap.Error(err))
		os.Exit(1)
	}
	if err := policyEngine.Bootstrap(context.Background()); err != nil {
		logger.Error("bootstrap policy", zap.Error(err))
		os.Exit(1)
	}

	verifyCache := service.NewVerifyCache(cfg.VerifyCacheTTL)
	svc := service.New(gormDB, policyEngine, cfg.TokenPepper, cfg.DBTimeout, verifyCache, logger)
	router := server.NewRouter(svc, cfg, logger)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting verifier server", zap.String("addr", cfg.Addr))
		if err := router.Run(cfg.Addr); err != nil {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		logger.Info("received shutdown signal", zap.String("signal", sig.String()))
	case err := <-errCh:
		logger.Error("server stopped", zap.Error(err))
		os.Exit(1)
	}
}
