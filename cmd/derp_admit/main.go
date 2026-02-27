package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/policy"
	"derp-admit/internel/app/derp_admit/server"
	"derp-admit/internel/app/derp_admit/service"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.LoadFromEnv()
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}

	gormDB, err := db.OpenDatabase(cfg.DatabaseURL)
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}

	mCtx, mCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer mCancel()
	if err := db.ApplyMigrations(mCtx, gormDB, cfg.DatabaseURL); err != nil {
		logger.Error("apply migrations", "error", err)
		os.Exit(1)
	}

	policyEngine, err := policy.NewEngine(gormDB, cfg.EnableCasbin)
	if err != nil {
		logger.Error("init policy", "error", err)
		os.Exit(1)
	}
	if err := policyEngine.Bootstrap(context.Background()); err != nil {
		logger.Error("bootstrap policy", "error", err)
		os.Exit(1)
	}

	verifyCache := service.NewVerifyCache(cfg.VerifyCacheTTL)
	svc := service.New(gormDB, policyEngine, cfg.TokenPepper, cfg.DBTimeout, verifyCache, logger)
	router := server.NewRouter(svc, cfg, logger)

	go func() {
		logger.Info("starting verifier server", "addr", cfg.Addr)
		if err := router.Run(cfg.Addr); err != nil {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Info("received shutdown signal")
}
