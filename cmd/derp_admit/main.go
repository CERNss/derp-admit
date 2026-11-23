package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"derp-admit/config"
	"derp-admit/internel/app/derp_admit/app"
	"derp-admit/internel/app/derp_admit/db"
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

	buildCtx, buildCancel := context.WithTimeout(context.Background(), 30*time.Second)
	application, err := app.Build(buildCtx, gormDB, cfg, logger)
	buildCancel()
	if err != nil {
		logger.Error("build application", zap.Error(err))
		os.Exit(1)
	}
	defer application.Close()

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           application.Router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting verifier server", zap.String("addr", cfg.Addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		logger.Info("received shutdown signal", zap.String("signal", sig.String()))
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("graceful shutdown failed", zap.Error(err))
		}
	case err := <-errCh:
		logger.Error("server stopped", zap.Error(err))
		os.Exit(1)
	}
}
