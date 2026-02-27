package telemetry

import (
	"context"
	"fmt"
	"strings"

	"derp-admit/config"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewLogger(level string) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	cfg.Encoding = "json"
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.MessageKey = "msg"
	cfg.EncoderConfig.LevelKey = "level"
	cfg.EncoderConfig.CallerKey = "caller"
	cfg.EncoderConfig.StacktraceKey = "stacktrace"
	cfg.EncoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	lvl := strings.TrimSpace(strings.ToLower(level))
	if lvl == "" {
		lvl = "info"
	}
	if err := cfg.Level.UnmarshalText([]byte(lvl)); err != nil {
		return nil, fmt.Errorf("invalid LOG_LEVEL %q: %w", level, err)
	}

	logger, err := cfg.Build()
	if err != nil {
		return nil, fmt.Errorf("build zap logger: %w", err)
	}
	return logger, nil
}

func SetupOTel(ctx context.Context, cfg config.Config, logger *zap.Logger) (func(context.Context) error, error) {
	if !cfg.OTELEnabled {
		return func(context.Context) error { return nil }, nil
	}

	opts := []otlptracehttp.Option{}
	if cfg.OTLPEndpoint != "" {
		opts = append(opts, otlptracehttp.WithEndpoint(cfg.OTLPEndpoint))
	}
	if cfg.OTLPInsecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}

	resource, err := sdkresource.New(ctx,
		sdkresource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.OTELServiceName),
		),
		sdkresource.WithHost(),
		sdkresource.WithOS(),
		sdkresource.WithProcess(),
		sdkresource.WithContainer(),
	)
	if err != nil {
		return nil, fmt.Errorf("create otel resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(resource),
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(
			sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.OTELSampleRatio)),
		),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	logger.Info("otel tracing enabled",
		zap.String("service_name", cfg.OTELServiceName),
		zap.String("otlp_endpoint", cfg.OTLPEndpoint),
		zap.Bool("otlp_insecure", cfg.OTLPInsecure),
		zap.Float64("sample_ratio", cfg.OTELSampleRatio),
	)

	return tp.Shutdown, nil
}
