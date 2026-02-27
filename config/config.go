package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr               string
	DatabaseURL        string
	TokenPepper        string
	LogLevel           string
	EnableCasbin       bool
	OTELEnabled        bool
	OTELServiceName    string
	OTLPEndpoint       string
	OTLPInsecure       bool
	OTELSampleRatio    float64
	DBTimeout          time.Duration
	VerifyRateLimitRPS float64
	VerifyRateBurst    int
	VerifyCacheTTL     time.Duration
}

func LoadFromEnv() (Config, error) {
	cfg := Config{
		Addr:               getOrDefault("ADDR", ":8080"),
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		TokenPepper:        os.Getenv("TOKEN_PEPPER"),
		LogLevel:           getOrDefault("LOG_LEVEL", "info"),
		EnableCasbin:       getBool("ENABLE_CASBIN", true),
		OTELEnabled:        getBool("OTEL_ENABLED", false),
		OTELServiceName:    getOrDefault("OTEL_SERVICE_NAME", "derp-admit"),
		OTLPEndpoint:       os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		OTLPInsecure:       getBool("OTEL_EXPORTER_OTLP_INSECURE", true),
		OTELSampleRatio:    getFloat("OTEL_TRACE_SAMPLE_RATIO", 1.0),
		DBTimeout:          getDuration("DB_TIMEOUT", 2*time.Second),
		VerifyRateLimitRPS: getFloat("VERIFY_RATE_LIMIT_RPS", 100),
		VerifyRateBurst:    getInt("VERIFY_RATE_LIMIT_BURST", 200),
		VerifyCacheTTL:     getDuration("VERIFY_CACHE_TTL", 0),
	}

	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.TokenPepper == "" {
		return Config{}, fmt.Errorf("TOKEN_PEPPER is required")
	}
	if cfg.VerifyRateLimitRPS <= 0 {
		return Config{}, fmt.Errorf("VERIFY_RATE_LIMIT_RPS must be > 0")
	}
	if cfg.VerifyRateBurst <= 0 {
		return Config{}, fmt.Errorf("VERIFY_RATE_LIMIT_BURST must be > 0")
	}
	if cfg.DBTimeout <= 0 {
		return Config{}, fmt.Errorf("DB_TIMEOUT must be > 0")
	}
	if cfg.OTELSampleRatio < 0 || cfg.OTELSampleRatio > 1 {
		return Config{}, fmt.Errorf("OTEL_TRACE_SAMPLE_RATIO must be between 0 and 1")
	}
	if cfg.OTELServiceName == "" {
		return Config{}, fmt.Errorf("OTEL_SERVICE_NAME must not be empty")
	}

	return cfg, nil
}

func getOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func getBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getFloat(key string, fallback float64) float64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func getDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
