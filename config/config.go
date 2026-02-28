package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultConfigFilePath = "config/config.yaml"
	defaultEnvFilePath    = ".env"
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

type fileConfig struct {
	Addr               *string  `yaml:"addr"`
	DatabaseURL        *string  `yaml:"database_url"`
	TokenPepper        *string  `yaml:"token_pepper"`
	LogLevel           *string  `yaml:"log_level"`
	EnableCasbin       *bool    `yaml:"enable_casbin"`
	OTELEnabled        *bool    `yaml:"otel_enabled"`
	OTELServiceName    *string  `yaml:"otel_service_name"`
	OTLPEndpoint       *string  `yaml:"otel_exporter_otlp_endpoint"`
	OTLPInsecure       *bool    `yaml:"otel_exporter_otlp_insecure"`
	OTELSampleRatio    *float64 `yaml:"otel_trace_sample_ratio"`
	DBTimeout          *string  `yaml:"db_timeout"`
	VerifyRateLimitRPS *float64 `yaml:"verify_rate_limit_rps"`
	VerifyRateBurst    *int     `yaml:"verify_rate_limit_burst"`
	VerifyCacheTTL     *string  `yaml:"verify_cache_ttl"`
}

func LoadFromEnv() (Config, error) {
	cfg := defaultConfig()

	configFilePath := getEnvOrDefault("CONFIG_FILE", nil, defaultConfigFilePath)
	if err := mergeFromYAMLFile(&cfg, configFilePath); err != nil {
		return Config{}, err
	}

	envFileVars, err := loadEnvFile(getEnvOrDefault("ENV_FILE", nil, defaultEnvFilePath))
	if err != nil {
		return Config{}, err
	}

	if err := mergeFromEnv(&cfg, envFileVars); err != nil {
		return Config{}, err
	}

	if err := validate(cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func defaultConfig() Config {
	return Config{
		Addr:               ":8080",
		LogLevel:           "info",
		EnableCasbin:       true,
		OTELEnabled:        false,
		OTELServiceName:    "derp-admit",
		OTLPEndpoint:       "",
		OTLPInsecure:       true,
		OTELSampleRatio:    1.0,
		DBTimeout:          2 * time.Second,
		VerifyRateLimitRPS: 100,
		VerifyRateBurst:    200,
		VerifyCacheTTL:     0,
	}
}

func mergeFromYAMLFile(cfg *Config, path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read config file %q: %w", path, err)
	}

	var fc fileConfig
	if err := yaml.Unmarshal(content, &fc); err != nil {
		return fmt.Errorf("parse config file %q: %w", path, err)
	}

	if fc.Addr != nil {
		cfg.Addr = *fc.Addr
	}
	if fc.DatabaseURL != nil {
		cfg.DatabaseURL = *fc.DatabaseURL
	}
	if fc.TokenPepper != nil {
		cfg.TokenPepper = *fc.TokenPepper
	}
	if fc.LogLevel != nil {
		cfg.LogLevel = *fc.LogLevel
	}
	if fc.EnableCasbin != nil {
		cfg.EnableCasbin = *fc.EnableCasbin
	}
	if fc.OTELEnabled != nil {
		cfg.OTELEnabled = *fc.OTELEnabled
	}
	if fc.OTELServiceName != nil {
		cfg.OTELServiceName = *fc.OTELServiceName
	}
	if fc.OTLPEndpoint != nil {
		cfg.OTLPEndpoint = *fc.OTLPEndpoint
	}
	if fc.OTLPInsecure != nil {
		cfg.OTLPInsecure = *fc.OTLPInsecure
	}
	if fc.OTELSampleRatio != nil {
		cfg.OTELSampleRatio = *fc.OTELSampleRatio
	}
	if fc.VerifyRateLimitRPS != nil {
		cfg.VerifyRateLimitRPS = *fc.VerifyRateLimitRPS
	}
	if fc.VerifyRateBurst != nil {
		cfg.VerifyRateBurst = *fc.VerifyRateBurst
	}

	if fc.DBTimeout != nil {
		parsed, err := time.ParseDuration(*fc.DBTimeout)
		if err != nil {
			return fmt.Errorf("invalid db_timeout in config file: %w", err)
		}
		cfg.DBTimeout = parsed
	}
	if fc.VerifyCacheTTL != nil {
		parsed, err := time.ParseDuration(*fc.VerifyCacheTTL)
		if err != nil {
			return fmt.Errorf("invalid verify_cache_ttl in config file: %w", err)
		}
		cfg.VerifyCacheTTL = parsed
	}

	return nil
}

func loadEnvFile(path string) (map[string]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("read env file %q: %w", path, err)
	}

	result := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		idx := strings.Index(line, "=")
		if idx <= 0 {
			return nil, fmt.Errorf("invalid env entry at %s:%d", path, lineNo)
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		value = strings.Trim(value, `"`)
		value = strings.Trim(value, `'`)
		result[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan env file %q: %w", path, err)
	}

	return result, nil
}

func mergeFromEnv(cfg *Config, fileVars map[string]string) error {
	if v := getEnvOrDefault("ADDR", fileVars, ""); v != "" {
		cfg.Addr = v
	}
	if v := getEnvOrDefault("DATABASE_URL", fileVars, ""); v != "" {
		cfg.DatabaseURL = v
	}
	if v := getEnvOrDefault("TOKEN_PEPPER", fileVars, ""); v != "" {
		cfg.TokenPepper = v
	}
	if v := getEnvOrDefault("LOG_LEVEL", fileVars, ""); v != "" {
		cfg.LogLevel = v
	}
	if v, ok := getEnv("ENABLE_CASBIN", fileVars); ok {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid ENABLE_CASBIN: %w", err)
		}
		cfg.EnableCasbin = parsed
	}
	if v, ok := getEnv("OTEL_ENABLED", fileVars); ok {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid OTEL_ENABLED: %w", err)
		}
		cfg.OTELEnabled = parsed
	}
	if v := getEnvOrDefault("OTEL_SERVICE_NAME", fileVars, ""); v != "" {
		cfg.OTELServiceName = v
	}
	if v, ok := getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", fileVars); ok {
		cfg.OTLPEndpoint = v
	}
	if v, ok := getEnv("OTEL_EXPORTER_OTLP_INSECURE", fileVars); ok {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid OTEL_EXPORTER_OTLP_INSECURE: %w", err)
		}
		cfg.OTLPInsecure = parsed
	}
	if v, ok := getEnv("OTEL_TRACE_SAMPLE_RATIO", fileVars); ok {
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("invalid OTEL_TRACE_SAMPLE_RATIO: %w", err)
		}
		cfg.OTELSampleRatio = parsed
	}
	if v, ok := getEnv("DB_TIMEOUT", fileVars); ok {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid DB_TIMEOUT: %w", err)
		}
		cfg.DBTimeout = parsed
	}
	if v, ok := getEnv("VERIFY_RATE_LIMIT_RPS", fileVars); ok {
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("invalid VERIFY_RATE_LIMIT_RPS: %w", err)
		}
		cfg.VerifyRateLimitRPS = parsed
	}
	if v, ok := getEnv("VERIFY_RATE_LIMIT_BURST", fileVars); ok {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid VERIFY_RATE_LIMIT_BURST: %w", err)
		}
		cfg.VerifyRateBurst = parsed
	}
	if v, ok := getEnv("VERIFY_CACHE_TTL", fileVars); ok {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid VERIFY_CACHE_TTL: %w", err)
		}
		cfg.VerifyCacheTTL = parsed
	}

	return nil
}

func validate(cfg Config) error {
	if cfg.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.TokenPepper == "" {
		return fmt.Errorf("TOKEN_PEPPER is required")
	}
	if cfg.VerifyRateLimitRPS <= 0 {
		return fmt.Errorf("VERIFY_RATE_LIMIT_RPS must be > 0")
	}
	if cfg.VerifyRateBurst <= 0 {
		return fmt.Errorf("VERIFY_RATE_LIMIT_BURST must be > 0")
	}
	if cfg.DBTimeout <= 0 {
		return fmt.Errorf("DB_TIMEOUT must be > 0")
	}
	if cfg.OTELSampleRatio < 0 || cfg.OTELSampleRatio > 1 {
		return fmt.Errorf("OTEL_TRACE_SAMPLE_RATIO must be between 0 and 1")
	}
	if cfg.OTELServiceName == "" {
		return fmt.Errorf("OTEL_SERVICE_NAME must not be empty")
	}

	return nil
}

func getEnv(key string, fileVars map[string]string) (string, bool) {
	if value, ok := os.LookupEnv(key); ok {
		return value, true
	}
	value, ok := fileVars[key]
	return value, ok
}

func getEnvOrDefault(key string, fileVars map[string]string, fallback string) string {
	if value, ok := getEnv(key, fileVars); ok {
		return value
	}
	return fallback
}
