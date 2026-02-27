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
	EnableCasbin       bool
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
		EnableCasbin:       getBool("ENABLE_CASBIN", true),
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
