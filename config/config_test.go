package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromEnv_ConfigYAMLEnvAndProcessEnvPrecedence(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	envPath := filepath.Join(tempDir, ".env")

	configContent := `
addr: ":18080"
database_url: "postgres://yaml"
token_pepper: "yaml-pepper"
log_level: "warn"
enable_casbin: false
db_timeout: "5s"
verify_rate_limit_rps: 50
verify_rate_limit_burst: 70
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("write config yaml: %v", err)
	}

	envContent := `
DATABASE_URL=postgres://env
TOKEN_PEPPER=env-pepper
VERIFY_RATE_LIMIT_BURST=90
`
	if err := os.WriteFile(envPath, []byte(envContent), 0o644); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	t.Setenv("CONFIG_FILE", configPath)
	t.Setenv("ENV_FILE", envPath)
	t.Setenv("DATABASE_URL", "postgres://process-env")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}

	if cfg.Addr != ":18080" {
		t.Fatalf("addr=%q want=:18080", cfg.Addr)
	}
	if cfg.DatabaseURL != "postgres://process-env" {
		t.Fatalf("database_url=%q want=postgres://process-env", cfg.DatabaseURL)
	}
	if cfg.TokenPepper != "env-pepper" {
		t.Fatalf("token_pepper=%q want=env-pepper", cfg.TokenPepper)
	}
	if cfg.VerifyRateBurst != 90 {
		t.Fatalf("verify_rate_limit_burst=%d want=90", cfg.VerifyRateBurst)
	}
	if cfg.DBTimeout.String() != "5s" {
		t.Fatalf("db_timeout=%s want=5s", cfg.DBTimeout.String())
	}
}

func TestLoadFromEnv_RequiresDatabaseURLAndTokenPepper(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("addr: \":8080\"\n"), 0o644); err != nil {
		t.Fatalf("write config yaml: %v", err)
	}

	t.Setenv("CONFIG_FILE", configPath)
	t.Setenv("ENV_FILE", filepath.Join(tempDir, "missing.env"))
	t.Setenv("DATABASE_URL", "")
	t.Setenv("TOKEN_PEPPER", "")

	if _, err := LoadFromEnv(); err == nil {
		t.Fatalf("expected error when DATABASE_URL and TOKEN_PEPPER are missing")
	}
}
