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
	if !cfg.LegacyCasbinDisabled {
		t.Fatalf("LegacyCasbinDisabled=false want=true when config.yaml sets enable_casbin: false")
	}
	if len(cfg.Warnings) == 0 {
		t.Fatalf("expected warning when enable_casbin is configured in config.yaml")
	}
}

func TestLoadFromEnv_EnableCasbinIgnored(t *testing.T) {
	aBaseEnv := func(t *testing.T, yamlContent, envContent string) {
		t.Helper()
		tempDir := t.TempDir()
		yamlPath := filepath.Join(tempDir, "config.yaml")
		envPath := filepath.Join(tempDir, ".env")
		if yamlContent != "" {
			if err := os.WriteFile(yamlPath, []byte(yamlContent), 0o644); err != nil {
				t.Fatalf("write config yaml: %v", err)
			}
		} else {
			yamlPath = filepath.Join(tempDir, "missing.yaml")
		}
		if envContent != "" {
			if err := os.WriteFile(envPath, []byte(envContent), 0o644); err != nil {
				t.Fatalf("write env file: %v", err)
			}
		} else {
			envPath = filepath.Join(tempDir, "missing.env")
		}
		t.Setenv("CONFIG_FILE", yamlPath)
		t.Setenv("ENV_FILE", envPath)
		t.Setenv("DATABASE_URL", "sqlite://"+filepath.Join(tempDir, "cfg.db"))
		t.Setenv("TOKEN_PEPPER", "pepper")
	}

	t.Run("unset produces no warning", func(t *testing.T) {
		aBaseEnv(t, "", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinDisabled {
			t.Fatalf("LegacyCasbinDisabled=true want=false")
		}
		if len(cfg.Warnings) != 0 {
			t.Fatalf("Warnings=%v want empty", cfg.Warnings)
		}
	})

	t.Run("env false warns and sets LegacyCasbinDisabled", func(t *testing.T) {
		aBaseEnv(t, "", "")
		t.Setenv("ENABLE_CASBIN", "false")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if !cfg.LegacyCasbinDisabled {
			t.Fatalf("LegacyCasbinDisabled=false want=true")
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 warning", cfg.Warnings)
		}
	})

	t.Run("env maybe loads with warning and LegacyCasbinDisabled false", func(t *testing.T) {
		aBaseEnv(t, "", "")
		t.Setenv("ENABLE_CASBIN", "maybe")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinDisabled {
			t.Fatalf("LegacyCasbinDisabled=true want=false for unparsable value")
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 warning", cfg.Warnings)
		}
	})

	t.Run("env true loads with warning and LegacyCasbinDisabled false", func(t *testing.T) {
		aBaseEnv(t, "", "")
		t.Setenv("ENABLE_CASBIN", "true")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinDisabled {
			t.Fatalf("LegacyCasbinDisabled=true want=false")
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 warning", cfg.Warnings)
		}
	})

	t.Run("dotenv false warns and sets LegacyCasbinDisabled", func(t *testing.T) {
		aBaseEnv(t, "", "ENABLE_CASBIN=false\n")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if !cfg.LegacyCasbinDisabled {
			t.Fatalf("LegacyCasbinDisabled=false want=true")
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 warning", cfg.Warnings)
		}
	})

	t.Run("yaml maybe loads with warning and LegacyCasbinDisabled false", func(t *testing.T) {
		aBaseEnv(t, "enable_casbin: maybe\n", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinDisabled {
			t.Fatalf("LegacyCasbinDisabled=true want=false")
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 warning", cfg.Warnings)
		}
	})

	t.Run("yaml null loads with warning and LegacyCasbinDisabled false", func(t *testing.T) {
		aBaseEnv(t, "enable_casbin: null\n", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinDisabled {
			t.Fatalf("LegacyCasbinDisabled=true want=false")
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 warning", cfg.Warnings)
		}
	})

	t.Run("env maybe overrides yaml false to not disabled", func(t *testing.T) {
		aBaseEnv(t, "enable_casbin: false\n", "")
		t.Setenv("ENABLE_CASBIN", "maybe")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinDisabled {
			t.Fatalf("LegacyCasbinDisabled=true want=false when env overrides yaml false")
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 deduplicated warning", cfg.Warnings)
		}
	})
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

func TestLoadFromEnv_PolicySyncInterval(t *testing.T) {
	baseEnv := func(t *testing.T) {
		t.Helper()
		tempDir := t.TempDir()
		t.Setenv("CONFIG_FILE", filepath.Join(tempDir, "missing.yaml"))
		t.Setenv("ENV_FILE", filepath.Join(tempDir, "missing.env"))
		t.Setenv("DATABASE_URL", "sqlite://"+filepath.Join(tempDir, "cfg.db"))
		t.Setenv("TOKEN_PEPPER", "pepper")
	}

	t.Run("default", func(t *testing.T) {
		baseEnv(t)
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.PolicySyncInterval.String() != "2s" {
			t.Fatalf("PolicySyncInterval=%s want=2s", cfg.PolicySyncInterval)
		}
		if !cfg.MetricsEnabled {
			t.Fatalf("MetricsEnabled=false want=true")
		}
	})

	t.Run("custom valid", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("POLICY_SYNC_INTERVAL", "500ms")
		t.Setenv("METRICS_ENABLED", "false")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.PolicySyncInterval.String() != "500ms" {
			t.Fatalf("PolicySyncInterval=%s want=500ms", cfg.PolicySyncInterval)
		}
		if cfg.MetricsEnabled {
			t.Fatalf("MetricsEnabled=true want=false")
		}
	})

	for _, bad := range []string{"0s", "-1s", "soon"} {
		t.Run("invalid_"+bad, func(t *testing.T) {
			baseEnv(t)
			t.Setenv("POLICY_SYNC_INTERVAL", bad)
			if _, err := LoadFromEnv(); err == nil {
				t.Fatalf("expected error for POLICY_SYNC_INTERVAL=%q", bad)
			}
		})
	}
}
