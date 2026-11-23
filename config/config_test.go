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
	if cfg.LegacyCasbinEnabled == nil || *cfg.LegacyCasbinEnabled {
		t.Fatalf("LegacyCasbinEnabled=%v want=false when config.yaml sets enable_casbin: false", cfg.LegacyCasbinEnabled)
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

	t.Run("unset produces no warning and nil LegacyCasbinEnabled", func(t *testing.T) {
		aBaseEnv(t, "", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinEnabled != nil {
			t.Fatalf("LegacyCasbinEnabled=%v want=nil", *cfg.LegacyCasbinEnabled)
		}
		if len(cfg.Warnings) != 0 {
			t.Fatalf("Warnings=%v want empty", cfg.Warnings)
		}
	})

	t.Run("env false warns and sets LegacyCasbinEnabled false", func(t *testing.T) {
		aBaseEnv(t, "", "")
		t.Setenv("ENABLE_CASBIN", "false")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinEnabled == nil || *cfg.LegacyCasbinEnabled {
			t.Fatalf("LegacyCasbinEnabled=%v want=false", cfg.LegacyCasbinEnabled)
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 warning", cfg.Warnings)
		}
	})

	t.Run("env maybe loads with warning and LegacyCasbinEnabled nil", func(t *testing.T) {
		aBaseEnv(t, "", "")
		t.Setenv("ENABLE_CASBIN", "maybe")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinEnabled != nil {
			t.Fatalf("LegacyCasbinEnabled=%v want=nil for unparsable value", *cfg.LegacyCasbinEnabled)
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 warning", cfg.Warnings)
		}
	})

	t.Run("env true loads with warning and LegacyCasbinEnabled true", func(t *testing.T) {
		aBaseEnv(t, "", "")
		t.Setenv("ENABLE_CASBIN", "true")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinEnabled == nil || !*cfg.LegacyCasbinEnabled {
			t.Fatalf("LegacyCasbinEnabled=%v want=true", cfg.LegacyCasbinEnabled)
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 warning", cfg.Warnings)
		}
	})

	t.Run("dotenv false warns and sets LegacyCasbinEnabled false", func(t *testing.T) {
		aBaseEnv(t, "", "ENABLE_CASBIN=false\n")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinEnabled == nil || *cfg.LegacyCasbinEnabled {
			t.Fatalf("LegacyCasbinEnabled=%v want=false", cfg.LegacyCasbinEnabled)
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 warning", cfg.Warnings)
		}
	})

	t.Run("dotenv true warns and sets LegacyCasbinEnabled true", func(t *testing.T) {
		aBaseEnv(t, "", "ENABLE_CASBIN=true\n")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinEnabled == nil || !*cfg.LegacyCasbinEnabled {
			t.Fatalf("LegacyCasbinEnabled=%v want=true", cfg.LegacyCasbinEnabled)
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 warning", cfg.Warnings)
		}
	})

	t.Run("yaml maybe loads with warning and LegacyCasbinEnabled nil", func(t *testing.T) {
		aBaseEnv(t, "enable_casbin: maybe\n", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinEnabled != nil {
			t.Fatalf("LegacyCasbinEnabled=%v want=nil", *cfg.LegacyCasbinEnabled)
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 warning", cfg.Warnings)
		}
	})

	t.Run("yaml null loads with warning and LegacyCasbinEnabled nil", func(t *testing.T) {
		aBaseEnv(t, "enable_casbin: null\n", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinEnabled != nil {
			t.Fatalf("LegacyCasbinEnabled=%v want=nil", *cfg.LegacyCasbinEnabled)
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 warning", cfg.Warnings)
		}
	})

	t.Run("env maybe does not override yaml false", func(t *testing.T) {
		aBaseEnv(t, "enable_casbin: false\n", "")
		t.Setenv("ENABLE_CASBIN", "maybe")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinEnabled == nil || *cfg.LegacyCasbinEnabled {
			t.Fatalf("LegacyCasbinEnabled=%v want=false when env value is unparsable", cfg.LegacyCasbinEnabled)
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 deduplicated warning", cfg.Warnings)
		}
	})

	t.Run("env off does not override yaml false", func(t *testing.T) {
		aBaseEnv(t, "enable_casbin: false\n", "")
		t.Setenv("ENABLE_CASBIN", "off")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinEnabled == nil || *cfg.LegacyCasbinEnabled {
			t.Fatalf("LegacyCasbinEnabled=%v want=false when env value is unparsable 'off'", cfg.LegacyCasbinEnabled)
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 deduplicated warning", cfg.Warnings)
		}
	})

	t.Run("env empty does not mask dotenv false", func(t *testing.T) {
		aBaseEnv(t, "", "ENABLE_CASBIN=false\n")
		t.Setenv("ENABLE_CASBIN", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinEnabled == nil || *cfg.LegacyCasbinEnabled {
			t.Fatalf("LegacyCasbinEnabled=%v want=false when process env is empty", cfg.LegacyCasbinEnabled)
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 deduplicated warning", cfg.Warnings)
		}
	})

	t.Run("dotenv unparsable does not override yaml true", func(t *testing.T) {
		aBaseEnv(t, "enable_casbin: true\n", "ENABLE_CASBIN=maybe\n")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinEnabled == nil || !*cfg.LegacyCasbinEnabled {
			t.Fatalf("LegacyCasbinEnabled=%v want=true when dotenv value is unparsable", cfg.LegacyCasbinEnabled)
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 deduplicated warning", cfg.Warnings)
		}
	})

	t.Run("env true overrides yaml false to true", func(t *testing.T) {
		aBaseEnv(t, "enable_casbin: false\n", "")
		t.Setenv("ENABLE_CASBIN", "true")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.LegacyCasbinEnabled == nil || !*cfg.LegacyCasbinEnabled {
			t.Fatalf("LegacyCasbinEnabled=%v want=true when env overrides yaml false", cfg.LegacyCasbinEnabled)
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings=%v want 1 deduplicated warning", cfg.Warnings)
		}
	})

	for _, val := range []string{"0", "f", "F", "false", "FALSE", "False"} {
		t.Run("env_false_spelling_"+val, func(t *testing.T) {
			aBaseEnv(t, "", "")
			t.Setenv("ENABLE_CASBIN", val)
			cfg, err := LoadFromEnv()
			if err != nil {
				t.Fatalf("LoadFromEnv: %v", err)
			}
			if cfg.LegacyCasbinEnabled == nil || *cfg.LegacyCasbinEnabled {
				t.Fatalf("ENABLE_CASBIN=%q: LegacyCasbinEnabled=%v want=false", val, cfg.LegacyCasbinEnabled)
			}
			if len(cfg.Warnings) != 1 {
				t.Fatalf("ENABLE_CASBIN=%q: Warnings=%v want 1 warning", val, cfg.Warnings)
			}
		})
	}

	for _, val := range []string{"1", "t", "T", "true", "TRUE", "True"} {
		t.Run("env_true_spelling_"+val, func(t *testing.T) {
			aBaseEnv(t, "", "")
			t.Setenv("ENABLE_CASBIN", val)
			cfg, err := LoadFromEnv()
			if err != nil {
				t.Fatalf("LoadFromEnv: %v", err)
			}
			if cfg.LegacyCasbinEnabled == nil || !*cfg.LegacyCasbinEnabled {
				t.Fatalf("ENABLE_CASBIN=%q: LegacyCasbinEnabled=%v want=true", val, cfg.LegacyCasbinEnabled)
			}
			if len(cfg.Warnings) != 1 {
				t.Fatalf("ENABLE_CASBIN=%q: Warnings=%v want 1 warning", val, cfg.Warnings)
			}
		})
	}

	for _, val := range []string{"false", "False", "FALSE", "off", "Off", "OFF", "no", "No", "NO", "n", "N"} {
		t.Run("yaml_false_spelling_"+val, func(t *testing.T) {
			aBaseEnv(t, "enable_casbin: "+val+"\n", "")
			cfg, err := LoadFromEnv()
			if err != nil {
				t.Fatalf("LoadFromEnv: %v", err)
			}
			if cfg.LegacyCasbinEnabled == nil || *cfg.LegacyCasbinEnabled {
				t.Fatalf("enable_casbin: %s: LegacyCasbinEnabled=%v want=false", val, cfg.LegacyCasbinEnabled)
			}
			if len(cfg.Warnings) != 1 {
				t.Fatalf("enable_casbin: %s: Warnings=%v want 1 warning", val, cfg.Warnings)
			}
		})
	}

	for _, val := range []string{"true", "True", "TRUE", "on", "On", "ON", "yes", "Yes", "YES", "y", "Y"} {
		t.Run("yaml_true_spelling_"+val, func(t *testing.T) {
			aBaseEnv(t, "enable_casbin: "+val+"\n", "")
			cfg, err := LoadFromEnv()
			if err != nil {
				t.Fatalf("LoadFromEnv: %v", err)
			}
			if cfg.LegacyCasbinEnabled == nil || !*cfg.LegacyCasbinEnabled {
				t.Fatalf("enable_casbin: %s: LegacyCasbinEnabled=%v want=true", val, cfg.LegacyCasbinEnabled)
			}
			if len(cfg.Warnings) != 1 {
				t.Fatalf("enable_casbin: %s: Warnings=%v want 1 warning", val, cfg.Warnings)
			}
		})
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

	t.Run("floor_100ms_accepted", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("POLICY_SYNC_INTERVAL", "100ms")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv(100ms): %v", err)
		}
		if cfg.PolicySyncInterval.String() != "100ms" {
			t.Fatalf("PolicySyncInterval=%s want=100ms", cfg.PolicySyncInterval)
		}
	})

	for _, bad := range []string{"0s", "-1s", "1ms", "50ms", "99ms", "soon"} {
		t.Run("invalid_"+bad, func(t *testing.T) {
			baseEnv(t)
			t.Setenv("POLICY_SYNC_INTERVAL", bad)
			if _, err := LoadFromEnv(); err == nil {
				t.Fatalf("expected error for POLICY_SYNC_INTERVAL=%q", bad)
			}
		})
	}
}

func TestLoadFromEnv_UpgradePolicyMode(t *testing.T) {
	baseEnv := func(t *testing.T, yamlContent, envContent string) {
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

	t.Run("unset is empty", func(t *testing.T) {
		baseEnv(t, "", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.UpgradePolicyMode != "" {
			t.Fatalf("UpgradePolicyMode=%q want empty", cfg.UpgradePolicyMode)
		}
	})

	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"env_enforced", "enforced", "enforced"},
		{"env_disabled", "disabled", "disabled"},
		{"env_mixed_case_and_spaces", "  EnFoRcEd \t", "enforced"},
		{"env_upper_disabled", "DISABLED", "disabled"},
		{"env_whitespace_only", "   ", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseEnv(t, "", "")
			t.Setenv("UPGRADE_POLICY_MODE", tc.raw)
			cfg, err := LoadFromEnv()
			if err != nil {
				t.Fatalf("LoadFromEnv(%q): %v", tc.raw, err)
			}
			if cfg.UpgradePolicyMode != tc.want {
				t.Fatalf("UpgradePolicyMode=%q want=%q", cfg.UpgradePolicyMode, tc.want)
			}
		})
	}

	t.Run("yaml valid normalized", func(t *testing.T) {
		baseEnv(t, "upgrade_policy_mode: \"  DiSaBlEd \"\n", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.UpgradePolicyMode != "disabled" {
			t.Fatalf("UpgradePolicyMode=%q want=disabled", cfg.UpgradePolicyMode)
		}
	})

	t.Run("dotenv overrides yaml and process env overrides dotenv", func(t *testing.T) {
		baseEnv(t, "upgrade_policy_mode: enforced\n", "UPGRADE_POLICY_MODE=disabled\n")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv(dotenv): %v", err)
		}
		if cfg.UpgradePolicyMode != "disabled" {
			t.Fatalf("dotenv override: UpgradePolicyMode=%q want=disabled", cfg.UpgradePolicyMode)
		}

		t.Setenv("UPGRADE_POLICY_MODE", "ENFORCED")
		cfg, err = LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv(env): %v", err)
		}
		if cfg.UpgradePolicyMode != "enforced" {
			t.Fatalf("process env override: UpgradePolicyMode=%q want=enforced", cfg.UpgradePolicyMode)
		}
	})

	for _, bad := range []string{"true", "false", "auto", "off", "enable"} {
		t.Run("invalid_env_"+bad, func(t *testing.T) {
			baseEnv(t, "", "")
			t.Setenv("UPGRADE_POLICY_MODE", bad)
			if _, err := LoadFromEnv(); err == nil {
				t.Fatalf("expected error for UPGRADE_POLICY_MODE=%q", bad)
			}
		})
		t.Run("invalid_yaml_"+bad, func(t *testing.T) {
			baseEnv(t, "upgrade_policy_mode: "+bad+"\n", "")
			if _, err := LoadFromEnv(); err == nil {
				t.Fatalf("expected error for yaml upgrade_policy_mode=%q", bad)
			}
		})
	}
}
