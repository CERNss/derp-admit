package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// opsUnsetEnv removes key from the process environment for the duration of
// the test and restores it afterwards.
func opsUnsetEnv(t *testing.T, key string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	t.Setenv(key, "") // registers restoration of the original value
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unsetenv %s: %v", key, err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, prev)
		}
	})
}

// opsBaseEnv points the loader at the given yaml and .env contents (empty
// string means the file is absent) and supplies the required settings.
func opsBaseEnv(t *testing.T, yamlContent, envContent string) {
	t.Helper()
	tempDir := t.TempDir()
	yamlPath := filepath.Join(tempDir, "config.yaml")
	envPath := filepath.Join(tempDir, ".env")
	if yamlContent != "" {
		if err := os.WriteFile(yamlPath, []byte(yamlContent), 0o644); err != nil {
			t.Fatalf("write yaml: %v", err)
		}
	}
	if envContent != "" {
		if err := os.WriteFile(envPath, []byte(envContent), 0o644); err != nil {
			t.Fatalf("write env: %v", err)
		}
	}
	t.Setenv("CONFIG_FILE", yamlPath)
	t.Setenv("ENV_FILE", envPath)
	t.Setenv("DATABASE_URL", "sqlite://"+filepath.Join(tempDir, "cfg.db"))
	t.Setenv("TOKEN_PEPPER", "pepper")
	for _, k := range []string{
		"VERIFY_ALLOWED_CIDRS", "METRICS_ALLOWED_CIDRS",
		"VERIFY_AUDIT_RETENTION_DAYS", "ADMIN_AUDIT_RETENTION_DAYS",
	} {
		opsUnsetEnv(t, k)
	}
}

func opsPrefixes(t *testing.T, items ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(items))
	for _, s := range items {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestLoadFromEnv_AllowedCIDRs(t *testing.T) {
	t.Run("unset means no restriction", func(t *testing.T) {
		opsBaseEnv(t, "", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.VerifyAllowedCIDRs != nil || cfg.MetricsAllowedCIDRs != nil {
			t.Fatalf("lists=%v/%v want nil", cfg.VerifyAllowedCIDRs, cfg.MetricsAllowedCIDRs)
		}
	})

	t.Run("empty and whitespace mean no restriction", func(t *testing.T) {
		opsBaseEnv(t, "verify_allowed_cidrs: \"   \"\nmetrics_allowed_cidrs: \"\"\n", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if len(cfg.VerifyAllowedCIDRs) != 0 || len(cfg.MetricsAllowedCIDRs) != 0 {
			t.Fatalf("lists=%v/%v want empty", cfg.VerifyAllowedCIDRs, cfg.MetricsAllowedCIDRs)
		}
	})

	t.Run("mixed list with bare IPs, IPv6 and whitespace", func(t *testing.T) {
		opsBaseEnv(t, "", "")
		t.Setenv("VERIFY_ALLOWED_CIDRS", " 10.0.0.0/8 , 192.0.2.7, 2001:db8::/32 ,2001:db8:1::5,\t172.16.5.9/12 ")
		t.Setenv("METRICS_ALLOWED_CIDRS", "::1")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		want := opsPrefixes(t, "10.0.0.0/8", "192.0.2.7/32", "2001:db8::/32", "2001:db8:1::5/128", "172.16.0.0/12")
		if !reflect.DeepEqual(cfg.VerifyAllowedCIDRs, want) {
			t.Fatalf("VerifyAllowedCIDRs=%v want=%v", cfg.VerifyAllowedCIDRs, want)
		}
		if !reflect.DeepEqual(cfg.MetricsAllowedCIDRs, opsPrefixes(t, "::1/128")) {
			t.Fatalf("MetricsAllowedCIDRs=%v want=[::1/128]", cfg.MetricsAllowedCIDRs)
		}
	})

	t.Run("IPv4-mapped items are unmapped", func(t *testing.T) {
		opsBaseEnv(t, "", "")
		t.Setenv("VERIFY_ALLOWED_CIDRS", "::ffff:10.0.0.5,::ffff:192.168.0.0/112")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		want := opsPrefixes(t, "10.0.0.5/32", "192.168.0.0/16")
		if !reflect.DeepEqual(cfg.VerifyAllowedCIDRs, want) {
			t.Fatalf("VerifyAllowedCIDRs=%v want=%v", cfg.VerifyAllowedCIDRs, want)
		}
	})

	invalid := []struct {
		name, key, value, item string
	}{
		{"word", "METRICS_ALLOWED_CIDRS", "10.0.0.0/8,not-an-ip", "not-an-ip"},
		{"bad prefix length", "VERIFY_ALLOWED_CIDRS", "10.0.0.0/33", "10.0.0.0/33"},
		{"bad address", "VERIFY_ALLOWED_CIDRS", "10.0.0.256", "10.0.0.256"},
		{"hostname", "VERIFY_ALLOWED_CIDRS", "derper", "derper"},
		{"empty item", "VERIFY_ALLOWED_CIDRS", "10.0.0.0/8,,192.0.2.7", `""`},
		{"trailing comma", "VERIFY_ALLOWED_CIDRS", "10.0.0.0/8,", `""`},
		{"zone", "VERIFY_ALLOWED_CIDRS", "fe80::1%eth0", "fe80::1%eth0"},
		{"short mapped prefix", "VERIFY_ALLOWED_CIDRS", "::ffff:0.0.0.0/80", "::ffff:0.0.0.0/80"},
	}
	for _, tc := range invalid {
		t.Run("invalid "+tc.name, func(t *testing.T) {
			opsBaseEnv(t, "", "")
			t.Setenv(tc.key, tc.value)
			_, err := LoadFromEnv()
			if err == nil {
				t.Fatalf("expected error for %s=%q", tc.key, tc.value)
			}
			if !strings.Contains(err.Error(), tc.key) || !strings.Contains(err.Error(), tc.item) {
				t.Fatalf("error %q does not name %s and %s", err, tc.key, tc.item)
			}
		})
	}

	t.Run("invalid yaml item names the yaml key", func(t *testing.T) {
		opsBaseEnv(t, "metrics_allowed_cidrs: \"10.0.0.0/8, bogus\"\n", "")
		_, err := LoadFromEnv()
		if err == nil || !strings.Contains(err.Error(), "metrics_allowed_cidrs") || !strings.Contains(err.Error(), "bogus") {
			t.Fatalf("err=%v want an error naming metrics_allowed_cidrs and bogus", err)
		}
	})

	t.Run("env over .env over yaml", func(t *testing.T) {
		opsBaseEnv(t,
			"verify_allowed_cidrs: \"10.0.0.0/8\"\nmetrics_allowed_cidrs: \"10.0.0.0/8\"\n",
			"VERIFY_ALLOWED_CIDRS=172.16.0.0/12\nMETRICS_ALLOWED_CIDRS=172.16.0.0/12\n")
		t.Setenv("VERIFY_ALLOWED_CIDRS", "192.0.2.0/24")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if !reflect.DeepEqual(cfg.VerifyAllowedCIDRs, opsPrefixes(t, "192.0.2.0/24")) {
			t.Fatalf("VerifyAllowedCIDRs=%v want process env value", cfg.VerifyAllowedCIDRs)
		}
		if !reflect.DeepEqual(cfg.MetricsAllowedCIDRs, opsPrefixes(t, "172.16.0.0/12")) {
			t.Fatalf("MetricsAllowedCIDRs=%v want .env value", cfg.MetricsAllowedCIDRs)
		}
	})

	t.Run("yaml only", func(t *testing.T) {
		opsBaseEnv(t, "verify_allowed_cidrs: \"10.0.0.0/8, 192.0.2.9\"\n", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if !reflect.DeepEqual(cfg.VerifyAllowedCIDRs, opsPrefixes(t, "10.0.0.0/8", "192.0.2.9/32")) {
			t.Fatalf("VerifyAllowedCIDRs=%v", cfg.VerifyAllowedCIDRs)
		}
	})

	t.Run("empty or blank env value does not clear a .env list", func(t *testing.T) {
		for _, blank := range []string{"", "   ", "\t"} {
			opsBaseEnv(t, "verify_allowed_cidrs: \"10.0.0.0/8\"\n", "VERIFY_ALLOWED_CIDRS=172.16.0.0/12\n")
			t.Setenv("VERIFY_ALLOWED_CIDRS", blank)
			cfg, err := LoadFromEnv()
			if err != nil {
				t.Fatalf("LoadFromEnv(%q): %v", blank, err)
			}
			if !reflect.DeepEqual(cfg.VerifyAllowedCIDRs, opsPrefixes(t, "172.16.0.0/12")) {
				t.Fatalf("env %q: VerifyAllowedCIDRs=%v want the .env list", blank, cfg.VerifyAllowedCIDRs)
			}
		}
	})

	t.Run("blank .env value does not clear a yaml list", func(t *testing.T) {
		opsBaseEnv(t, "metrics_allowed_cidrs: \"10.0.0.0/8\"\n", "METRICS_ALLOWED_CIDRS=  \n")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if !reflect.DeepEqual(cfg.MetricsAllowedCIDRs, opsPrefixes(t, "10.0.0.0/8")) {
			t.Fatalf("MetricsAllowedCIDRs=%v want the yaml list", cfg.MetricsAllowedCIDRs)
		}
	})

	t.Run("invalid .env item names the setting", func(t *testing.T) {
		opsBaseEnv(t, "", "VERIFY_ALLOWED_CIDRS=10.0.0.0/8,nope\n")
		_, err := LoadFromEnv()
		if err == nil || !strings.Contains(err.Error(), "VERIFY_ALLOWED_CIDRS") || !strings.Contains(err.Error(), "nope") {
			t.Fatalf("err=%v want an error naming VERIFY_ALLOWED_CIDRS and nope", err)
		}
	})

	t.Run("empty env value does not clear a yaml list", func(t *testing.T) {
		opsBaseEnv(t, "verify_allowed_cidrs: \"10.0.0.0/8\"\n", "METRICS_ALLOWED_CIDRS=\n")
		t.Setenv("VERIFY_ALLOWED_CIDRS", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if !reflect.DeepEqual(cfg.VerifyAllowedCIDRs, opsPrefixes(t, "10.0.0.0/8")) {
			t.Fatalf("VerifyAllowedCIDRs=%v want yaml value kept", cfg.VerifyAllowedCIDRs)
		}
		if cfg.MetricsAllowedCIDRs != nil {
			t.Fatalf("MetricsAllowedCIDRs=%v want nil", cfg.MetricsAllowedCIDRs)
		}
	})
}

func TestLoadFromEnv_AuditRetentionDays(t *testing.T) {
	t.Run("default zero", func(t *testing.T) {
		opsBaseEnv(t, "", "")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.VerifyAuditRetentionDays != 0 || cfg.AdminAuditRetentionDays != 0 {
			t.Fatalf("retention=%d/%d want 0/0", cfg.VerifyAuditRetentionDays, cfg.AdminAuditRetentionDays)
		}
	})

	t.Run("valid values and layering", func(t *testing.T) {
		opsBaseEnv(t,
			"verify_audit_retention_days: 7\nadmin_audit_retention_days: 365\n",
			"VERIFY_AUDIT_RETENTION_DAYS=14\n")
		t.Setenv("VERIFY_AUDIT_RETENTION_DAYS", "30")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.VerifyAuditRetentionDays != 30 {
			t.Fatalf("VerifyAuditRetentionDays=%d want 30 (process env)", cfg.VerifyAuditRetentionDays)
		}
		if cfg.AdminAuditRetentionDays != 365 {
			t.Fatalf("AdminAuditRetentionDays=%d want 365 (yaml)", cfg.AdminAuditRetentionDays)
		}
	})

	t.Run(".env over yaml", func(t *testing.T) {
		opsBaseEnv(t, "admin_audit_retention_days: 365\n", "ADMIN_AUDIT_RETENTION_DAYS=90\n")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.AdminAuditRetentionDays != 90 {
			t.Fatalf("AdminAuditRetentionDays=%d want 90", cfg.AdminAuditRetentionDays)
		}
	})

	t.Run("explicit zero", func(t *testing.T) {
		opsBaseEnv(t, "verify_audit_retention_days: 30\n", "")
		t.Setenv("VERIFY_AUDIT_RETENTION_DAYS", "0")
		cfg, err := LoadFromEnv()
		if err != nil {
			t.Fatalf("LoadFromEnv: %v", err)
		}
		if cfg.VerifyAuditRetentionDays != 0 {
			t.Fatalf("VerifyAuditRetentionDays=%d want 0", cfg.VerifyAuditRetentionDays)
		}
	})

	for _, key := range []string{"VERIFY_AUDIT_RETENTION_DAYS", "ADMIN_AUDIT_RETENTION_DAYS"} {
		for _, bad := range []string{"-1", "1.5", "ten", ""} {
			t.Run("invalid env "+key+"="+bad, func(t *testing.T) {
				opsBaseEnv(t, "", "")
				t.Setenv(key, bad)
				_, err := LoadFromEnv()
				if err == nil || !strings.Contains(err.Error(), key) {
					t.Fatalf("err=%v want an error naming %s", err, key)
				}
			})
		}
	}

	for _, yamlBad := range []string{
		"verify_audit_retention_days: -3\n",
		"admin_audit_retention_days: 1.5\n",
		"admin_audit_retention_days: ten\n",
	} {
		t.Run("invalid yaml "+strings.TrimSpace(yamlBad), func(t *testing.T) {
			opsBaseEnv(t, yamlBad, "")
			if _, err := LoadFromEnv(); err == nil {
				t.Fatalf("expected error for yaml %q", yamlBad)
			}
		})
	}
}

// TestShippedConfigFilesLoad checks that the shipped config/config.yaml still
// loads with the commented settings in place.
func TestShippedConfigFilesLoad(t *testing.T) {
	opsBaseEnv(t, "", "")
	t.Setenv("CONFIG_FILE", "config.yaml")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv with shipped config.yaml: %v", err)
	}
	if cfg.VerifyAllowedCIDRs != nil || cfg.MetricsAllowedCIDRs != nil || cfg.VerifyAuditRetentionDays != 0 || cfg.AdminAuditRetentionDays != 0 {
		t.Fatalf("shipped config.yaml must leave the new settings at their defaults: %+v", cfg)
	}
}
