package config

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultConfigFilePath = "config/config.yaml"
	defaultEnvFilePath    = ".env"
	minPolicySyncInterval = 100 * time.Millisecond
)

type Config struct {
	Addr                 string
	DatabaseURL          string
	TokenPepper          string
	AdminAPIKey          string
	LogLevel             string
	LegacyCasbinEnabled  *bool
	UpgradePolicyMode    string
	Warnings             []string
	OTELEnabled          bool
	OTELServiceName      string
	OTLPEndpoint         string
	OTLPInsecure         bool
	OTELSampleRatio      float64
	DBTimeout            time.Duration
	VerifyRateLimitRPS   float64
	VerifyRateBurst      int
	RegisterRateLimitRPS float64
	RegisterRateBurst    int
	AdminRateLimitRPS    float64
	AdminRateBurst       int
	VerifyCacheTTL       time.Duration
	PolicySyncInterval   time.Duration
	MetricsEnabled       bool
	// VerifyAllowedCIDRs and MetricsAllowedCIDRs restrict the TCP peers that
	// may call /verify and /metrics. Empty means no restriction.
	VerifyAllowedCIDRs  []netip.Prefix
	MetricsAllowedCIDRs []netip.Prefix
	// VerifyAuditRetentionDays and AdminAuditRetentionDays bound the age of
	// audit_logs and admin_audit_logs rows. 0 keeps rows forever.
	VerifyAuditRetentionDays int
	AdminAuditRetentionDays  int
}

type fileConfig struct {
	Addr                 *string   `yaml:"addr"`
	DatabaseURL          *string   `yaml:"database_url"`
	TokenPepper          *string   `yaml:"token_pepper"`
	AdminAPIKey          *string   `yaml:"admin_api_key"`
	LogLevel             *string   `yaml:"log_level"`
	UpgradePolicyMode    *string   `yaml:"upgrade_policy_mode"`
	OTELEnabled          *bool     `yaml:"otel_enabled"`
	OTELServiceName      *string   `yaml:"otel_service_name"`
	OTLPEndpoint         *string   `yaml:"otel_exporter_otlp_endpoint"`
	OTLPInsecure         *bool     `yaml:"otel_exporter_otlp_insecure"`
	OTELSampleRatio      *float64  `yaml:"otel_trace_sample_ratio"`
	DBTimeout            *string   `yaml:"db_timeout"`
	VerifyRateLimitRPS   *float64  `yaml:"verify_rate_limit_rps"`
	VerifyRateBurst      *int      `yaml:"verify_rate_limit_burst"`
	RegisterRateLimitRPS *float64  `yaml:"register_rate_limit_rps"`
	RegisterRateBurst    *int      `yaml:"register_rate_limit_burst"`
	AdminRateLimitRPS    *float64  `yaml:"admin_rate_limit_rps"`
	AdminRateBurst       *int      `yaml:"admin_rate_limit_burst"`
	VerifyCacheTTL       *string   `yaml:"verify_cache_ttl"`
	PolicySyncInterval   *string   `yaml:"policy_sync_interval"`
	MetricsEnabled       *bool     `yaml:"metrics_enabled"`
	VerifyAllowedCIDRs   *string   `yaml:"verify_allowed_cidrs"`
	MetricsAllowedCIDRs  *string   `yaml:"metrics_allowed_cidrs"`
	VerifyAuditRetention yaml.Node `yaml:"verify_audit_retention_days"`
	AdminAuditRetention  yaml.Node `yaml:"admin_audit_retention_days"`
}

const legacyEnableCasbinWarning = "ENABLE_CASBIN / enable_casbin is deprecated and ignored for enforcement; policy is always enforced (its value is read only by the one-time upgrade)"

func LoadFromEnv() (Config, error) {
	cfg := defaultConfig()
	legacyCasbinSeen := false

	configFilePath := getEnvOrDefault("CONFIG_FILE", nil, defaultConfigFilePath)
	yamlCasbinSeen, err := mergeFromYAMLFile(&cfg, configFilePath)
	if err != nil {
		return Config{}, err
	}
	if yamlCasbinSeen {
		legacyCasbinSeen = true
	}

	envFileVars, err := loadEnvFile(getEnvOrDefault("ENV_FILE", nil, defaultEnvFilePath))
	if err != nil {
		return Config{}, err
	}

	envCasbinSeen, err := mergeFromEnv(&cfg, envFileVars)
	if err != nil {
		return Config{}, err
	}
	if envCasbinSeen {
		legacyCasbinSeen = true
	}

	if legacyCasbinSeen {
		cfg.Warnings = append(cfg.Warnings, legacyEnableCasbinWarning)
	}

	cfg.UpgradePolicyMode = strings.ToLower(strings.TrimSpace(cfg.UpgradePolicyMode))

	if err := validate(cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func defaultConfig() Config {
	return Config{
		Addr:                 ":8080",
		LogLevel:             "info",
		OTELEnabled:          false,
		OTELServiceName:      "derp-admit",
		OTLPEndpoint:         "",
		OTLPInsecure:         true,
		OTELSampleRatio:      1.0,
		DBTimeout:            2 * time.Second,
		VerifyRateLimitRPS:   100,
		VerifyRateBurst:      200,
		RegisterRateLimitRPS: 5,
		RegisterRateBurst:    10,
		AdminRateLimitRPS:    10,
		AdminRateBurst:       20,
		VerifyCacheTTL:       0,
		PolicySyncInterval:   2 * time.Second,
		MetricsEnabled:       true,
	}
}

func mergeFromYAMLFile(cfg *Config, path string) (bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("read config file %q: %w", path, err)
	}

	var fc fileConfig
	if err := yaml.Unmarshal(content, &fc); err != nil {
		return false, fmt.Errorf("parse config file %q: %w", path, err)
	}

	legacyCasbinSeen := false
	if fc.Addr != nil {
		cfg.Addr = *fc.Addr
	}
	if fc.DatabaseURL != nil {
		cfg.DatabaseURL = *fc.DatabaseURL
	}
	if fc.TokenPepper != nil {
		cfg.TokenPepper = *fc.TokenPepper
	}
	if fc.AdminAPIKey != nil {
		cfg.AdminAPIKey = *fc.AdminAPIKey
	}
	if fc.LogLevel != nil {
		cfg.LogLevel = *fc.LogLevel
	}
	if fc.UpgradePolicyMode != nil {
		cfg.UpgradePolicyMode = strings.TrimSpace(*fc.UpgradePolicyMode)
	}
	if node, present := extractYAMLKey(content, "enable_casbin"); present {
		legacyCasbinSeen = true
		if parsed, ok := parseYAMLBoolNode(node); ok {
			cfg.LegacyCasbinEnabled = &parsed
		}
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
	if fc.RegisterRateLimitRPS != nil {
		cfg.RegisterRateLimitRPS = *fc.RegisterRateLimitRPS
	}
	if fc.RegisterRateBurst != nil {
		cfg.RegisterRateBurst = *fc.RegisterRateBurst
	}
	if fc.AdminRateLimitRPS != nil {
		cfg.AdminRateLimitRPS = *fc.AdminRateLimitRPS
	}
	if fc.AdminRateBurst != nil {
		cfg.AdminRateBurst = *fc.AdminRateBurst
	}

	if fc.DBTimeout != nil {
		parsed, err := time.ParseDuration(*fc.DBTimeout)
		if err != nil {
			return false, fmt.Errorf("invalid db_timeout in config file: %w", err)
		}
		cfg.DBTimeout = parsed
	}
	if fc.VerifyCacheTTL != nil {
		parsed, err := time.ParseDuration(*fc.VerifyCacheTTL)
		if err != nil {
			return false, fmt.Errorf("invalid verify_cache_ttl in config file: %w", err)
		}
		cfg.VerifyCacheTTL = parsed
	}
	if fc.PolicySyncInterval != nil {
		parsed, err := time.ParseDuration(*fc.PolicySyncInterval)
		if err != nil {
			return false, fmt.Errorf("invalid policy_sync_interval in config file: %w", err)
		}
		cfg.PolicySyncInterval = parsed
	}
	if fc.MetricsEnabled != nil {
		cfg.MetricsEnabled = *fc.MetricsEnabled
	}
	if fc.VerifyAllowedCIDRs != nil {
		if err := mergeCIDRList(&cfg.VerifyAllowedCIDRs, "verify_allowed_cidrs", *fc.VerifyAllowedCIDRs); err != nil {
			return false, fmt.Errorf("config file: %w", err)
		}
	}
	if fc.MetricsAllowedCIDRs != nil {
		if err := mergeCIDRList(&cfg.MetricsAllowedCIDRs, "metrics_allowed_cidrs", *fc.MetricsAllowedCIDRs); err != nil {
			return false, fmt.Errorf("config file: %w", err)
		}
	}
	if yamlNodeSet(&fc.VerifyAuditRetention) {
		parsed, err := parseYAMLIntNode(&fc.VerifyAuditRetention)
		if err != nil {
			return false, fmt.Errorf("invalid verify_audit_retention_days in config file: %w", err)
		}
		cfg.VerifyAuditRetentionDays = parsed
	}
	if yamlNodeSet(&fc.AdminAuditRetention) {
		parsed, err := parseYAMLIntNode(&fc.AdminAuditRetention)
		if err != nil {
			return false, fmt.Errorf("invalid admin_audit_retention_days in config file: %w", err)
		}
		cfg.AdminAuditRetentionDays = parsed
	}

	return legacyCasbinSeen, nil
}

func extractYAMLKey(content []byte, key string) (*yaml.Node, bool) {
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, false
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, false
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			return root.Content[i+1], true
		}
	}
	return nil, false
}

func parseYAMLBoolNode(node *yaml.Node) (bool, bool) {
	if node == nil || node.Kind != yaml.ScalarNode {
		return false, false
	}
	// Decode into *bool with yaml.v3 exactly as the previous fileConfig struct
	// did, so YAML 1.1 booleans (off, no, n, N, NO, Off, OFF, false, ...) are
	// recognised while null and non-bool values count as not false.
	var b *bool
	if err := node.Decode(&b); err == nil && b != nil {
		return *b, true
	}
	return false, false
}

// yamlNodeSet reports whether a key was present with a non-null value, the
// same as a non-nil pointer field for the other settings.
func yamlNodeSet(node *yaml.Node) bool {
	return node.Kind != 0 && !(node.Kind == yaml.ScalarNode && node.ShortTag() == "!!null")
}

// parseYAMLIntNode accepts only a scalar resolved as a YAML integer. Decoding
// straight into an int would silently truncate a float such as 1.5.
func parseYAMLIntNode(node *yaml.Node) (int, error) {
	if node.Kind != yaml.ScalarNode || node.ShortTag() != "!!int" {
		return 0, fmt.Errorf("%q is not an integer", node.Value)
	}
	var v int
	if err := node.Decode(&v); err != nil {
		return 0, err
	}
	return v, nil
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

func mergeFromEnv(cfg *Config, fileVars map[string]string) (bool, error) {
	legacyCasbinSeen := false
	if v := getEnvOrDefault("ADDR", fileVars, ""); v != "" {
		cfg.Addr = v
	}
	if v := getEnvOrDefault("DATABASE_URL", fileVars, ""); v != "" {
		cfg.DatabaseURL = v
	}
	if v := getEnvOrDefault("TOKEN_PEPPER", fileVars, ""); v != "" {
		cfg.TokenPepper = v
	}
	if v := getEnvOrDefault("ADMIN_API_KEY", fileVars, ""); v != "" {
		cfg.AdminAPIKey = v
	}
	if v := getEnvOrDefault("LOG_LEVEL", fileVars, ""); v != "" {
		cfg.LogLevel = v
	}
	if v, ok := fileVars["ENABLE_CASBIN"]; ok {
		legacyCasbinSeen = true
		if parsed, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			cfg.LegacyCasbinEnabled = &parsed
		}
	}
	if v, ok := os.LookupEnv("ENABLE_CASBIN"); ok {
		legacyCasbinSeen = true
		if parsed, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			cfg.LegacyCasbinEnabled = &parsed
		}
	}
	if v, ok := fileVars["UPGRADE_POLICY_MODE"]; ok {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			cfg.UpgradePolicyMode = trimmed
		}
	}
	if v, ok := os.LookupEnv("UPGRADE_POLICY_MODE"); ok {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			cfg.UpgradePolicyMode = trimmed
		}
	}
	if v, ok := getEnv("OTEL_ENABLED", fileVars); ok {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return false, fmt.Errorf("invalid OTEL_ENABLED: %w", err)
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
			return false, fmt.Errorf("invalid OTEL_EXPORTER_OTLP_INSECURE: %w", err)
		}
		cfg.OTLPInsecure = parsed
	}
	if v, ok := getEnv("OTEL_TRACE_SAMPLE_RATIO", fileVars); ok {
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return false, fmt.Errorf("invalid OTEL_TRACE_SAMPLE_RATIO: %w", err)
		}
		cfg.OTELSampleRatio = parsed
	}
	if v, ok := getEnv("DB_TIMEOUT", fileVars); ok {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return false, fmt.Errorf("invalid DB_TIMEOUT: %w", err)
		}
		cfg.DBTimeout = parsed
	}
	if v, ok := getEnv("VERIFY_RATE_LIMIT_RPS", fileVars); ok {
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return false, fmt.Errorf("invalid VERIFY_RATE_LIMIT_RPS: %w", err)
		}
		cfg.VerifyRateLimitRPS = parsed
	}
	if v, ok := getEnv("VERIFY_RATE_LIMIT_BURST", fileVars); ok {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return false, fmt.Errorf("invalid VERIFY_RATE_LIMIT_BURST: %w", err)
		}
		cfg.VerifyRateBurst = parsed
	}
	if v, ok := getEnv("REGISTER_RATE_LIMIT_RPS", fileVars); ok {
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return false, fmt.Errorf("invalid REGISTER_RATE_LIMIT_RPS: %w", err)
		}
		cfg.RegisterRateLimitRPS = parsed
	}
	if v, ok := getEnv("REGISTER_RATE_LIMIT_BURST", fileVars); ok {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return false, fmt.Errorf("invalid REGISTER_RATE_LIMIT_BURST: %w", err)
		}
		cfg.RegisterRateBurst = parsed
	}
	if v, ok := getEnv("ADMIN_RATE_LIMIT_RPS", fileVars); ok {
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return false, fmt.Errorf("invalid ADMIN_RATE_LIMIT_RPS: %w", err)
		}
		cfg.AdminRateLimitRPS = parsed
	}
	if v, ok := getEnv("ADMIN_RATE_LIMIT_BURST", fileVars); ok {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return false, fmt.Errorf("invalid ADMIN_RATE_LIMIT_BURST: %w", err)
		}
		cfg.AdminRateBurst = parsed
	}
	if v, ok := getEnv("VERIFY_CACHE_TTL", fileVars); ok {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return false, fmt.Errorf("invalid VERIFY_CACHE_TTL: %w", err)
		}
		cfg.VerifyCacheTTL = parsed
	}
	if v, ok := getEnv("POLICY_SYNC_INTERVAL", fileVars); ok {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return false, fmt.Errorf("invalid POLICY_SYNC_INTERVAL: %w", err)
		}
		cfg.PolicySyncInterval = parsed
	}
	if v, ok := getEnv("METRICS_ENABLED", fileVars); ok {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return false, fmt.Errorf("invalid METRICS_ENABLED: %w", err)
		}
		cfg.MetricsEnabled = parsed
	}
	// An empty or blank value at any layer does not override a lower layer, so
	// a stray empty line in .env or an environment variable that expands to
	// nothing cannot silently lift a restriction set lower down.
	if err := mergeCIDRLayers(&cfg.VerifyAllowedCIDRs, "VERIFY_ALLOWED_CIDRS", fileVars); err != nil {
		return false, err
	}
	if err := mergeCIDRLayers(&cfg.MetricsAllowedCIDRs, "METRICS_ALLOWED_CIDRS", fileVars); err != nil {
		return false, err
	}
	if v, ok := getEnv("VERIFY_AUDIT_RETENTION_DAYS", fileVars); ok {
		parsed, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return false, fmt.Errorf("invalid VERIFY_AUDIT_RETENTION_DAYS: %w", err)
		}
		cfg.VerifyAuditRetentionDays = parsed
	}
	if v, ok := getEnv("ADMIN_AUDIT_RETENTION_DAYS", fileVars); ok {
		parsed, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return false, fmt.Errorf("invalid ADMIN_AUDIT_RETENTION_DAYS: %w", err)
		}
		cfg.AdminAuditRetentionDays = parsed
	}

	return legacyCasbinSeen, nil
}

func validate(cfg Config) error {
	if cfg.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.TokenPepper == "" {
		return fmt.Errorf("TOKEN_PEPPER is required")
	}
	if cfg.AdminAPIKey != "" && len(cfg.AdminAPIKey) < 16 {
		return fmt.Errorf("ADMIN_API_KEY must be at least 16 characters when set")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.UpgradePolicyMode)) {
	case "", "enforced", "disabled":
	default:
		return fmt.Errorf("invalid UPGRADE_POLICY_MODE %q: must be \"enforced\" or \"disabled\"", cfg.UpgradePolicyMode)
	}
	if cfg.VerifyRateLimitRPS <= 0 {
		return fmt.Errorf("VERIFY_RATE_LIMIT_RPS must be > 0")
	}
	if cfg.VerifyRateBurst <= 0 {
		return fmt.Errorf("VERIFY_RATE_LIMIT_BURST must be > 0")
	}
	if cfg.RegisterRateLimitRPS <= 0 {
		return fmt.Errorf("REGISTER_RATE_LIMIT_RPS must be > 0")
	}
	if cfg.RegisterRateBurst <= 0 {
		return fmt.Errorf("REGISTER_RATE_LIMIT_BURST must be > 0")
	}
	if cfg.AdminRateLimitRPS <= 0 {
		return fmt.Errorf("ADMIN_RATE_LIMIT_RPS must be > 0")
	}
	if cfg.AdminRateBurst <= 0 {
		return fmt.Errorf("ADMIN_RATE_LIMIT_BURST must be > 0")
	}
	if cfg.DBTimeout <= 0 {
		return fmt.Errorf("DB_TIMEOUT must be > 0")
	}
	if cfg.PolicySyncInterval < minPolicySyncInterval {
		return fmt.Errorf("POLICY_SYNC_INTERVAL must be >= %s", minPolicySyncInterval)
	}
	if cfg.OTELSampleRatio < 0 || cfg.OTELSampleRatio > 1 {
		return fmt.Errorf("OTEL_TRACE_SAMPLE_RATIO must be between 0 and 1")
	}
	if cfg.OTELServiceName == "" {
		return fmt.Errorf("OTEL_SERVICE_NAME must not be empty")
	}
	if cfg.VerifyAuditRetentionDays < 0 {
		return fmt.Errorf("VERIFY_AUDIT_RETENTION_DAYS must be >= 0")
	}
	if cfg.AdminAuditRetentionDays < 0 {
		return fmt.Errorf("ADMIN_AUDIT_RETENTION_DAYS must be >= 0")
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
