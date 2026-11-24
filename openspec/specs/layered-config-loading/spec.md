# layered-config-loading Specification

## Purpose
Define how the service loads its configuration from layered sources and fails startup when required values are missing or typed values are invalid.

## Requirements

### Requirement: Configuration SHALL support layered sources
The system MUST load configuration from `config/config.yaml`, then `.env`, then process environment variables, where later sources override earlier ones.

#### Scenario: Process environment overrides file values
- **WHEN** a config key is present in both `config.yaml` and process environment
- **THEN** the runtime uses the process environment value

#### Scenario: Env file overrides YAML defaults
- **WHEN** a config key is present in both `config.yaml` and `.env`, but absent in process env
- **THEN** the runtime uses the `.env` value

### Requirement: Missing required values SHALL fail startup
The system MUST reject startup when `DATABASE_URL` or `TOKEN_PEPPER` are missing after layered config resolution.

#### Scenario: Required secret missing
- **WHEN** resolved configuration has empty `TOKEN_PEPPER`
- **THEN** config loading fails with an explicit validation error

### Requirement: Invalid typed values SHALL fail validation
The system MUST fail config loading when typed values (duration, bool, float, int) cannot be parsed.

#### Scenario: Invalid duration in environment
- **WHEN** `DB_TIMEOUT` is set to an invalid duration string
- **THEN** config loading fails with a parse error

### Requirement: Caller allowlist settings are parsed and validated at load
`VERIFY_ALLOWED_CIDRS` / `verify_allowed_cidrs` and `METRICS_ALLOWED_CIDRS` / `metrics_allowed_cidrs` MUST accept a comma-separated list of CIDRs or single IP addresses, with whitespace around items trimmed. A single address MUST mean `/32` for IPv4 and `/128` for IPv6. An unset or empty value MUST mean no restriction. Any invalid item MUST fail config loading with an error naming the setting and the item.

#### Scenario: Mixed list
- **WHEN** `VERIFY_ALLOWED_CIDRS` is ` 10.0.0.0/8 , 192.0.2.7, 2001:db8::/32 ,2001:db8:1::5`
- **THEN** configuration loads with four entries: `10.0.0.0/8`, `192.0.2.7/32`, `2001:db8::/32` and `2001:db8:1::5/128`

#### Scenario: Invalid item
- **WHEN** `METRICS_ALLOWED_CIDRS` is `10.0.0.0/8,not-an-ip`
- **THEN** configuration loading fails with an error that names `METRICS_ALLOWED_CIDRS` and `not-an-ip`

#### Scenario: Empty item
- **WHEN** `VERIFY_ALLOWED_CIDRS` is `10.0.0.0/8,,192.0.2.7`
- **THEN** configuration loading fails with an error that names `VERIFY_ALLOWED_CIDRS`

### Requirement: Caller allowlist settings follow the layering rules
The allowlist settings MUST be layered as process environment over `.env` over YAML. The `.env` value and then the process environment value MUST each apply only when it is not empty or whitespace-only after trimming, so an empty or blank value at a higher layer never clears a list set at a lower layer and does not stop a lower layer from being read.

#### Scenario: Environment overrides YAML
- **WHEN** `config.yaml` sets `verify_allowed_cidrs: "10.0.0.0/8"` and the process environment sets `VERIFY_ALLOWED_CIDRS=192.0.2.0/24`
- **THEN** the effective list is `192.0.2.0/24` only

#### Scenario: Empty environment value
- **WHEN** `config.yaml` sets `verify_allowed_cidrs: "10.0.0.0/8"` and the process environment sets `VERIFY_ALLOWED_CIDRS=` (empty)
- **THEN** the effective list is `10.0.0.0/8`

#### Scenario: Blank environment value over a .env list
- **WHEN** `.env` sets `VERIFY_ALLOWED_CIDRS=172.16.0.0/12` and the process environment sets `VERIFY_ALLOWED_CIDRS` to an empty or whitespace-only value
- **THEN** the effective list is `172.16.0.0/12`

### Requirement: Audit retention settings are validated at load
`VERIFY_AUDIT_RETENTION_DAYS` / `verify_audit_retention_days` and `ADMIN_AUDIT_RETENTION_DAYS` / `admin_audit_retention_days` MUST accept non-negative integers, default to `0`, and follow the same layering as the other integer settings. A negative or non-integer value MUST fail config loading.

#### Scenario: Valid retention
- **WHEN** `VERIFY_AUDIT_RETENTION_DAYS` is `30` in the environment and `admin_audit_retention_days: 365` is in `config.yaml`
- **THEN** configuration loads with verify retention 30 days and admin retention 365 days

#### Scenario: Negative or non-integer retention
- **WHEN** `ADMIN_AUDIT_RETENTION_DAYS` is `-1`, `1.5` or `ten`
- **THEN** configuration loading fails with an error naming `ADMIN_AUDIT_RETENTION_DAYS`
