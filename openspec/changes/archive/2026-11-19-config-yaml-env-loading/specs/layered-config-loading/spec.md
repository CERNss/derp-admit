## ADDED Requirements

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
