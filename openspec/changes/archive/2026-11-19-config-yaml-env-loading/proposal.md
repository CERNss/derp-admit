## Why

The service currently relies on environment variables only, which makes default configuration management and local/production parity harder to maintain. We need a layered configuration model using `config.yaml` plus `.env` so defaults and secrets are managed separately.

## What Changes

- Add layered config loading with precedence: `config/config.yaml` -> `.env` -> process env.
- Introduce YAML-based default runtime configuration file.
- Add `.env.example` for required secret/runtime values.
- Update Docker image and compose wiring to use file-based config plus env file injection.
- Add config loader tests for precedence and required-value validation.

## Capabilities

### New Capabilities
- `layered-config-loading`: Support deterministic multi-source configuration loading from YAML and env sources.

### Modified Capabilities
- None.

## Impact

- Affected code: `config` package parsing/validation, Docker runtime layout, compose env wiring, docs.
- Affected operations: `.env` becomes primary secret delivery path while `config.yaml` stores defaults.
