## 1. Config Loader

- [x] 1.1 Add YAML-backed default config file parsing
- [x] 1.2 Add `.env` parsing support without mutating global process env state
- [x] 1.3 Implement source precedence and retain validation semantics

## 2. Runtime Packaging

- [x] 2.1 Include `config/config.yaml` in runtime image
- [x] 2.2 Update compose to consume `env_file` and set `CONFIG_FILE`

## 3. Validation and Docs

- [x] 3.1 Add tests for source precedence and required values
- [x] 3.2 Add `.env.example` and update README with configuration model
- [x] 3.3 Run full tests with Go 1.24.0
