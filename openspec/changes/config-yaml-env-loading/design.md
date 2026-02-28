## Context

The verifier now has many runtime options (database, auth, policy, tracing, limits). Managing all values as raw environment variables is error-prone and reduces portability across developer and deployment environments.

## Goals / Non-Goals

**Goals:**
- Load defaults from `config/config.yaml`.
- Load additional values from `.env`.
- Allow process env to override both config file and `.env`.
- Keep current validation semantics for required values and numeric/duration bounds.

**Non-Goals:**
- Dynamic runtime config reload.
- External config service integration.
- Encrypted secret storage within this repository.

## Decisions

- Decision: Implement precedence order `config.yaml` -> `.env` -> process env.
  - Rationale: Keeps stable defaults in versioned config while allowing environment-specific overrides.
- Decision: Parse `.env` internally (without mutating process env globally).
  - Rationale: Avoids hidden side effects in tests and runtime.
- Decision: Keep required secrets (`DATABASE_URL`, `TOKEN_PEPPER`) outside `config.yaml` by default.
  - Rationale: Reduces risk of committing sensitive values.
- Decision: Ship `config/config.yaml` in runtime image and use compose `env_file` for deployment values.
  - Rationale: Aligns local and containerized startup paths.

## Risks / Trade-offs

- [Misconfigured precedence expectations] -> Mitigation: document precedence clearly in README and tests.
- [Invalid config syntax] -> Mitigation: fail fast with parse/validation errors.
- [Secrets accidentally committed] -> Mitigation: keep `.env` ignored and provide `.env.example` only.

## Migration Plan

1. Add layered loader implementation and tests.
2. Add default `config/config.yaml` and `.env.example`.
3. Update Dockerfile to include config directory.
4. Update compose to use `env_file` and `CONFIG_FILE`.
5. Validate with Go 1.24 test run.

Rollback:
- Restore previous env-only loader and remove YAML/.env layering code.
