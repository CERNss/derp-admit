## Context

`derp_admit` currently logs via a basic logger and does not initialize OpenTelemetry tracing. This limits incident debugging and request-level correlation, especially when verifier behavior must be diagnosed together with surrounding services (derper, proxies, database, policy systems). The target architecture is to keep logging lightweight while emitting OTel traces that can be exported to an OTLP backend and later visualized in SigNoz.

## Goals / Non-Goals

**Goals:**
- Introduce `zap` as the shared structured logger used across bootstrap, HTTP handlers, and core service logic.
- Initialize OTel tracer provider and propagation with OTLP exporter configuration via env vars.
- Instrument gin routes with OTel middleware so `/register` and `/verify` have spans and context propagation.
- Preserve security constraints (no token plaintext in logs).
- Keep behavior backwards compatible for existing API responses and verifier decision logic.

**Non-Goals:**
- Implement full metrics/logs OTLP export pipeline in this iteration.
- Add external tracing storage or collector deployment in this repo.
- Introduce UI dashboards or SigNoz provisioning automation.

## Decisions

### 1) Use zap as the single application logger
- Decision: Replace current runtime logger with `zap.Logger` and use structured fields (`error`, `node_key`, `reason`, etc.) consistently.
- Rationale: Zap is performant, production-friendly, and standard for structured JSON logs.
- Alternatives considered:
  - Keep existing logger: rejected due to weaker ecosystem integration and consistency for structured fields.
  - Use sugared logger everywhere: rejected to keep typed fields and lower overhead.

### 2) Add OTel tracing baseline with OTLP exporter
- Decision: Initialize OpenTelemetry tracer provider at startup with configurable OTLP endpoint and service name.
- Rationale: Provides interoperable traces and immediate compatibility with SigNoz/OTLP collectors.
- Alternatives considered:
  - No tracing, logs only: rejected due to weak request correlation across services.
  - Vendor-specific SDK first: rejected to keep portability and avoid lock-in.

### 3) Instrument gin with otel middleware
- Decision: Add OTel gin middleware to create request spans and propagate context through handlers.
- Rationale: Keeps tracing integration low-friction and captures the critical `/register` and `/verify` paths.
- Alternatives considered:
  - Manual spans in each handler only: rejected due to inconsistent coverage and maintenance overhead.

### 4) Trace/log correlation strategy
- Decision: Keep logs in zap and include trace context in request-scoped logging paths where available, while traces are exported through OTel SDK.
- Rationale: Gives immediate correlation utility without requiring OTel log signal rollout.
- Alternatives considered:
  - OTel log bridge now: deferred to avoid additional complexity and immature signal usage in this phase.

### 5) Config-driven rollout
- Decision: Telemetry activation is controlled by env configuration (service name, OTLP endpoint, insecure flag, enable switch) with safe defaults.
- Rationale: Supports local development and staged production rollout without code changes.

## Risks / Trade-offs

- [Misconfigured OTLP endpoint may add startup/runtime noise] -> Mitigation: explicit startup logs and graceful shutdown hooks.
- [Extra instrumentation overhead on hot verify path] -> Mitigation: keep middleware simple, use batch processor defaults, and allow toggle via config.
- [Potential sensitive data in logs] -> Mitigation: preserve redaction policy and avoid token fields in all log calls.
- [Incomplete observability if collector unavailable] -> Mitigation: logging remains local and tracing initialization failures are surfaced clearly.

## Migration Plan

1. Add zap + OpenTelemetry dependencies.
2. Introduce telemetry config fields and startup initialization.
3. Replace logger usage in router/service/bootstrap with zap.
4. Add gin OTel middleware and ensure context propagation.
5. Add/adjust tests for logger/telemetry-safe behavior and existing API behavior regression checks.
6. Deploy with telemetry disabled by default or with OTLP endpoint configured per environment.

Rollback:
- Disable telemetry via config/env and redeploy; fall back to local structured logs.
- Revert logger/telemetry commit if runtime issues occur.

## Open Questions

- Should we export only traces in v1, or also enable OTel metrics/log signal in the next change?
- Do we standardize trace/span field names in logs now or in a broader observability guideline?
- Should we add per-endpoint sampling controls for high-QPS `/verify` traffic?
