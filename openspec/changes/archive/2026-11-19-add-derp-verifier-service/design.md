## Context

This change introduces a new sidecar service, `derp-verifier`, used by `derper --verify-client-url` for admission decisions. The service must support multiple users, multiple devices per user, token-based device enrollment, and deterministic allow/deny responses from `POST /verify`.

Deployment and runtime are intentionally constrained:
- Single region authorization target: object `derp:default`, action `connect`.
- PostgreSQL is the source of truth for identity, enrollment, device state, and audit logs.
- Optional-but-enabled Casbin policy layer with Postgres adapter for future policy growth.
- Fail-closed integration preference via `--verify-client-url-fail-open=false`.

## Goals / Non-Goals

**Goals:**
- Provide `POST /register` to bind a device `node_key` to a user through hashed enroll token validation.
- Provide `POST /verify` consuming `tailcfg.DERPAdmitClientRequest` and returning `tailcfg.DERPAdmitClientResponse`.
- Enforce deny decisions for unregistered device, revoked device, disabled user, and policy-denied cases.
- Persist audit logs for every verify request and update `devices.last_seen_at` on allow.
- Keep token plaintext out of storage and logs.
- Ensure an idempotent policy bootstrap for baseline role access (`role:standard` connect permission).

**Non-Goals:**
- Multi-region authorization objects or per-region policy routing.
- End-user UI or full admin portal.
- Replacing derper authentication internals beyond external verify callback integration.
- Designing advanced distributed cache/rate-limit infrastructure in v1.

## Decisions

### 1) Runtime topology and integration contract
- Decision: Run verifier as a standalone service on `:8080` in the same Docker network as derper; derper calls `http://verifier:8080/verify`.
- Rationale: Matches derper callback mechanism and isolates verifier rollout/operational concerns.
- Alternatives considered:
  - Embed verifier logic in derper: rejected due to tight coupling and harder independent delivery.
  - Split enrollment and verify into separate services: rejected due to unnecessary latency and extra coordination.

### 2) HTTP API contracts are fixed
- Decision: Expose exactly:
  - `POST /register` request `{ token, nodeKey, label? }` and response `{ ok: true }` on success.
  - `POST /verify` request parsed as `tailcfg.DERPAdmitClientRequest`, response as `tailcfg.DERPAdmitClientResponse`.
- Rationale: Keeps integration deterministic for both users (enrollment) and derper (admit callback).
- Alternatives considered:
  - Custom verify payload parsing by ad-hoc fields: rejected to avoid drift from tailscale official struct contract.

### 3) Registration status/error semantics are fixed
- Decision: `POST /register` status codes are fixed as:
  - `401`: token hash not found
  - `403`: token revoked/expired, user disabled, or max device reached
  - `409`: node key already bound to a different user
  - `200`: success (including idempotent same-user retry and same-user revoked reactivation)
- Rationale: Distinguishes authentication failure, policy/lifecycle denial, and ownership conflict for clients/ops.

### 4) Verify decision semantics are fixed
- Decision: Verify deny reasons are canonical:
  - `not registered`
  - `revoked`
  - `user disabled`
  - `policy denied`
- Rationale: Stable reason strings simplify audit analysis and monitoring.
- Alternatives considered:
  - Free-form deny reasons: rejected because they complicate alerting and analytics.

### 5) PostgreSQL schema and indexing follow the spec exactly
- Decision: Use four core tables with explicit lifecycle fields and indexes:
  - `users(id, username, email, disabled_at, created_at)`
  - `enroll_tokens(id, user_id, token_hash, expires_at, revoked_at, max_devices, note, created_at)`
  - `devices(id, user_id, node_key, label, created_at, last_seen_at, revoked_at)`
  - `audit_logs(id, device_id, node_key, allowed, reason, ts)`
- Rationale: Supports hot-path queries:
  - token lookup by `token_hash`
  - device lookup by unique `node_key`
  - active device counting by `user_id` + `revoked_at`
  - time-based audit retrieval
- Alternatives considered:
  - Single table or JSON blob storage: rejected for weaker constraints and query performance.

### 6) Token hashing and secret handling are fixed
- Decision: Store only `token_hash = hex(sha256(token + ":" + TOKEN_PEPPER))`; never store or log token plaintext.
- Rationale: Provides deterministic lookup while minimizing token leakage risk.
- Alternatives considered:
  - Plaintext token storage: rejected for obvious secret exposure risk.
  - Adaptive password hash: not selected for deterministic lookup workflow.

### 7) Casbin RBAC chain and storage are enabled
- Decision: Enable Casbin with PostgreSQL adapter and RBAC relation chain:
  - `g, device:<node_key>, user:<user_id>`
  - `g, user:<user_id>, role:standard`
  - `p, role:standard, derp:default, connect`
- Verify enforcement call is fixed:
  - `Enforce("device:<node_key>", "derp:default", "connect")`
- Casbin model uses standard RBAC (`r=sub,obj,act`; `p=sub,obj,act`; `g=_,_`) with inheritance in matcher.
- Rationale: Delivers immediate policy control while keeping future role/resource extension path.
- Alternatives considered:
  - No Casbin and DB flag checks only: rejected due to poor extensibility.
  - Direct user policy without role layer: workable fallback, not selected for this version.

### 8) Startup policy bootstrap is idempotent
- Decision: On startup, ensure baseline rule exists once:
  - `p, role:standard, derp:default, connect`
- Rationale: Prevents cold-start policy outages and avoids manual pre-seeding requirement.
- Alternatives considered:
  - Manual SQL/casbin seeding only: rejected because it creates operational foot-guns.

### 9) Verify path performance guardrails
- Decision: All DB operations run with context deadlines; `/verify` applies lightweight in-process token-bucket rate limiting; short TTL node-key cache is optional.
- Rationale: Admission path must be bounded and resilient under burst/scanning traffic.
- Alternatives considered:
  - No rate limiting: rejected because DB can be trivially pressured.
  - Mandatory cache in v1: deferred until production metrics justify complexity.

### 10) Verify audit behavior is mandatory
- Decision: Every `/verify` call writes one `audit_logs` row (with nullable `device_id` for unknown devices) and mirrors deny reason string.
- Rationale: Required for incident response and troubleshooting.

## Risks / Trade-offs

- [Fail-closed causes deny during verifier outage] -> Mitigation: health checks, restart policy, and capacity/SLO monitoring.
- [Casbin adds operational complexity] -> Mitigation: keep single role + fixed object/action in v1 and bootstrap rule automatically.
- [Verify traffic spikes impact DB] -> Mitigation: query indexes, strict timeouts, local rate limiting, optional short TTL cache.
- [Token leakage via logs] -> Mitigation: explicit log sanitization and no token fields in structured logs.
- [Audit table growth over time] -> Mitigation: retention and archival plan after baseline usage data is collected.

## Migration Plan

1. Apply DB migrations for `users`, `enroll_tokens`, `devices`, `audit_logs`, and `casbin_rule`.
2. Deploy verifier with required env:
  - `DATABASE_URL`
  - `TOKEN_PEPPER`
3. Start verifier and run idempotent bootstrap for baseline Casbin `p` rule.
4. Prepare users and enroll tokens; register initial devices through `POST /register`.
5. Configure derper:
  - `--verify-client-url=http://verifier:8080/verify`
  - `--verify-client-url-fail-open=false`
6. Validate end-to-end admit behavior and monitor:
  - verify latency/error rate
  - deny reason distribution
  - audit write throughput

Rollback:
- Revert derper `--verify-client-url` configuration to disable external verify path.
- Keep verifier DB state intact for future re-enable; no destructive rollback migration required.

## Open Questions

- Should v1 include admin APIs for user/token/device lifecycle, or rely on SQL + operator scripts first?
- Should we enable short TTL node-key decision caching from day one or defer until load metrics justify it?
- Should startup optionally create a bootstrap admin user and initial enroll token, or leave bootstrapping external?
- Should we fix implementation stack now (`Gin/Fiber`, `pgx+sqlc/GORM`) or keep that as an internal implementation choice?
