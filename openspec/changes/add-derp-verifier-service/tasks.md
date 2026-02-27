## 1. Project Bootstrap

- [x] 1.1 Initialize Go 1.22+ service skeleton for `derp-verifier` with `cmd/` entrypoint and internal packages for config, handlers, store, and policy
- [x] 1.2 Add core dependencies (HTTP framework, PostgreSQL driver/ORM or query layer, tailscale `tailcfg`, Casbin core + Postgres adapter, migrations, test tooling)
- [x] 1.3 Implement configuration loading and validation for required env vars (`DATABASE_URL`, `TOKEN_PEPPER`) and server bind address `:8080`

## 2. Database Schema and Migrations

- [x] 2.1 Create migration for `users`, `enroll_tokens`, `devices`, and `audit_logs` tables with required columns, constraints, and timestamps
- [x] 2.2 Add required indexes for lifecycle checks and hot-path lookups (`token_hash`, `node_key`, `revoked_at`, `disabled_at`, audit time queries)
- [x] 2.3 Create migration for `casbin_rule` table compatible with selected Casbin Postgres adapter
- [x] 2.4 Add migration verification tests or checks to ensure schema applies cleanly on empty database

## 3. Enrollment Domain and Register API

- [x] 3.1 Implement token hashing utility `hex(sha256(token + ":" + TOKEN_PEPPER))` and ensure token plaintext is never logged
- [x] 3.2 Implement enrollment token and user validation logic for not-found (`401`), revoked/expired (`403`), and disabled user (`403`)
- [x] 3.3 Implement max-devices enforcement using active device count (`revoked_at IS NULL`) for token owner
- [x] 3.4 Implement node key ownership rules (`409` cross-user conflict, same-user idempotent `200`, same-user revoked reactivation)
- [x] 3.5 Implement `POST /register` handler with request/response contract `{token,nodeKey,label?}` -> `{ok:true}` on success

## 4. Casbin Policy Integration

- [x] 4.1 Implement Casbin model setup (RBAC `r,p,g`) and Postgres adapter initialization
- [x] 4.2 Add startup bootstrap to idempotently ensure `p, role:standard, derp:default, connect`
- [x] 4.3 On successful registration, upsert grouping policies `g, device:<node_key>, user:<user_id>` and `g, user:<user_id>, role:standard`
- [x] 4.4 Implement policy service abstraction used by verify flow for `Enforce("device:<node_key>", "derp:default", "connect")`

## 5. Verify API and Audit Logging

- [x] 5.1 Implement `POST /verify` request parsing using `tailcfg.DERPAdmitClientRequest` and robust node key extraction
- [x] 5.2 Implement verify decision pipeline for `not registered`, `revoked`, `user disabled`, and `policy denied` deny reasons
- [x] 5.3 Implement allow path response (`Allow=true`) and `devices.last_seen_at` update only on allow
- [x] 5.4 Implement deny/allow response generation as `tailcfg.DERPAdmitClientResponse`
- [x] 5.5 Implement mandatory `audit_logs` write for every verify request, including nullable `device_id` for unknown device denies

## 6. Runtime Safety and Operability

- [x] 6.1 Add per-request DB context timeouts for register/verify data access paths
- [x] 6.2 Add lightweight in-process rate limiting for `/verify` (global or per remote IP)
- [x] 6.3 Add structured logging and redaction rules to prevent token leakage in logs
- [x] 6.4 Add optional short TTL node-key decision cache hook behind config flag (disabled by default if not implemented in v1)
- [x] 6.5 Add health/readiness endpoints and basic operational metrics/log fields for deny-reason visibility

## 7. Test Coverage and Local Deployment

- [x] 7.1 Add register tests: invalid token `401`, expired/revoked token `403`, cross-user node key conflict `409`, max-devices limit `403`
- [x] 7.2 Add verify tests: unregistered deny `not registered`, revoked deny `revoked`, disabled user deny `user disabled`, allow returns `Allow=true`
- [x] 7.3 Add verify side-effect tests: `last_seen_at` updated on allow and unchanged on deny
- [x] 7.4 Add audit logging tests: allow and deny both create audit rows, unknown device deny writes `device_id=null` with reason
- [x] 7.5 Add Casbin integration tests: policy bootstrap idempotency and policy-denied verify path
- [x] 7.6 Add Docker Compose wiring for verifier + Postgres (+ derper integration notes) with `--verify-client-url=http://verifier:8080/verify`
