## Why

The DERP deployment needs a dedicated verifier service so `derper --verify-client-url` can make consistent allow/deny decisions based on registered devices, revoked state, and user authorization. This is needed now to move from ad-hoc access control to auditable, multi-user, production-ready admission control backed by PostgreSQL.

## What Changes

- Add a new Go sidecar service `derp-verifier` with `POST /register` and `POST /verify` endpoints for DERP client admission.
- Introduce a PostgreSQL data model for users, enroll tokens, devices, and verify audit logs.
- Enforce device registration via token binding and prevent cross-user node key takeover.
- Evaluate verify decisions using device/user state and policy authorization on fixed resource `derp:default` + action `connect`.
- Persist verify outcomes (allow/deny + reason) for traceability and troubleshooting.
- Define runtime safety expectations for verifier availability, request timeout, rate limiting, and token secrecy in logs.

## Capabilities

### New Capabilities

- `device-enrollment`: Register and manage DERP client devices by binding `node_key` to a user through hashed enroll tokens, including expiry/revocation/max-device checks.
- `derp-client-verification`: Process DERP admit requests and return `tailcfg.DERPAdmitClientResponse` allow/deny based on registration, revocation, and user status.
- `derp-access-policy`: Authorize `device:<node_key>` on `derp:default/connect` using Casbin-backed RBAC relationships (device -> user -> role) stored in PostgreSQL.
- `verify-audit-logging`: Record each verify decision with reason and timestamp, and update device `last_seen_at` on allow.

### Modified Capabilities

- None.

## Impact

- Affected code: new verifier service, HTTP handlers, DB layer, policy integration, configuration loading, and tests.
- Affected APIs: new internal endpoints `POST /register` and `POST /verify` consumed by users and derper respectively.
- Affected infrastructure: PostgreSQL becomes required for verifier state and policy persistence; derper runtime uses `--verify-client-url=http://verifier:8080/verify`.
- Dependencies: Go 1.22+, PostgreSQL driver/ORM stack, tailscale `tailcfg` types, Casbin + Postgres adapter.
