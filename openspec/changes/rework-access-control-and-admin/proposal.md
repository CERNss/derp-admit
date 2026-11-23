## Why

The verifier grants every registered device the same access to one relay, through Casbin rules written per device at registration. Roles exist only as a fixed `role:standard`, and nothing manages them. The admin API is guarded by one static, all-powerful key, and none of its actions are recorded. Policy is held per process with no way to see changes made elsewhere, so a second instance or a SQL edit only takes effect after a restart. The owner asked on 2026-11-23 for role-based access per relay, tiered and audited admin keys, and policy that stays in sync across instances. The owner also decided the two open security questions left by `harden-registration-and-admin-api`.

## What Changes

- **BREAKING** Policy subjects become users. `/verify` resolves device to user and enforces `user:<user_id>` on `derp:<relay>` / `connect`. Registration no longer writes policy rules. Legacy `g, device:<node_key>, user:<user_id>` rules are kept but grant nothing, and are removed only when their device or user is deleted.
- Roles and relays become managed registries with admin endpoints. A role is granted `connect` on named relays or on all relays (`*`). Grants allow only. There are no direct user grants and no deny rules. A user with no role, or whose roles do not cover the relay, is denied with `policy denied`.
- Built-ins are seeded at startup: relay `default`, and role `standard` granted on `default`. A one-time upgrade imports roles and relays named in existing rules and binds users to `standard`. It never loosens access: where policy was enforced, users that were denied stay unbound, and devices that were denied are revoked. The upgrade reports both.
- **BREAKING** The admin API becomes the only supported way to provision roles, grants, bindings and relays. Users and tokens inserted by SQL get no role, and are denied until bound through the admin API. Policy rows changed by SQL are applied only at restart.
- **BREAKING** `ENABLE_CASBIN` is removed. Policy is always enforced. A leftover setting is ignored with a startup warning. The one-time upgrade still reads it, so a deployment running with `ENABLE_CASBIN=false` must keep it for the first start.
- Each derper names its relay in the URL path: `POST /verify/:relay`. Plain `POST /verify` means relay `default`. An unknown relay is denied with the new reason `unknown relay`. The verify cache is keyed by relay and node key, and verify audit rows record the relay.
- Policy changes reach every instance without a restart. Each decision-affecting change bumps a version in the database in the same transaction. Instances check it every `POLICY_SYNC_INTERVAL`. An instance that cannot confirm it is current fails closed.
- **BREAKING** The single static `ADMIN_API_KEY` is replaced by admin keys stored in the database with tiers `viewer`, `operator` and `admin`. `ADMIN_API_KEY` still enables `/admin`, and now also seeds or follows a `bootstrap` key of tier `admin`. A tier that is too low gets `403`.
- Every authenticated mutating admin request is recorded in an admin audit log. Admin and verify audit logs can be queried through the admin API.
- **BREAKING** `/register` refuses a revoked node key of the same user with `403`. Only the admin API re-enables it. (Owner decision.)
- The `/admin` rate limit becomes per client IP. It still runs before authentication. (Owner decision.)
- Users, enroll tokens and devices can be deleted. User views include their roles, and a user's roles can be replaced.
- **BREAKING** Every admin list endpoint is paginated with `limit` (default 50, max 200) and `cursor`. Callers that read one unpaged response get only the first 50 rows.
- A Prometheus `/metrics` endpoint, a restored `.env.example`, a working `derper` service in compose, and README upgrade notes.

## Capabilities

### New Capabilities
- `access-management-api`: Admin endpoints for roles and their relay grants, relays, and a user's role bindings, with the naming rules and built-in protections.
- `admin-access-control`: How `/admin` is enabled and authenticated: stored admin keys, tiers and their permissions, the bootstrap key, the lockout guard and the per-IP pre-auth rate limit.
- `admin-audit-logging`: The record of every authenticated mutating admin request and how it is queried.
- `policy-sync`: How policy and lifecycle changes reach every instance, the staleness bound, and fail-closed behaviour when an instance cannot confirm it is current.
- `service-metrics`: The Prometheus metrics endpoint, its switch, its series and its label rules.

### Modified Capabilities
- `derp-access-policy`: Per-user subjects, per-relay objects, role-level allow-only grants, built-ins, always-on enforcement, and the one-time upgrade of existing rules.
- `derp-client-verification`: Relay in the URL path, the `unknown relay` reason, a fixed check order, and a verify cache keyed by relay and node key that is also cleared on deletes and policy changes.
- `device-enrollment`: Revoked node keys are refused at `/register`. Reactivation is removed from the device limit. Revoke bans a node key and delete forgets it.
- `verify-audit-logging`: Rows record the relay and survive device and user deletion. Rows can be queried through the admin API.
- `admin-lifecycle-api` (defined by the unarchived change `harden-registration-and-admin-api`): Delete endpoints, pagination and roles in user views. Mounting, authentication and rate limiting move to `admin-access-control`.

## Impact

- Affected code: `policy` (model, subjects, sync), `service` (verify, register, admin, cache), `server` (router, admin routes, rate limiter, metrics), `db` (new tables, models and migrations, one-time upgrade), `model`, `config`, `cmd/derp_admit`.
- New tables: `roles`, `relays`, `admin_keys`, an admin audit table, and durable storage for the policy version and the one-time upgrade marker. Each needs a gorm model for sqlite and a SQL migration for Postgres. `audit_logs` gains a relay column.
- Affected APIs: new `POST /verify/:relay` and `GET /metrics`. New `/admin` routes for roles, relays, admin keys, user roles, deletes and audit queries. Admin list responses gain `nextCursor`, and admin responses can return `403`. `/register` returns `403` for a revoked node key. `/readyz` can return `503` when policy state is stale.
- Configuration: `ENABLE_CASBIN` is removed. New settings are `POLICY_SYNC_INTERVAL` (default `2s`) and `METRICS_ENABLED` (default `true`). `ADMIN_API_KEY` changes meaning, as described above.
- Dependencies: adds `github.com/prometheus/client_golang`.
- Operations: derper configs that call `/verify` keep working as relay `default`. Mixed-version operation is not supported: every old instance must be stopped before the first new instance starts. Deployments that provision users by SQL must bind roles through the admin API.
- Depends on `harden-registration-and-admin-api` being reviewed and archived first.
