## Context

See proposal.md (Why) for the motivation. This section covers only the current state that shapes the design, as read from the code at `2a81399`.

- Policy (`policy/policy.go`) is one Casbin `SyncedEnforcer` over `gorm-adapter`, loaded once at startup. The model is `r = sub, obj, act` with role inheritance `g = _, _`. The matcher allows role inheritance and also a direct `r.sub == p.sub` match. `/verify` calls `Enforce("device:<node_key>", "derp:default", "connect")`. After the registration transaction commits, `/register` writes `g, device:<node_key>, user:<user_id>` and `g, user:<user_id>, role:standard`. `Bootstrap` seeds `p, role:standard, derp:default, connect`. With `ENABLE_CASBIN=false` the engine allows everything and writes nothing.
- The verify cache (`service/cache.go`) is per process and keyed by node key, with epoch-based invalidation. `SetDeviceRevoked` and `SetUserDisabled` invalidate only the local cache.
- `/admin` (`server/admin.go`) is mounted when `ADMIN_API_KEY` is set. It checks one static bearer key in constant time, behind a single shared `rate.Limiter`. `/register` already uses a per-IP limiter (`server/ratelimit.go`) keyed by the TCP peer, because the router trusts no proxy headers.
- `db/migrate.go`: sqlite runs gorm `AutoMigrate` on the four models and ignores the SQL files. Postgres runs each `migrations/*.sql` once. Every new table therefore needs a model and a SQL migration, and any data upgrade must be idempotent Go code that runs on both.
- `audit_logs.device_id` has `ON DELETE SET NULL` only in the Postgres SQL. The `AuditLog` model declares no foreign key, so on sqlite nothing nulls it.
- derper (tailscale v1.84.3) POSTs `tailcfg.DERPAdmitClientRequest{NodePublic, Source}` to `--verify-client-url` with no identifying header. `--verify-client-url-fail-open` defaults to `true`.
- `config/config.yaml` ships `enable_casbin: true`, and `config/config_test.go` sets `enable_casbin: false`.
- Existing tests create users by SQL and expect `/register` followed by `/verify` to allow (`TestVerifyAllowUpdatesLastSeenAndAudit`, `TestAdminLifecycleEndToEnd`, among others). `TestVerifyPolicyDenied` inserts a device with no Casbin rules and expects `policy denied`.

## Goals / Non-Goals

**Goals:**
- Role-based, per-relay admission with Casbin, where the database is the only source of truth and every instance converges within a stated bound.
- Tiered, attributable admin access, with every authenticated mutation recorded atomically with its effect.
- An upgrade that keeps existing derper configs, admin callers and allowed devices working without manual steps.
- Keep the `/register` and `/verify` core logic and its tests. Only the changes named in the specs are allowed.

**Non-Goals:**
- Authenticating derpers to `/verify`. The relay name in the URL is trusted (decision B3).
- Deny rules, direct user grants, and an endpoint that explains a denial.
- Admin audit retention or pruning.
- A CI workflow, removing the empty `openspec/changes/refactor-derp-admit-layout` stub, and upgrading tailscale (needs Go 1.27.4). These are follow-ups.
- An automated end-to-end test with a real Tailscale client. Compose wiring is checked with `docker compose config` and a documented manual smoke test.

## Approaches

### Policy subject: per-device rules vs per-user subjects
- **Per-device rules (today).** Each registration writes `g, device:<node_key>, user:<user_id>`. Policy can then tell devices apart, but nothing uses that. Policy also duplicates the `devices` table, registration has a second, non-transactional write, and a device row with no rule is silently denied.
- **Per-user subjects (picked).** `/verify` already loads the device row, so its `user_id` is at hand. Enforcing `user:<user_id>` removes the duplicate state and the post-commit write, and the `devices` table stays the only device-to-user mapping. It loses per-device policy, which no decision asks for. Decided by the change author (decision A2).

### Cross-instance sync: periodic full reload vs version check vs LISTEN/NOTIFY
- **Periodic full reload (`StartAutoLoadPolicy`).** It is built in and simple. But every instance reloads the whole `casbin_rule` table every interval whether or not anything changed, nothing tells an instance that it is stale, and lifecycle changes (revoke, disable) do not live in `casbin_rule`, so cached decisions on other instances are not dropped.
- **Version check in the database (picked).** One cheap read per interval. A reload happens only when something changed. The same version covers lifecycle changes, so remote caches are dropped too. A failed read gives a clear staleness signal for the fail-closed rule. It works the same on sqlite and Postgres. The cost is that every decision-affecting write must bump the version in its transaction, and the staleness bound is the polling interval rather than immediate. Decided by the change author (decisions C1 to C5).
- **Postgres LISTEN/NOTIFY.** Near-immediate. But it is Postgres-only while tests run on sqlite. Notifications are lost while a connection is down, so a version check is needed anyway to recover. It also needs a dedicated connection outside gorm's pool.

### Relay identification: URL path vs query parameter vs separate listener or secret per relay
- **URL path, `POST /verify/:relay` (picked).** derper takes the verify URL as an opaque string, so any form that fits in a URL works. A path segment is visible in access logs and routing, cannot collide with other query parameters, and plain `/verify` maps cleanly to `default`. Decided by the change author (decision B1).
- **Query parameter, `/verify?relay=eu-1`.** It works equally well with derper. It is easier to drop by accident in proxies and URL rewriting, and less visible in route-level metrics.
- **Separate listener or shared secret per relay.** This would let the verifier authenticate which relay is calling. derper sends no headers, so the secret would have to sit in the URL anyway. That costs a listener or a secret per relay for a guarantee the owner did not ask for. Authenticating derpers is a non-goal.

### Admin key bootstrap: permanent root key vs import-on-startup bootstrap key vs separate enable flag
- **Permanent root key from env.** `ADMIN_API_KEY` stays an all-powerful key beside the stored keys. It is simple, but it cannot be revoked through the API, is not attributable, and defeats the tier model.
- **Import-on-startup bootstrap key (picked).** `ADMIN_API_KEY` keeps its two existing roles: it enables `/admin`, and it lets existing callers in. It becomes an ordinary stored key named `bootstrap`, so it is audited, revocable and covered by the lockout guard. Restarting with no active admin key recovers access. The cost is the three startup cases in `admin-access-control`. Decided by the change author (decision D3).
- **Separate enable flag** (for example `ADMIN_API_ENABLED`) plus a one-time key printed or created out of band. It is clean, but it changes every existing deployment's configuration, and it needs a second secret channel for the first key.

## Decisions

Who decided is given in brackets: [OWNER] means the owner's answers of 2026-11-23; [author] means the author of this change, including the resolutions R1 to R11 given after the first draft.

### Owner answers
- Engine: keep Casbin. [OWNER, answer 2]
- Scope: rebuild the permission layer and the admin API only. Keep the `/register` and `/verify` core logic and tests. Also add delete endpoints, pagination, metrics, `.env.example` and working derper wiring in compose. [OWNER, answer 3]
- Capabilities: roles decide connect, with roles and bindings managed through the admin API; per-relay authorization; tiered admin keys with every admin operation audited and queryable; policy changes take effect across instances without a restart. [OWNER, answer 1]
- Security fix 1: `/register` refuses a revoked node key of the same user with `403`. Only the admin API re-enables it. [OWNER, answer 4]
- Security fix 2: the `/admin` rate limit is per client IP and still runs before authentication. [OWNER, answer 4]

### A. Access model
- A1 Casbin stays. Roles decide connect, per relay. [OWNER]
- A2 The subject is `user:<user_id>`, resolved from the `devices` table. The object is `derp:<relay>` and the action is `connect`. Registration writes no rules, and legacy device rules are obsolete. [author]
- A3 Grants are role-level and allow-only, on named relays or on `*`. There are no direct user grants and no deny rules. Uncovered requests get `policy denied`. [author] Because the existing matcher also allows a direct `r.sub == p.sub` match, the builder must make sure only role grants can allow. [author]
- A4 `roles` and `relays` are registry tables (name, description, created_at), and names match `^[a-z0-9][a-z0-9-]{0,62}$`. Grants and bindings stay Casbin rules in their existing format: `p, role:<name>, derp:<relay>, connect` and `g, user:<id>, role:<name>`. [author] The `*` grant is stored as an `all_relays` flag on the role's registry row and expanded over the registered relays in memory when policy is loaded. It is never stored in `casbin_rule`, so no rule that exists before the upgrade, `derp:*` included, can act as a wildcard. Decided on 2026-11-23, replacing the earlier "builder's choice". [author]
- A5 Built-ins are relay `default` and role `standard`, with `standard` granted on `default`. They are seeded idempotently at startup and cannot be deleted (`409`). [author] The grant is seeded only when `standard` is created, so that edits to the grants of `standard` survive a restart. [author]
- A6 `POST /admin/users` binds `standard` when `roles` is omitted, and no role when `roles` is `[]`. A user with no binding fails closed. [author]
- A7 One-time upgrade, on both backends, in one transaction after seeding (A5), with a durable marker that prevents re-runs. It deletes no `casbin_rule` row. [author]
  - R1/S1 Invariant: no device that `POST /verify` denied immediately before the upgrade is allowed immediately after. A user is "covered on `default`" when, after the R4 import, the user has a managed binding `g, user:<id>, role:<name>` to a registered role that has a managed grant on `default`. No pre-upgrade rule can act as the `*` wildcard. Policy counts as enforced before unless `ENABLE_CASBIN=false` / `enable_casbin: false` is in effect on the upgrading instance. Not enforced: every user who is not covered is bound to `standard`, so every device allowed before stays allowed. Enforced: a user who is not covered and has no device rows is bound to `standard`, because the old version bound `standard` at first registration whatever other bindings the user had. A user who is not covered and has device rows is left as is and reported. For a covered user, a non-revoked device with no legacy rule `g, device:<node_key>, user:<owner id>` naming its owner is revoked and reported. The invariant concerns relay `default`, the only relay the previous version evaluated. [author]
  - R1/S2 Reporting: one warning with the ids and count of users left not covered, the ids and count of devices revoked, and the count of unmanaged rules. Devices that lose access only because rules outside the managed shapes stop granting are not listed: shipped code need not reconstruct the old model's per-device decision. Only `TestUpgradeNeverLoosens` does that. Each revocation gets an admin audit row with actor `system`. The admin audit table must therefore exist when the upgrade first runs (task 2.1). [author]
  - S3 When several new instances start at once against one database, schema migration, seeding and the one-time upgrade each take effect exactly once, and every instance starts. The mechanism is the builder's choice, for example a Postgres advisory lock around startup data changes, or relying on sqlite's `_txlock=immediate` serialization. This is separate from R6: mixed-version operation stays unsupported. [author]
  - R2 Legacy `g, device:*, user:*` rules are kept. They grant nothing in the new model, and are removed only when their device or user is deleted. [author]
  - R4 Every valid role name in `g, user:<uuid>, role:<name>` or `p, role:<name>, derp:<relay>, connect`, and every valid relay name in such `p` rules, is added to the registries. Every other rule stays in the table, never grants anything, and is counted in the warning. That includes direct `p` rules on `user:`/`device:`, other actions, invalid names, other grouping shapes, and a pre-existing `derp:*` object. The invariant is one-directional: devices allowed only by such rules become denied. Only the rule count is reported, not those devices (S2). Because of the `derp:*` case, the representation of the `*` grant (A4) must not let a rule that existed before the upgrade act as a wildcard. [author]
- A8 `ENABLE_CASBIN` is removed and ignored for enforcement with a warning, whatever its value and wherever it is set (env, `.env`, `config.yaml`). Failing startup instead would leave derpers on their default fail-open, which would admit everyone. The one-time upgrade reads it for R1 only. An unparsable value counts as not `false`, so policy counts as enforced. [author]
- A9 (R3) From this change on, the admin API is the only supported way to provision roles, grants, bindings and relays. A deployment without `ADMIN_API_KEY` can still insert users and tokens by SQL. Such users have no role and are denied until bound through the admin API. Rows changed by SQL are picked up only at restart. [author]

### B. Multi-relay
- B1 `POST /verify/:relay`. `POST /verify` means `default`. [author]
- B2 An unknown or malformed relay is denied with `unknown relay` in the normal response format, and audited. [author]
- B3 `/verify` stays unauthenticated, and the relay name is trusted as asserted (see Non-Goals). [author]
- B4 The cache key is (relay, node key). Verify audit rows record the relay in a new `audit_logs` column. [author] (R9) A name that matches the name format is stored as given, even when it is not in the registry. A malformed name is stored as null. Pre-upgrade rows hold null, with no backfill. The `relay` filter matches exactly. [author]
- B5 Checks run in this order: parse, relay known, registered, revoked, user disabled, policy. [author] The global verify rate limit stays in front of all of them, unchanged. [author, from the code] (S5/S6) Every deny produced after the rate limit is audited, including a body that is not valid JSON, which `server/router.go` answers today without an audit row. Rate-limited requests stay unaudited, as today, so a flood cannot fill the audit table. [author]

### C. Sync
- C1 The database is the source of truth. A stored policy version is bumped in the same transaction as each decision-affecting change. Each instance polls it every `POLICY_SYNC_INTERVAL` (default `2s`). The instance that made a change applies it before it responds. [author]
- C2 Role, grant, binding and relay changes reload the snapshot and drop all cached decisions. Device and user lifecycle changes and registrations drop cached decisions. [author] With a single version number, an instance that sees it move cannot tell which keys changed. The simplest catch-up is to reload and drop the whole cache, but the spec only requires the outcome. [author]
- C3 The bound: another healthy instance reflects a committed change within two sync intervals. [author]
- C4 Fail closed: after more than three intervals without a successful check, `/readyz` returns `503` and `/verify` returns `internal error`, including for requests that would be answered from the cache. [author]
- C5 Mechanism is the builder's choice. Options include writing `casbin_rule` rows through the same gorm transaction as the change and then calling `SyncedEnforcer.LoadPolicy`, or the adapter's `Transaction` / `NewTransactionalAdapterByDB` support, whose semantics have not been verified. The requirement is that the change, the version bump and the admin audit row are atomic. [author]

### D. Admin keys, tiers, audit
- D1 Stored, tiered admin keys replace the static key. [OWNER]
- D2 The `admin_keys` table holds id, unique name, tier, key hash, created_at, expires_at, revoked_at and last_used_at. A key is `dak_` plus base64url of 32 random bytes, and is stored as `hex(sha256(key + ":" + TOKEN_PEPPER))`. [author]
- D3 `ADMIN_API_KEY` enables `/admin` and is the bootstrap key (at least 16 characters). At startup: if `bootstrap` is active, its hash follows the env value; else, if no other active admin-tier key exists, `bootstrap` is created or reactivated; else the env value grants nothing and this is logged. Startup actions are audited as actor `system`. (R11) The name `bootstrap` is reserved: `POST /admin/keys` with it returns `409`. [author] The order of the three checks, treating an expired or absent `bootstrap` like a revoked one, writing no audit row when nothing changes, and treating a lost unique-name race between replicas as already done are additions. [author]
- D4 Revoking the last active admin-tier key returns `409`. Expiry can still leave none, and D3 recovers on restart. [author]
- D5 The tier matrix is as specified in `admin-access-control`. [author]
- D6 Every authenticated mutation is audited, including `403`. A successful mutation's audit row is written in the same transaction as the change. `401` is only logged and counted. Read-only requests are not audited. [OWNER wants everything audited and queryable; the details are the author's] `429` is treated like `401`, and failed mutations (`400`, `404`, `409`) are audited too. [author]
- D7 Audit queries are `GET /admin/audit/admin` (tier `admin`) and `GET /admin/audit/verify` (tier `viewer`), paginated newest first. [author]
- D8 The `/admin` limiter is per client IP, before authentication, keyed by the TCP peer. It keeps the `ADMIN_RATE_LIMIT_RPS` / `ADMIN_RATE_LIMIT_BURST` names. [OWNER for per-IP; the rest is the author's] It reuses the `/register` limiter type with its own instance. [author] The limiter type groups IPv6 peers by /64, for `/admin` and `/register` alike, because one host or site normally holds a whole /64 and per-address buckets would not bound it. Added on 2026-11-23 after a security review of the per-IP change. [author]

### E. Lifecycle API
- E1 `DELETE` for users (with their tokens, devices and bindings), devices and tokens. `200`, `404` and `400` as usual. [OWNER for scope; the details are the author's] Deletion must be explicit, in one transaction: delete the child rows, the `g, user:<id>, *` rules and the legacy `g, device:<node_key>, user:<id>` rules (R2), and set `audit_logs.device_id` to null, rather than relying on foreign-key cascades. sqlite has no `ON DELETE SET NULL` on that column, and does not enforce foreign keys unless `PRAGMA foreign_keys` is on. [author, from the code]
- E2 Revoke is a ban and delete is forgetting. [author]
- E3 A revoked node key of the same user gets `403` at `/register`. A node key of another user still gets `409`. [OWNER]
- E4 `limit` (default 50, max 200) and `cursor` on every list. `nextCursor` is null on the last page. Order is created_at ascending with an id tie-break, and audit lists are newest first. [OWNER for scope; the details are the author's] Roles and relays have no id, so they tie-break on name. Cursors are opaque, and an invalid one returns `400`. [author]
- E5 User views carry `roles`. `PUT /admin/users/:id/roles` replaces them. [author]
- E6 and E7 Role and relay endpoints are as specified in `access-management-api`. (R10) `*` must be the only element of a `relays` list; mixing it with names returns `400`. [author]

### F. Service gaps
- F1 `GET /metrics` on the main listener, unauthenticated, switched by `METRICS_ENABLED` (default `true`), using `prometheus/client_golang`. Series and label rules are in `service-metrics`. [OWNER for scope; the details are the author's] Metric names are chosen by the builder and listed in the README. [author]
- F2 Restore `.env.example` and add `!.env.example` to `.gitignore`. [OWNER]
- F3 A real `derper` service in compose, wired to `http://verifier:8080/verify/default` with `--verify-client-url-fail-open=false`. Acceptance is `docker compose config` passing plus a documented manual smoke test. There is no automated end-to-end test with a Tailscale client. [OWNER for scope; acceptance is the author's] (R7) The builder verifies that the derper image reference actually pulls. If no usable published image can be verified, compose builds derper from the tailscale module version pinned in `go.mod`. The TLS choice used for the smoke test is documented. [author]
- F4 The README covers every change above, plus upgrade notes for A7, A8, D3 and E3. [OWNER]

## Risks / Trade-offs

- [The upgrade revokes devices and leaves users unbound (R1).] Devices that were `policy denied` stay denied, now as `revoked`. Devices allowed only by rules outside the managed shapes (R4) become denied without being listed; only the count of such rules is reported (S2). → Users left not covered and revoked devices are reported in one startup warning with ids, and revocations are audited as `system`. The README upgrade notes tell operators to review the warning and re-enable or bind through the admin API.
- [A deployment that drops `ENABLE_CASBIN=false` before the first start is upgraded as if policy was enforced.] Users with devices who are not covered then stay as they are and are denied. → The README upgrade notes say to keep the setting for the first start.
- [Devices registered after the upgrade are denied by the previous version.] See Migration Plan, Rollback.
- [Per-IP admin limiting weakens the brute-force bound.] Under a shared bucket, key guessing was bounded in total. Per IP, it is bounded per source address. Generated `dak_` keys carry 256 bits, so this does not matter for them. The operator-chosen `ADMIN_API_KEY` only has to be 16 characters long. → Mitigation: the README recommends a high-entropy `ADMIN_API_KEY` and creating named keys, then revoking `bootstrap`. IPv6 peers are bucketed by /64. No aggregate limit is kept: an aggregate bound and "unauthenticated traffic cannot starve the admin caller" exclude each other, and the owner chose the latter. The limiter still forgets buckets when it tracks more than 10000 clients; a source with that many addresses is not bounded by per-client limiting either way.
- [Behind a reverse proxy, all admin callers share one bucket.] The router trusts no forwarded headers. → Accepted and documented.
- [Rate limits are per instance.] With N replicas, the effective limits are N times the configured ones. → Accepted and documented.
- [Staleness window.] Another instance can serve a decision up to two intervals old (4s by default). → Bounded and documented. Lower `POLICY_SYNC_INTERVAL` if needed.
- [Fail closed under database trouble.] An instance that cannot reach the database denies all clients after three intervals, even ones it could have answered from the cache. → This is intended. `/readyz` returns `503`, so orchestrators can route around it.
- [Policy edits made by SQL are applied only at restart (A9).] → Documented as unsupported. Use the admin API.
- [The relay name is caller-asserted.] A misconfigured derper can claim a more permissive relay. → Documented trust statement (B3). The derper URL configuration is trusted.
- [`last_used_at` is written on every authenticated admin request.] This adds one write per call. → Admin traffic is low. A failed write must not fail the request.
- [Admin audit growth.] There is no retention. → Retention is a follow-up.

## Migration Plan

Upgrade:
1. Archive `harden-registration-and-admin-api` after owner review, so this change's deltas apply to main specs that contain its requirements.
2. Take a database backup. The upgrade revokes devices and changes bindings.
3. Stop every old instance before the first new instance starts. Mixed-version operation is not supported (R6): old instances neither bump nor check the policy version, and their admin writes bypass the version and the audit.
4. If the deployment runs with `ENABLE_CASBIN=false` / `enable_casbin: false`, leave it in place for the first start. The one-time upgrade reads it to decide how to bind users (R1). Remove it after the first start; until then it is ignored for enforcement, with a warning.
5. Start the new version. It migrates the schema (new tables, plus a relay column on `audit_logs`), seeds `default` and `standard`, runs the one-time upgrade, and creates `bootstrap` from `ADMIN_API_KEY`.
6. Check: read the upgrade warning (users left unbound, devices revoked, rules that grant nothing). `GET /admin/users` (with the old `ADMIN_API_KEY`) shows the expected `roles`, devices that were allowed are still allowed through plain `/verify`, and `GET /admin/audit/admin` shows the `system` rows.
7. Optional: create relays, roles and named keys, and point additional derpers at `/verify/<relay>`.
8. Deployments that provision by SQL: users and tokens can still be inserted, but such users are denied until bound to a role through the admin API (A9). Policy rows changed by SQL are applied only at restart.

Rollback:
- Stop every new instance before starting the previous version, and keep the backup from step 2 as the last resort.
- Legacy device rules are kept (R2), so devices that existed before the upgrade keep working under the previous version. Devices registered after the upgrade have no device rule. The previous version denies them with `policy denied` until they register again.
- The previous version matches `derp:default` only, so grants on other relays or on `*` have no effect there. Bindings and grants created through the admin API use the existing rule format, and the previous version reads them.
- Devices revoked under the new version, including those the upgrade revoked, stay revoked. The previous version lets `/register` reactivate them.
- New tables and the `audit_logs.relay` column can stay. The previous version ignores them.
- The previous version authenticates `/admin` with `ADMIN_API_KEY` directly, so admin access survives a rollback. Named keys stop working.

## Open Questions

None blocking. These are decisions the owner may want to overrule:

- A6: new users created through the admin API default to role `standard` when `roles` is omitted.
- A8: `ENABLE_CASBIN` is ignored for enforcement, with a warning, rather than failing startup.
- C3/C4: other instances reflect a change within two sync intervals, and an instance fails closed after three intervals without a successful check.
- D3: `ADMIN_API_KEY` is both the switch that enables `/admin` and the bootstrap key.
- R1: the upgrade never loosens access, which includes revoking devices that were `policy denied` before.
- R3: provisioning policy by SQL is unsupported, and SQL changes are applied only at restart.
