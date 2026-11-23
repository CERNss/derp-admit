# derp-admit

`derp-admit` (`derp-verifier`) is an admission controller sidecar for Tailscale `derper` relays (`--verify-client-url`). It enrolls device node keys with admin-minted tokens, enforces role-based per-relay access with Casbin, and exposes a tiered, audited admin API.

## Endpoints

| Method & path | Auth | Purpose |
| --- | --- | --- |
| `POST /register` | Enroll token in body | Enroll a device's node key for the token's owner |
| `POST /verify` | None (caller-asserted) | Evaluate `derper` admission for built-in relay `default` |
| `POST /verify/:relay` | None (caller-asserted) | Evaluate `derper` admission for named relay `:relay` |
| `/admin/...` | Bearer admin key | Tiered management API (mounted only when `ADMIN_API_KEY` is set) |
| `GET /healthz` | None | Liveness probe (`200 {"ok":true}`) |
| `GET /readyz` | None | Readiness probe (`200` when DB ping succeeds and policy sync is current; `503` otherwise) |
| `GET /metrics` | None | Prometheus metrics (mounted when `METRICS_ENABLED=true`; `404` when `false`) |
| `GET /` | None | Service identity and current UTC timestamp |

Quick start:

```bash
cp .env.example .env
# Edit .env to set DATABASE_URL, TOKEN_PEPPER, and optionally ADMIN_API_KEY.
go run ./cmd/derp_admit
```

## Configuration

Configuration is loaded in this order (later overrides earlier):

1. Built-in defaults
2. `config/config.yaml` (override path with `CONFIG_FILE` in the process environment)
3. `.env` (override path with `ENV_FILE` in the process environment)
4. Real process environment variables

`.env.example` at the repository root lists every setting with its built-in default and leaves secrets blank. Because uncommented lines in `.env` override `config/config.yaml`, remove any line from `.env` that you want `config/config.yaml` to control.

`CONFIG_FILE` and `ENV_FILE` are read from the process environment only (not from `.env` or YAML).

### Settings

| Environment variable | YAML key | Default | Validation & notes |
| --- | --- | --- | --- |
| `CONFIG_FILE` | *(env only)* | `config/config.yaml` | Optional; missing file is ignored |
| `ENV_FILE` | *(env only)* | `.env` | Optional; missing file is ignored |
| `DATABASE_URL` | `database_url` | *(required)* | `postgres://`, `postgresql://`, or `sqlite://` (`sqlite://` is for tests and running from source; the container image is built without cgo and requires PostgreSQL) |
| `TOKEN_PEPPER` | `token_pepper` | *(required)* | Secret mixed into enroll token and admin key hashes: `hex(sha256(secret + ":" + TOKEN_PEPPER))` |
| `ADDR` | `addr` | `:8080` | HTTP listen address |
| `LOG_LEVEL` | `log_level` | `info` | Zap level (`debug`, `info`, `warn`, `error`, `dpanic`, `panic`, `fatal`) |
| `ADMIN_API_KEY` | `admin_api_key` | *(unset)* | Optional; enables `/admin` and configures the `bootstrap` admin key. Must be `>= 16` characters when set |
| `DB_TIMEOUT` | `db_timeout` | `2s` | Go duration, must be `> 0` |
| `POLICY_SYNC_INTERVAL` | `policy_sync_interval` | `2s` | Go duration, minimum `100ms` (values `< 100ms`, zero, or negative fail startup) |
| `VERIFY_RATE_LIMIT_RPS` | `verify_rate_limit_rps` | `100` | Must be `> 0`; global limit across `/verify` and `/verify/:relay` |
| `VERIFY_RATE_LIMIT_BURST` | `verify_rate_limit_burst` | `200` | Integer `> 0` |
| `VERIFY_CACHE_TTL` | `verify_cache_ttl` | `0s` | Go duration; `<= 0` disables the verify decision cache |
| `REGISTER_RATE_LIMIT_RPS` | `register_rate_limit_rps` | `5` | Must be `> 0`; per client IP (IPv6 grouped by `/64`) |
| `REGISTER_RATE_LIMIT_BURST` | `register_rate_limit_burst` | `10` | Integer `> 0` |
| `ADMIN_RATE_LIMIT_RPS` | `admin_rate_limit_rps` | `10` | Must be `> 0`; per client IP before auth (IPv6 grouped by `/64`) |
| `ADMIN_RATE_LIMIT_BURST` | `admin_rate_limit_burst` | `20` | Integer `> 0` |
| `METRICS_ENABLED` | `metrics_enabled` | `true` | Boolean; serves `GET /metrics` when `true`, returns `404` when `false` |
| `OTEL_ENABLED` | `otel_enabled` | `false` | Boolean; enables OpenTelemetry OTLP/HTTP trace export |
| `OTEL_SERVICE_NAME` | `otel_service_name` | `derp-admit` | Must not be empty |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `otel_exporter_otlp_endpoint` | *(empty)* | OTLP/HTTP collector host:port (for example `otel-collector:4318`) |
| `OTEL_EXPORTER_OTLP_INSECURE` | `otel_exporter_otlp_insecure` | `true` | Boolean; disables TLS for the OTLP exporter when `true` |
| `OTEL_TRACE_SAMPLE_RATIO` | `otel_trace_sample_ratio` | `1.0` | Float in `0..1` |

`sqlite://` is for tests and for running from source: the published container image is built with `CGO_ENABLED=0` and cannot open a sqlite database, so use PostgreSQL in containers.

`ENABLE_CASBIN` / `enable_casbin` has been removed for enforcement; policy is always enforced. Its only remaining use is deciding the one-time database upgrade mode on the first start of this version (when absent or not a boolean on an existing database with devices and no registration rules, startup refuses to run until a boolean value is provided). After the first start it has no effect, logs a warning if still present, and should be removed (see [Upgrading from the previous version](#upgrading-from-the-previous-version)).

### OpenTelemetry / SigNoz tracing

To send traces to an OTLP/HTTP collector such as SigNoz, set:

- `OTEL_ENABLED=true`
- `OTEL_EXPORTER_OTLP_ENDPOINT=<your-collector-host:4318>`

Logs remain structured zap JSON on stdout/stderr with `trace_id` and `span_id` fields when a span is active.

## Access model

Admission is role-based and per-relay, enforced by Casbin:

- **Users** own devices and are bound to zero or more roles (`g, user:<user_id>, role:<name>`).
- **Relays** are named entries in the `relays` registry.
- **Roles** are named entries in the `roles` registry, each granted `connect` on either a list of registered relays (`p, role:<name>, derp:<relay>, connect`) or all relays (`*`).
- **Grants are role-level and allow-only.** There are no direct user grants and no deny rules. A user is allowed on a relay only if at least one bound role covers that relay.
- **Role and relay names** must match `^[a-z0-9][a-z0-9-]{0,62}$`.
- **Built-ins:** relay `default` and role `standard` are seeded idempotently at every startup and cannot be deleted (`409`). `standard` is granted `default` only when `standard` is first created, so edits to `standard`'s grants survive restarts.
- **Wildcard `*` grants:** setting a role's `relays` to `["*"]` stores an `all_relays` flag on the role and expands it in memory over every relay currently in the registry. `*` cannot be mixed with relay names (`400`); duplicate `*` entries are normalized to `["*"]`.
- **User defaults:** `POST /admin/users` binds `["standard"]` when `roles` is omitted. Passing `"roles": []` creates the user with no role bindings. A user without any role binding is denied on every relay with `policy denied`.
- **Clean start on creation:** `POST /admin/roles` removes any leftover `casbin_rule` rows naming `role:<name>` and `POST /admin/relays` removes any leftover grants naming `derp:<name>` in the same transaction, reporting the count removed in the admin audit summary.

### Registration

`POST /register` accepts `{ "token": "...", "nodeKey": "nodekey:<64-hex>", "label": "..." }`.

- `nodeKey` must be a valid non-zero Tailscale node public key in canonical text form (`nodekey:` followed by 64 hex digits). Malformed keys return `400`.
- Registration writes no Casbin rules. Policy is evaluated on `user:<user_id>`, resolved from the `devices` table.
- Re-registering an existing active node key for the same user is idempotent (`200`, updating `label` if non-empty).
- Re-registering a **revoked** node key for the same user is refused with `403` without modifying the device; re-enabling goes through `POST /admin/devices/:id/enable`.
- Registering a node key already bound to another user returns `409` (whether active or revoked).
- Token `maxDevices` (`> 0`) caps the user's active devices on new registrations (`403` when reached).

### Verify flow

Before pointing a `derper` at `/verify/<relay>`, create the relay (`POST /admin/relays`) and grant a role on it (`POST /admin/roles` or `PUT /admin/roles/:name/relays`); otherwise every client is denied (`unknown relay`, then `policy denied`). After the upgrade, the only built-in grant is `standard` on `default`.

Point each `derper` instance at its own relay path:

- `--verify-client-url=http://verifier:8080/verify/<relay>`
- `--verify-client-url-fail-open=false`

Plain `POST /verify` (with no relay segment) evaluates relay `default`, so existing `derper` configurations keep working. `POST /verify/` (trailing slash, no redirect) and paths containing `/` (`POST /verify/a/b`, `POST /verify/a%2Fb`) are treated as malformed relay names and denied with `unknown relay`.

`/verify` and `/verify/:relay` accept a `tailcfg.DERPAdmitClientRequest` JSON body (`{"NodePublic":"nodekey:..."}`) and return HTTP `200` with `{"Allow":true}` or `{"Allow":false,"DenyReason":"..."}`.

Checks run in this order, returning the first failure's deny reason:

1. Global verify rate limit -> `rate limited` (not audited)
2. Parse request body and node key -> `invalid request`
3. Policy sync freshness check -> `internal error` (when stale)
4. Relay exists in the registry -> `unknown relay`
5. Device is registered -> `not registered`
6. Device is not revoked -> `revoked`
7. Owner user is not disabled -> `user disabled`
8. At least one of the owner's roles grants `connect` on `derp:<relay>` -> `policy denied`

Database or policy lookup errors also return `internal error`. When `VERIFY_CACHE_TTL > 0`, decisions (after check 4) are cached per `(relay, nodeKey)` and invalidated on lifecycle and policy changes.

**Trust statement and network exposure:** `/verify`, `/verify/:relay`, and `/metrics` require no credentials (`derper` sends no credentials or identifying headers). The relay name in the URL path is asserted by whoever calls `/verify` and is trusted as configured on `derper`; relay separation keeps a role from being admitted on another relay when each `derper` is configured with its own verify URL, but does not prevent an untrusted caller or misconfigured `derper` from naming a more permissive relay. Anyone who can reach the service port can learn whether a node key is registered, revoked, or belongs to a disabled user; can consume the single global verify rate limit, which with `--verify-client-url-fail-open=false` makes every `derper` reject every client; and each `/verify` call writes a verify audit row that nothing prunes. Restrict network access to the service to the `derper` relays and the admin callers.

## Admin API

The `/admin` routes are mounted only when `ADMIN_API_KEY` is set (`>= 16` characters). When `ADMIN_API_KEY` is unset, all `/admin` paths return `404`, even if active keys exist in the database, and there is no supported way to bind users to roles (users created by SQL have no role and are denied).

Every `/admin` request must carry `Authorization: Bearer <key>`. Keys are looked up in `admin_keys` by peppered hash (`hex(sha256(key + ":" + TOKEN_PEPPER))`). Missing, unknown, revoked, or expired keys receive `401`. Each authenticated request updates the key's `last_used_at` (best-effort).

Keys created via `POST /admin/keys` are generated server-side with 32 random bytes encoded as base64url with the prefix `dak_`. The plaintext is returned once at creation; only its hash is stored.

### Tiers

Tiers are ordered `viewer` < `operator` < `admin`, and each tier inherits all permissions of lower tiers. A key below a route's minimum tier receives `403`.

| Tier | Capabilities |
| --- | --- |
| `viewer` | Read users, enroll tokens, devices, roles, relays, and verify audit logs |
| `operator` | All `viewer` reads, plus create/disable/enable/delete users, assign any existing role to a user (including a role granted on all relays `*`), mint/revoke/delete enroll tokens, and revoke/enable/delete devices |
| `admin` | All `operator` actions, plus create/delete relays, define/edit/delete roles and their relay grants, create/list/revoke admin keys, and read admin audit logs |

### Route reference

| Method | Path | Min tier | Purpose |
| --- | --- | --- | --- |
| `POST` | `/admin/users` | `operator` | Create user `{ username, email?, roles? }` (`201`; `roles` defaults to `["standard"]`, `[]` binds none) |
| `GET` | `/admin/users` | `viewer` | List users with `roles` (paginated) |
| `PUT` | `/admin/users/:id/roles` | `operator` | Replace a user's roles `{ roles: [...] }` (`[]` clears all bindings) |
| `POST` | `/admin/users/:id/disable` | `operator` | Disable user (idempotent; drops cached verify decisions) |
| `POST` | `/admin/users/:id/enable` | `operator` | Re-enable user (idempotent) |
| `DELETE` | `/admin/users/:id` | `operator` | Delete user with their tokens, devices, role bindings, and legacy device rules |
| `POST` | `/admin/tokens` | `operator` | Mint enroll token `{ userId, expiresAt?, maxDevices?, note? }` (`201`; plaintext returned once; `maxDevices` defaults to `1`, `0` = unlimited) |
| `GET` | `/admin/tokens` | `viewer` | List enroll tokens (paginated; metadata only, never plaintext or hash) |
| `POST` | `/admin/tokens/:id/revoke` | `operator` | Revoke enroll token (idempotent) |
| `DELETE` | `/admin/tokens/:id` | `operator` | Delete enroll token (keeps devices already enrolled with it) |
| `GET` | `/admin/devices` | `viewer` | List devices (paginated; optional `?userId=<uuid>`) |
| `POST` | `/admin/devices/:id/revoke` | `operator` | Revoke/ban device (idempotent; drops cached verify decisions) |
| `POST` | `/admin/devices/:id/enable` | `operator` | Re-enable a revoked device (idempotent; only way to clear revocation) |
| `DELETE` | `/admin/devices/:id` | `operator` | Delete/forget device and its legacy device rule |
| `POST` | `/admin/relays` | `admin` | Register relay `{ name, description? }` (`201`; purges leftover rules for `derp:<name>`) |
| `GET` | `/admin/relays` | `viewer` | List relays (paginated) |
| `DELETE` | `/admin/relays/:name` | `admin` | Delete relay and all grants naming it (`409` for `default`) |
| `POST` | `/admin/roles` | `admin` | Create role `{ name, description?, relays? }` (`201`; omitted `relays` = no grants; purges leftover rules for `role:<name>`) |
| `GET` | `/admin/roles` | `viewer` | List roles with their `relays` grants (paginated) |
| `PUT` | `/admin/roles/:name/relays` | `admin` | Replace a role's grants `{ relays: [...] }` (registered relay names or `["*"]`) |
| `DELETE` | `/admin/roles/:name` | `admin` | Delete role, its grants, and all user bindings to it (`409` for `standard`; returns `removedBindings`) |
| `POST` | `/admin/keys` | `admin` | Create admin key `{ name, tier, expiresAt? }` (`201`; plaintext `dak_...` returned once) |
| `GET` | `/admin/keys` | `admin` | List admin keys (paginated; metadata only, never plaintext or hash) |
| `POST` | `/admin/keys/:id/revoke` | `admin` | Revoke admin key (idempotent; `409` for the last active `admin`-tier key) |
| `GET` | `/admin/audit/admin` | `admin` | Query admin audit log (paginated, newest first; see [Audit](#audit)) |
| `GET` | `/admin/audit/verify` | `viewer` | Query verify audit log (paginated, newest first; see [Audit](#audit)) |

### Bootstrap key, reserved names, and lockout guard

- **Reserved key names:** `bootstrap` and `system` (compared case-insensitively after trimming surrounding whitespace) cannot be created via `POST /admin/keys` (`409`). `system` is reserved for startup and upgrade audit rows.
- **Bootstrap reconciliation on startup** (when `ADMIN_API_KEY` is set):
  1. **Collision check (highest precedence):** If the hash of `ADMIN_API_KEY` matches a stored key other than `bootstrap`, startup does **not** fail. It leaves every key unchanged—including `bootstrap`, so if `bootstrap` is still active, the value it was last installed with keeps working—logs an error naming the colliding key's name and tier only, writes no audit row, and continues. Requests carrying `ADMIN_API_KEY` authenticate as that existing key (with its tier and active/inactive state).
  2. **Follow while active:** If `bootstrap` exists and is active, its stored hash is updated to match `ADMIN_API_KEY` (so rotating `ADMIN_API_KEY` invalidates the previous value).
  3. **Create or reactivate when no other active admin exists:** If `bootstrap` is absent, revoked, or expired and no other active `admin`-tier key exists, startup creates `bootstrap` (or reactivates it by clearing `revoked_at` and `expires_at`) with tier `admin` and the hash of `ADMIN_API_KEY`.
  4. **Ignored once replaced (dormant credential):** If `bootstrap` is inactive and another active `admin`-tier key exists, `bootstrap` is left untouched, a warning is logged, and `ADMIN_API_KEY` grants no access (though `ADMIN_API_KEY` must remain set to keep `/admin` mounted). After you revoke `bootstrap`, the configured `ADMIN_API_KEY` remains a dormant admin credential: any restart at a time when no active `admin`-tier key exists (for example, after named keys have expired) reactivates `bootstrap` with tier `admin` and no expiry, so treat `ADMIN_API_KEY` as a secret for as long as it is configured.
  - Creating, rotating, or reactivating `bootstrap` writes a `system` admin audit row (`bootstrap.create`, `bootstrap.rotate`, `bootstrap.reactivate`); no-op startups write no audit row.
- **Last-admin guard:** `POST /admin/keys/:id/revoke` returns `409` if the target is the only active `admin`-tier key. (If all `admin`-tier keys expire, restarting recovers access by reactivating `bootstrap`.)
- **Recommendation:** Set a high-entropy `ADMIN_API_KEY`, create named keys with the minimum tier each caller needs (including at least one named `admin` key), and revoke `bootstrap`.

### Revoke vs. delete

- **Revoke (`POST /admin/devices/:id/revoke`) is a ban:** the device row stays bound to its user and `nodeKey`, `/verify` denies it with `revoked`, and `/register` refuses that `nodeKey` with `403` until an operator calls `POST /admin/devices/:id/enable`.
- **Delete (`DELETE /admin/devices/:id`) is forgetting:** the device row and any legacy device rule are removed, verify audit rows are kept with `deviceId` set to `null`, `/verify` denies it with `not registered`, and the `nodeKey` can be enrolled again with a valid token.
- `DELETE /admin/users/:id` deletes the user, their tokens, their devices, their role bindings, and their legacy device rules in one transaction, while preserving verify audit rows with `deviceId` set to `null`.
- `DELETE /admin/tokens/:id` removes the token without affecting devices previously enrolled with it.

### Pagination (breaking change)

> **Breaking change:** Every list endpoint (`GET /admin/users`, `/tokens`, `/devices`, `/roles`, `/relays`, `/keys`, `/audit/admin`, `/audit/verify`) is now paginated and returns at most `50` items by default. Callers that previously expected a single unpaginated response must follow `nextCursor`.

- Query parameters: `limit` (default `50`, integer from `1` to `200`; out-of-range or non-integer returns `400`) and `cursor` (opaque token from the previous response's `nextCursor`).
- `nextCursor` is `null` on the last page.
- Ordering: entity lists are ordered by `created_at` ascending with a tie-break on `id` ascending (or `name` ascending for roles and relays). Audit lists are ordered newest first (`ts` descending, `id` descending).
- A cursor is bound to both the list endpoint and the exact filter values it was issued under. Sending a malformed cursor, a cursor from another list, or a cursor with different filter parameters returns `400`.

### Rate limiting

`/admin` enforces an independent per-client-IP token bucket (`ADMIN_RATE_LIMIT_RPS`, `ADMIN_RATE_LIMIT_BURST`) **before authentication**, returning `429` once exhausted (even for requests without a key). `/register` uses the same per-client-IP limiter (`REGISTER_RATE_LIMIT_RPS`, `REGISTER_RATE_LIMIT_BURST`).

- Client IP is the TCP peer address; forwarded headers (`X-Forwarded-For`, etc.) are not trusted.
- IPv4 clients are bucketed per address; IPv6 clients are grouped by `/64` prefix (IPv4-mapped IPv6 addresses are unmapped to IPv4).
- All callers behind a single reverse proxy share the proxy's peer address and therefore one bucket.

### Examples

The examples below assume the service is running on `http://127.0.0.1:8080` with `ADMIN_API_KEY` set to `change-me-admin-api-key`.

```bash
BASE="http://127.0.0.1:8080"
BOOTSTRAP_KEY="change-me-admin-api-key"
NODE_KEY="nodekey:0000000000000000000000000000000000000000000000000000000000000001"

# 1. Health and readiness
curl -s "$BASE/healthz"
# {"ok":true}
curl -s "$BASE/readyz"
# {"ok":true}

# 2. Create a named admin key and revoke bootstrap
ADMIN_KEY=$(curl -s -X POST "$BASE/admin/keys" \
  -H "Authorization: Bearer $BOOTSTRAP_KEY" \
  -H 'content-type: application/json' \
  -d '{"name":"ops-admin","tier":"admin"}' | jq -r .key)

BOOT_ID=$(curl -s "$BASE/admin/keys" \
  -H "Authorization: Bearer $ADMIN_KEY" | jq -r '.keys[] | select(.name=="bootstrap") | .id')

curl -s -X POST "$BASE/admin/keys/$BOOT_ID/revoke" \
  -H "Authorization: Bearer $ADMIN_KEY"
# {"ok":true}

# 3. Create a relay and a role granted on that relay
curl -s -X POST "$BASE/admin/relays" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d '{"name":"eu-1","description":"Frankfurt"}'

curl -s -X POST "$BASE/admin/roles" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d '{"name":"eu-only","description":"EU access","relays":["eu-1"]}'

# 4. Create a user (defaults to ["standard"]) and bind them to ["standard","eu-only"]
USER_ID=$(curl -s -X POST "$BASE/admin/users" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d '{"username":"alice"}' | jq -r .user.id)

curl -s -X PUT "$BASE/admin/users/$USER_ID/roles" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d '{"roles":["standard","eu-only"]}'

# 5. Mint an enroll token and register a device
ENROLL_TOKEN=$(curl -s -X POST "$BASE/admin/tokens" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d "{\"userId\":\"$USER_ID\",\"maxDevices\":5}" | jq -r .token)

curl -s -X POST "$BASE/register" \
  -H 'content-type: application/json' \
  -d "{\"token\":\"$ENROLL_TOKEN\",\"nodeKey\":\"$NODE_KEY\",\"label\":\"laptop\"}"
# {"ok":true}

# 6. Verify on default, named relay, and unknown relay
curl -s -X POST "$BASE/verify" \
  -H 'content-type: application/json' \
  -d "{\"NodePublic\":\"$NODE_KEY\"}"
# {"Allow":true}

curl -s -X POST "$BASE/verify/eu-1" \
  -H 'content-type: application/json' \
  -d "{\"NodePublic\":\"$NODE_KEY\"}"
# {"Allow":true}

curl -s -X POST "$BASE/verify/does-not-exist" \
  -H 'content-type: application/json' \
  -d "{\"NodePublic\":\"$NODE_KEY\"}"
# {"Allow":false,"DenyReason":"unknown relay"}

# 7. Revoke, re-enable, and delete the device
DEV_ID=$(curl -s "$BASE/admin/devices?userId=$USER_ID" \
  -H "Authorization: Bearer $ADMIN_KEY" | jq -r '.devices[0].id')

curl -s -X POST "$BASE/admin/devices/$DEV_ID/revoke" \
  -H "Authorization: Bearer $ADMIN_KEY"
# {"ok":true}

curl -s -X POST "$BASE/verify" \
  -H 'content-type: application/json' \
  -d "{\"NodePublic\":\"$NODE_KEY\"}"
# {"Allow":false,"DenyReason":"revoked"}

curl -s -X POST "$BASE/admin/devices/$DEV_ID/enable" \
  -H "Authorization: Bearer $ADMIN_KEY"
# {"ok":true}

curl -s -X DELETE "$BASE/admin/devices/$DEV_ID" \
  -H "Authorization: Bearer $ADMIN_KEY"
# {"ok":true}

# 8. Query admin and verify audit logs
curl -s "$BASE/admin/audit/admin?limit=5" \
  -H "Authorization: Bearer $ADMIN_KEY"

curl -s "$BASE/admin/audit/verify?relay=eu-1&limit=5" \
  -H "Authorization: Bearer $ADMIN_KEY"
```

## Audit

### Admin audit (`admin_audit_logs`)

- **Recorded:** Every authenticated mutating (`POST`, `PUT`, `DELETE`) request under `/admin`, regardless of outcome (`2xx`, `400`, `403`, `404`, `409`, `413`, `500`). For successful mutations, the audit row is committed in the same database transaction as the change (if the audit write fails, the change rolls back). Startup `bootstrap` key changes and one-time upgrade actions (`upgrade.run` and per-device `device.revoke`) are recorded with `actorName: "system"`, `actorKeyId: null`, `httpStatus: null`.
- **Not recorded:** Unauthenticated (`401`) requests, rate-limited (`429`) requests, and read-only (`GET`) requests. `401` and `429` requests are logged and counted in metrics only.
- **No secrets:** Plaintext admin keys, enroll tokens, `ADMIN_API_KEY`, and their hashes are never written to audit rows or logs (including GORM parameterized SQL logs).
- **Query:** `GET /admin/audit/admin` (tier `admin`), paginated newest first (`ts DESC, id DESC`). Optional filters combined with `AND`:
  - `actorKeyId` (UUID)
  - `action` (exact match, e.g. `device.revoke`, `role.grants.set`, `bootstrap.create`, `upgrade.run`)
  - `targetType` (exact match, e.g. `user`, `device`, `token`, `role`, `relay`, `admin_key`)
  - `targetId` (exact match)
  - `since` (RFC 3339 / RFC 3339 Nano timestamp, inclusive `ts >= since`)
  - `until` (RFC 3339 / RFC 3339 Nano timestamp, inclusive `ts <= until`)
  - Malformed UUID or timestamp filters return `400`.

### Verify audit (`audit_logs`)

- **Recorded:** Every `POST /verify` and `POST /verify/:relay` decision after the verify rate limit, including allows, denies, and bodies that are not valid JSON (`nodeKey: ""`, `reason: "invalid request"`).
- **Not recorded:** Requests rejected by the verify rate limit (`rate limited`).
- **Relay column:** Stores valid relay names as requested (including unknown relays), `"default"` for plain `/verify`, and `null` for malformed relay names or pre-upgrade rows (no backfill).
- **Preserved on delete:** Deleting a device or its owner user keeps existing verify audit rows and sets `deviceId` to `null`.
- **Query:** `GET /admin/audit/verify` (tier `viewer`), paginated newest first (`ts DESC, id DESC`). Optional filters combined with `AND`:
  - `nodeKey` (exact match)
  - `deviceId` (UUID)
  - `relay` (exact match; rows with `relay: null` do not match)
  - `allowed` (`true` or `false`)
  - `since` (RFC 3339 / RFC 3339 Nano, inclusive)
  - `until` (RFC 3339 / RFC 3339 Nano, inclusive)
  - Malformed UUID, boolean, or timestamp filters return `400`.

### Retention

There is no automatic retention or pruning for `admin_audit_logs` or `audit_logs`.

## Running several instances

- **Database as source of truth:** Every decision-affecting write (role, grant, binding, and relay changes; device revoke, enable, and delete; user disable, enable, and delete; new device registration) increments `policy_state.version` in the same transaction. The instance that handled the write applies it locally before responding.
- **Sync polling (`POLICY_SYNC_INTERVAL`):** Each instance polls `policy_state.version` every `POLICY_SYNC_INTERVAL` (default `2s`, minimum `100ms`). When the version advances, the instance reloads its policy snapshot and purges its local verify cache. Another healthy instance reflects a committed change within **two sync intervals** (4 seconds by default).
- **Non-blocking catch-up:** While an instance is reloading after observing a newer version, it continues serving `/verify` from its current snapshot and `/readyz` stays `200`.
- **Fail closed when stale:** If an instance goes longer than **three sync intervals** (measured by elapsed monotonic time, unaffected by wall-clock adjustments) without a successful version check—or if a policy reload fails—`/readyz` returns `503` and `/verify` denies every request (including requests that would have been answered from cache) with `DenyReason: "internal error"` (audited) until a check and any needed reload succeed.
- **Concurrent startup:** Startup migrations, built-in seeding, the one-time upgrade, and `bootstrap` key sync are serialized across replicas (PostgreSQL session advisory lock; lock file on SQLite). Startup has a 30-second limit covering waiting for the startup lock, migrations, and the upgrade; an instance that waits longer exits and should be restarted by its supervisor.
- **Per-instance rate limits:** Rate limiters are in-memory per process; with `N` instances, the effective rate limit is `N` times the configured values.

> **Breaking change — Admin API is the only supported way to provision policy:** Changing roles, grants, bindings, or relays by SQL is not supported. Such rows do not increment `policy_state.version`; they are picked up at the next policy reload on each instance—which happens at restart and whenever any admin change or new device registration moves the policy version—so they take effect at an unpredictable time. Without `ADMIN_API_KEY` there is no supported way to bind users to roles: users created by SQL have no role and are denied with `policy denied`.

## Metrics

When `METRICS_ENABLED=true` (the default), `GET /metrics` exposes Prometheus metrics on the main listener without authentication, using a dedicated registry (only `derp_admit_*` metrics are emitted). When `METRICS_ENABLED=false`, `GET /metrics` returns `404`.

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `derp_admit_verify_decisions_total` | Counter | `relay`, `allowed`, `reason` | Total verify decisions (`relay` is a registered relay name or `unknown`; `allowed` is `true`/`false`; `reason` is empty on allow or the deny reason) |
| `derp_admit_register_requests_total` | Counter | `status` | Total `/register` requests by HTTP status code |
| `derp_admit_admin_requests_total` | Counter | `tier`, `status_class` | Total `/admin` requests by actor tier (`viewer`, `operator`, `admin`, or `none` for `401`/`429`) and HTTP status class (`1xx`–`5xx`, `other`) |
| `derp_admit_rate_limited_total` | Counter | `endpoint` | Total rate-limit rejections by endpoint (`verify`, `register`, `admin`) |
| `derp_admit_verify_cache_lookups_total` | Counter | `result` | Total verify cache lookups (`hit` or `miss`; incremented when `VERIFY_CACHE_TTL > 0`) |
| `derp_admit_policy_version` | Gauge | *(none)* | Current `policy_state.version` published by this instance |
| `derp_admit_policy_sync_last_success_timestamp_seconds` | Gauge | *(none)* | Unix timestamp (seconds) of the last successful policy sync check |
| `derp_admit_policy_sync_failures_total` | Counter | *(none)* | Total failed policy sync checks or sync-triggered reloads |
| `derp_admit_policy_reloads_total` | Counter | `result` | Total policy snapshot reloads (`ok` or `error`) |

Metric labels never contain node keys, user IDs, device IDs, admin key IDs, or admin key names. Any relay name that is not in the registry or is malformed is labeled `unknown`.

## Upgrading from the previous version

Follow these steps in order:

1. **Take a database backup.** The one-time upgrade modifies role bindings and may revoke devices.
2. **Stop every old instance before starting the new version.** Mixed-version operation is not supported: old instances do not bump or check `policy_state.version`, and their admin writes bypass policy sync and admin audit.
3. **Ensure `ADMIN_API_KEY` is set at the first start.** Remediation requires the `/admin` API.
4. **Decide whether `ENABLE_CASBIN` / `enable_casbin` is needed for the first start:**
   - The one-time upgrade mode is decided once, at the first start of this version on a database: `ENABLE_CASBIN` (env or `.env`) or `enable_casbin` (YAML) present with a boolean value sets it (`false` = policy was disabled before, `true` = policy was enforced before). Environment variables and `.env` override YAML.
   - In `config/config.yaml`, YAML 1.1 boolean spellings count (`off`, `no`, `n` are false). In env and `.env`, only values accepted by Go's `strconv.ParseBool` count (`false`, `0`, `f`, `F`, `FALSE`, `False`); `off`, `no`, or an empty value are not booleans there.
   - When the setting is absent or not a boolean: a database with no devices, or with at least one registration rule (`g, device:..., user:...` in `casbin_rule`), is treated as **enforced** (the old default). A database that has devices but not a single registration rule looks like it ran with policy disabled; the service **refuses to start**, changes nothing, and tells the operator to start once with `ENABLE_CASBIN=false` (keep those devices allowed) or `ENABLE_CASBIN=true` (confirm they were denied).
   - The new `.env.example` and `config/config.yaml` do not contain `ENABLE_CASBIN` / `enable_casbin`, so an operator rebuilding configuration from them must add it back by hand for the first start if policy was disabled before.
   - **Warning:** Setting `false` on a deployment that did enforce policy binds every user to `standard` and revokes nothing, so devices that were denied become allowed. Use `false` **only** if the previous version really ran with policy disabled.
   - The setting is read only for this one decision. After the first successful start it has no effect and should be removed.
5. **Start the new version (start one instance first on a large database).** Startup has a 30-second limit covering waiting for the startup lock, migrations, and the upgrade; an instance that waits longer exits and should be restarted by its supervisor.
   - On first start against an existing database, startup runs schema migrations (creating `roles`, `relays`, `policy_state`, `admin_keys`, `admin_audit_logs`, and adding nullable `audit_logs.relay`), seeds `default` and `standard`, runs the one-time upgrade in a single transaction (recording a durable marker in `policy_state.upgraded_at` so it never runs again), and creates the `bootstrap` admin key from `ADMIN_API_KEY`.
   - **What the one-time upgrade does** (it deletes no `casbin_rule` row):
     - Imports valid role and relay names from existing `g, user:<uuid>, role:<name>` and `p, role:<name>, derp:<relay>, connect` rules into the `roles` and `relays` registries.
     - **Disabled mode (`false`):** Every user not already covered on `default` is bound to `standard`; nothing is revoked.
     - **Enforced mode (`true`):** A user who is not covered on `default` and has no devices is bound to `standard`; a user who is not covered and has devices is left as is and reported; every device without its registration rule (`g, device:<node_key>, user:<owner_id>`) is revoked, whoever owns it.
     - Rules outside the managed shapes (direct `p` rules on `user:` or `device:`, role-to-role `g` rules, pre-existing `derp:*` rules, legacy `g, device:*, user:*` rules) remain in `casbin_rule`, grant nothing under the new model, and are counted as unmanaged rules.
   - **What it records:**
     - One info log line and one `system` admin audit row with action `upgrade.run` holding the mode and the counts (users bound, users left without access, devices revoked, unmanaged rules, and roles and relays imported).
     - One `system` admin audit row (`device.revoke`) per revoked device.
     - One warning log line listing the IDs of users left without access and devices revoked. This warning is logged once by the instance that ran the upgrade and is hidden at `LOG_LEVEL=error`, so read the admin audit (`GET /admin/audit/admin`) instead of relying on logs.
6. **Verify and remediate:**
   - Query `GET /admin/audit/admin` (using `ADMIN_API_KEY`) to inspect the `upgrade.run` row and any `system` `device.revoke` rows rather than relying on the startup warning log.
   - Binding an uncovered user later with `PUT /admin/users/:id/roles` (for example `{"roles":["standard"]}`) admits only devices that were properly registered; re-enable any revoked device individually with `POST /admin/devices/:id/enable`.
   - Remove `ENABLE_CASBIN` / `enable_casbin` after the first successful start.
7. **Review breaking changes for callers:**
   - `/register` now returns `403` for a revoked device instead of reactivating it.
   - `ADMIN_API_KEY` becomes the stored `bootstrap` key (`tier: admin`), keeping existing callers working; create named keys and revoke `bootstrap` when ready.
   - List endpoints under `/admin` now paginate (default `limit=50`).
   - Changing policy by SQL is not supported, and without `ADMIN_API_KEY` there is no supported way to bind users to roles (users created by SQL have no role and are denied).

### Rollback

- Stop every new instance before starting the previous version. When in doubt, restore the database backup from step 1.
- The previous version enforces `device:<node_key>` rules. Because the upgrade deletes none of them, devices registered before the upgrade under enforced policy are still allowed after a rollback, provided their owner still has `g, user:<id>, role:standard`: a user whose roles were replaced through `PUT /admin/users/:id/roles` without `standard` is denied on rollback.
- A deployment that ran with `ENABLE_CASBIN=false` has no device rules: after a rollback it **must** run the previous version with `ENABLE_CASBIN=false` again, or every device is denied.
- Devices registered under the new version have no device rule and are denied by the previous version until they register again.
- Rollback can also widen access compared with the new version: the previous version re-adds the `standard` grant on `default` at every start, binds `standard` at every registration, lets `/register` reactivate a revoked device, evaluates only `default`, and knows nothing of relays, tiers, or named keys (it accepts `ADMIN_API_KEY` directly).
- The new tables and `audit_logs.relay` column can stay; the previous version ignores them.

## Development

`go.mod` pins `go 1.24.0`.

Run the SQLite test suite on the local Go toolchain:

```bash
go build ./... && go vet ./... && go test -race -count=1 ./...
```

Run with the pinned Go 1.24.0 toolchain:

```bash
GOTOOLCHAIN=go1.24.0 go build ./... && GOTOOLCHAIN=go1.24.0 go vet ./... && GOTOOLCHAIN=go1.24.0 go test -race -count=1 ./...
```

Run the PostgreSQL-gated tests by pointing `TEST_POSTGRES_URL` at an empty PostgreSQL database whose role can create databases (`CREATEDB`):

```bash
TEST_POSTGRES_URL="postgres://verifier:verifier@127.0.0.1:5432/verifier?sslmode=disable" \
  go test -race -count=1 ./...
```

### Docker Build (Cross-Platform)

Single platform (for local load, e.g. Linux amd64):

```bash
docker buildx build \
  --platform linux/amd64 \
  -f builder/derp_admit/Dockerfile \
  -t derp-admit:linux-amd64 \
  --load \
  .
```

Multi-platform (for registry push):

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f builder/derp_admit/Dockerfile \
  -t <your-registry>/derp-admit:<tag> \
  --push \
  .
```

## Docker Compose stack and manual smoke test

`builder/derp_admit/docker-compose.yml` runs three services: `postgres`, `verifier` (built from `builder/derp_admit/Dockerfile`) and `derper`. There is no usable published derper image (`tailscale/derper` and `ghcr.io/tailscale/derper` refuse anonymous pulls), so compose builds derper from `builder/derp_admit/derper.Dockerfile` at the tailscale version pinned in `go.mod` (`v1.84.3`).

derper is started with `--verify-client-url=http://verifier:8080/verify/default` and `--verify-client-url-fail-open=false`, so it rejects every client when the verifier cannot be reached.

Start the stack:

```bash
cp .env.example .env
# Fill in TOKEN_PEPPER and ADMIN_API_KEY, and point the database at the compose postgres:
# DATABASE_URL=postgres://verifier:verifier@postgres:5432/verifier?sslmode=disable
docker compose -f builder/derp_admit/docker-compose.yml up -d --build
```

Host ports: `5432` (postgres), `8080` (verifier), `3340/tcp` (derper HTTP) and `3478/udp` (STUN). Note that `builder/derp_admit/docker-compose.yml` publishes port `8080` (and PostgreSQL's `5432`) on all host interfaces and is meant for local use only.

### TLS choice

For the smoke test, derper serves plain HTTP on `:3340` with no certificate. derper only serves TLS when its listen address is `:443` or `--certmode=manual` is set (`serveTLS := tsweb.IsProd443(*addr) || *certMode == "manual"` in `cmd/derper/derper.go`); with `-a=:3340` neither holds, so no Let's Encrypt or certificate files are needed. Its node key is kept in the `derper-data` volume (`-c=/var/lib/derper/derper.key`). For real clients, serve derper over TLS: run it on `:443` with a public hostname, or use `--certmode=manual` with your own certificate.

### Checking each service

```bash
dc() { docker compose -f builder/derp_admit/docker-compose.yml "$@"; }
dc ps                                       # postgres should be "healthy"; verifier and derper "Up"
curl -s http://127.0.0.1:8080/healthz        # {"ok":true}
curl -s http://127.0.0.1:8080/readyz         # {"ok":true}
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3340/derp/probe   # 200
dc logs derper                              # "STUN server listening on [::]:3478", "derper: serving on :3340"
dc logs verifier                            # "starting verifier server"
dc down -v                                  # stop and delete the volumes
```

There is no automated end-to-end test with a real Tailscale client. Checking that derper actually admits or rejects a client through the verifier is a manual step: a Tailscale client has to use a DERP map that points at this derper.
