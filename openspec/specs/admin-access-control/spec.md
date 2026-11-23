# admin-access-control Specification

## Purpose
Define how the `/admin` API is enabled and who may use it: admin keys stored in the database with a tier, the permissions of each tier, the bootstrap key taken from `ADMIN_API_KEY`, the guard against locking out every admin, and the per-client-IP rate limit that runs before authentication.

## Requirements

### Requirement: Admin API is enabled by ADMIN_API_KEY
The system MUST mount the `/admin` routes only when `ADMIN_API_KEY` is set, and MUST fail configuration loading when it is set but shorter than 16 characters. When it is not set, admin keys stored in the database MUST NOT give access to anything.

#### Scenario: Admin key is not configured
- **WHEN** the service starts without `ADMIN_API_KEY` and a request is sent to any `/admin` path
- **THEN** the service returns HTTP `404`, even if the request carries a key that is stored and active in the database

#### Scenario: Admin key is too short
- **WHEN** configuration is loaded with an `ADMIN_API_KEY` shorter than 16 characters
- **THEN** configuration loading fails with an error

### Requirement: Admin requests authenticate with a stored admin key
Every `/admin` request MUST carry `Authorization: Bearer <key>`, where the key belongs to a stored admin key that is active. A key is active when `revoked_at` is null and `expires_at` is null or later than the current time. The service MUST look keys up by hash only.

#### Scenario: Missing or unknown key
- **WHEN** a request to an `/admin` route has no `Authorization` header, or a bearer key whose hash matches no stored admin key
- **THEN** the service returns HTTP `401` and performs no admin operation

#### Scenario: Revoked or expired key
- **WHEN** a request to an `/admin` route carries a stored key whose `revoked_at` is set or whose `expires_at` has passed
- **THEN** the service returns HTTP `401` and performs no admin operation

#### Scenario: Active key is accepted
- **WHEN** a request to an `/admin` route carries an active stored key whose tier permits the route
- **THEN** the request is processed and the key's `last_used_at` is set to the current time

### Requirement: Admin keys are generated server-side and stored only as a hash
The system MUST generate admin keys from 32 random bytes, encoded as base64url and prefixed with `dak_`. It MUST return the plaintext only in the response that creates the key. It MUST store only `hex(sha256(key + ":" + TOKEN_PEPPER))`, and MUST NOT write the plaintext to logs, audit rows or any database field. Reserved names are defined in "Admin key names bootstrap and system are reserved".

#### Scenario: Key is created
- **WHEN** an `admin`-tier caller calls `POST /admin/keys` with a unique non-blank `name`, a `tier` of `viewer`, `operator` or `admin`, and an optional `expiresAt`
- **THEN** the service returns HTTP `201` with the plaintext key, which starts with `dak_`, and the key's metadata; only the hash is stored

#### Scenario: Key name is taken
- **WHEN** `POST /admin/keys` is called with a `name` that another admin key already has
- **THEN** the service returns HTTP `409` and creates no key

#### Scenario: Key name bootstrap is reserved
- **WHEN** `POST /admin/keys` is called with `name` set to `bootstrap`
- **THEN** the service returns HTTP `409` and creates no key

#### Scenario: Tier is not valid
- **WHEN** `POST /admin/keys` is called with a missing `tier` or a value other than `viewer`, `operator` or `admin`
- **THEN** the service returns HTTP `400` and creates no key

#### Scenario: Keys are listed
- **WHEN** an `admin`-tier caller calls `GET /admin/keys`
- **THEN** the service returns HTTP `200` with a page of keys, paginated as defined in `admin-lifecycle-api`, each with id, name, tier, `createdAt`, `expiresAt`, `revokedAt` and `lastUsedAt`, and neither the plaintext nor the hash

#### Scenario: Key is revoked
- **WHEN** an `admin`-tier caller calls `POST /admin/keys/:id/revoke` for an existing key
- **THEN** the service sets `revoked_at` and returns HTTP `200`, and later requests with that key return HTTP `401`; a key that is already revoked keeps its original `revoked_at`

#### Scenario: Key id is unknown or malformed
- **WHEN** `POST /admin/keys/:id/revoke` is called with an id that is not a UUID, or a UUID that matches no key
- **THEN** the service returns HTTP `400` for a malformed id and HTTP `404` for an unknown one

### Requirement: Admin key names bootstrap and system are reserved
The names `bootstrap` and `system` MUST be reserved for admin keys, compared case-insensitively after trimming surrounding whitespace. `POST /admin/keys` with either name MUST return HTTP `409` and create no key. `system` is the actor name of startup audit rows.

#### Scenario: Key name system is reserved
- **WHEN** `POST /admin/keys` is called with `name` set to `system`
- **THEN** the service returns HTTP `409` and creates no key

#### Scenario: Reserved name in another case or with surrounding whitespace
- **WHEN** `POST /admin/keys` is called with `name` set to `Bootstrap`, `SYSTEM` or ` system `
- **THEN** the service returns HTTP `409` and creates no key

### Requirement: Admin routes require a minimum tier
Tiers are ordered `viewer` < `operator` < `admin`, and each tier has every permission of the tiers below it. Each `/admin` route MUST require a minimum tier. A request whose key is authenticated but below the route's minimum tier MUST receive HTTP `403`, and the operation MUST NOT run.

#### Scenario: Tier is too low
- **WHEN** a `viewer` key calls `POST /admin/users`
- **THEN** the service returns HTTP `403` and creates no user

#### Scenario: Higher tier inherits lower permissions
- **WHEN** an `admin` key calls `GET /admin/users`
- **THEN** the request is processed

### Requirement: Viewer tier reads lifecycle and access data
The `viewer` tier MUST be sufficient for `GET /admin/users`, `GET /admin/tokens`, `GET /admin/devices`, `GET /admin/roles`, `GET /admin/relays` and `GET /admin/audit/verify`, and for no other route.

#### Scenario: Viewer reads devices and verify audit
- **WHEN** a `viewer` key calls `GET /admin/devices` or `GET /admin/audit/verify`
- **THEN** the request is processed

#### Scenario: Viewer cannot read admin audit or keys
- **WHEN** a `viewer` key calls `GET /admin/audit/admin` or `GET /admin/keys`
- **THEN** the service returns HTTP `403`

### Requirement: Operator tier manages users, tokens and devices
The `operator` tier MUST be the minimum for creating, disabling, enabling and deleting users, for `PUT /admin/users/:id/roles`, for minting, revoking and deleting enroll tokens, and for revoking, enabling and deleting devices.

#### Scenario: Operator sets a user's roles
- **WHEN** an `operator` key calls `PUT /admin/users/:id/roles` with existing role names
- **THEN** the request is processed

#### Scenario: Viewer cannot revoke a device
- **WHEN** a `viewer` key calls `POST /admin/devices/:id/revoke`
- **THEN** the service returns HTTP `403` and the device is unchanged

#### Scenario: Operator cannot change roles or relays
- **WHEN** an `operator` key calls `POST /admin/roles`, `PUT /admin/roles/:name/relays`, `DELETE /admin/roles/:name`, `POST /admin/relays` or `DELETE /admin/relays/:name`
- **THEN** the service returns HTTP `403` and nothing changes

### Requirement: Admin tier manages roles, relays, keys and the admin audit
The `admin` tier MUST be the minimum for creating, editing and deleting roles and their grants, for creating and deleting relays, for `POST /admin/keys`, `GET /admin/keys` and `POST /admin/keys/:id/revoke`, and for `GET /admin/audit/admin`.

#### Scenario: Operator cannot manage admin keys
- **WHEN** an `operator` key calls `POST /admin/keys`
- **THEN** the service returns HTTP `403` and creates no key

#### Scenario: Admin reads the admin audit
- **WHEN** an `admin` key calls `GET /admin/audit/admin`
- **THEN** the request is processed

### Requirement: Bootstrap key follows ADMIN_API_KEY while it is active
At startup, when the admin key named `bootstrap` exists and is active, the system MUST set its hash from the current `ADMIN_API_KEY`, so that the previous value stops working.

#### Scenario: ADMIN_API_KEY is rotated
- **WHEN** the service restarts with a new `ADMIN_API_KEY` while the `bootstrap` key is active
- **THEN** requests with the new value authenticate with tier `admin`, and requests with the old value return HTTP `401`

### Requirement: Bootstrap key is restored when no active admin key exists
At startup, when the `bootstrap` key is not active and no other active key of tier `admin` exists, the system MUST create the `bootstrap` key with tier `admin` and the hash of `ADMIN_API_KEY`. If a `bootstrap` row already exists, it MUST be reactivated instead, by clearing `revoked_at` and `expires_at` and setting its hash.

#### Scenario: First start
- **WHEN** the service starts with `ADMIN_API_KEY` set and the database has no admin keys
- **THEN** a key named `bootstrap` with tier `admin` exists, and requests that carry `ADMIN_API_KEY` as bearer key are processed

#### Scenario: Upgrade from the static key
- **WHEN** a deployment that used `ADMIN_API_KEY` as its static admin key starts on this version for the first time
- **THEN** existing callers that send that value keep working with tier `admin`

#### Scenario: Recovery after every admin key expired
- **WHEN** the service restarts while every key of tier `admin` is expired or revoked
- **THEN** the `bootstrap` key is reactivated with the current `ADMIN_API_KEY` and has tier `admin`

### Requirement: ADMIN_API_KEY grants nothing once another admin key has taken over
At startup, when the `bootstrap` key is not active and another active key of tier `admin` exists, the system MUST leave the `bootstrap` key unchanged and MUST log that `ADMIN_API_KEY` grants no access.

#### Scenario: Bootstrap key was revoked deliberately
- **WHEN** the `bootstrap` key is revoked, another active `admin`-tier key exists, and the service restarts
- **THEN** the `bootstrap` key stays revoked, requests that carry `ADMIN_API_KEY` return HTTP `401`, and a log entry states that `ADMIN_API_KEY` grants no access

### Requirement: Startup never fails because ADMIN_API_KEY equals another stored key
At startup, when the hash of `ADMIN_API_KEY` belongs to a stored admin key other than `bootstrap`, the system MUST leave every admin key unchanged, MUST log an error that names that key by name and tier only, MUST NOT write an admin audit row, and MUST continue starting. This takes precedence over the three `bootstrap` cases above. The configured value then authenticates exactly as the key it already is.

#### Scenario: ADMIN_API_KEY is set to a named key while bootstrap is active
- **WHEN** the `bootstrap` key is active and the service restarts with `ADMIN_API_KEY` set to the plaintext of a stored `operator` key named `ci`
- **THEN** startup succeeds, the hash of `bootstrap` and of `ci` are unchanged, an error log names `ci` and tier `operator` and contains neither the key nor its hash, no admin audit row is written, and requests that carry `ADMIN_API_KEY` authenticate as `ci` with tier `operator`

#### Scenario: ADMIN_API_KEY is set to a named key and no bootstrap key is active
- **WHEN** no active key of tier `admin` exists and the service starts with `ADMIN_API_KEY` set to the plaintext of a stored key other than `bootstrap`
- **THEN** startup succeeds, no `bootstrap` key is created or reactivated, every admin key is unchanged, and the error log names that key by name and tier

### Requirement: The last active admin key cannot be revoked
The system MUST refuse to revoke a key of tier `admin` when it is the only active key of tier `admin`.

#### Scenario: Revoking the last admin key
- **WHEN** `POST /admin/keys/:id/revoke` targets the only active key of tier `admin`
- **THEN** the service returns HTTP `409` and the key stays active

#### Scenario: Revoking one of several admin keys
- **WHEN** `POST /admin/keys/:id/revoke` targets a key of tier `admin` while another active key of tier `admin` exists
- **THEN** the key is revoked and the service returns HTTP `200`

### Requirement: Admin API is rate limited per client IP before authentication
The system MUST apply an independent token bucket, configured by `ADMIN_RATE_LIMIT_RPS` and `ADMIN_RATE_LIMIT_BURST`, to each client IP calling `/admin`, before the key is checked. The client IP MUST be the TCP peer address; forwarded-for headers MUST NOT be trusted. IPv6 peers MUST be grouped by their /64 prefix, so that all addresses in one /64 share one bucket.

#### Scenario: One client exceeds its budget
- **WHEN** a client IP sends `/admin` requests faster than the configured rate and burst allow
- **THEN** that client's excess requests receive HTTP `429` whether or not they carry a valid key

#### Scenario: Other clients are unaffected
- **WHEN** one client IP has exhausted its admin budget
- **THEN** requests from a different client IP are still evaluated against their own budget

#### Scenario: Callers behind one reverse proxy
- **WHEN** several admin callers reach the service through the same reverse proxy
- **THEN** they share the proxy's address and therefore one bucket

#### Scenario: IPv6 addresses in one /64 share a bucket
- **WHEN** `/admin` requests arrive from different IPv6 addresses inside the same /64 prefix
- **THEN** they are counted against one bucket, and an address in a different /64 has its own bucket
