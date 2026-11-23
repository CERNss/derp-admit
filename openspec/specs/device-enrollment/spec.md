# device-enrollment Specification

## Purpose
Define the `POST /register` endpoint that binds a node key to a user with an enroll token: token and user validation, device ownership and idempotency, per-token device limits, and protection of token secrets.

## Requirements

### Requirement: Register endpoint validates enroll token and user state
The system MUST provide `POST /register` that accepts `token`, `nodeKey`, and optional `label`, and MUST validate token hash lookup, token lifecycle, and user active state before any device binding.

#### Scenario: Unknown token is rejected
- **WHEN** `POST /register` is called with a token whose hash does not match any `enroll_tokens.token_hash`
- **THEN** the service returns HTTP `401` and does not create or update any device record

#### Scenario: Revoked or expired token is rejected
- **WHEN** `POST /register` is called with a token where `revoked_at` is not null or `expires_at` is earlier than current time
- **THEN** the service returns HTTP `403` and does not create or update any device record

#### Scenario: Disabled user is rejected
- **WHEN** `POST /register` resolves a token to a user with `disabled_at` not null
- **THEN** the service returns HTTP `403` and does not create or update any device record

### Requirement: Register endpoint protects token secret material
The system MUST hash tokens as `hex(sha256(token + ":" + TOKEN_PEPPER))` for lookup and MUST NOT write token plaintext to logs or database fields.

#### Scenario: Token handling in request processing
- **WHEN** `POST /register` processes a valid or invalid token
- **THEN** only token hash is used for persistence/query and logs exclude token plaintext values

### Requirement: Register endpoint is rate limited per client IP
The system MUST apply an independent rate limit, configured by `REGISTER_RATE_LIMIT_RPS` and `REGISTER_RATE_LIMIT_BURST`, to each client IP calling `POST /register`, and MUST take the client IP from the TCP peer address without trusting forwarded-for headers. IPv6 peers MUST be grouped by their /64 prefix, so that all addresses in one /64 share one bucket.

#### Scenario: One client exceeds its budget
- **WHEN** a client IP sends `POST /register` requests faster than the configured rate and burst allow
- **THEN** that client's excess requests receive HTTP `429` and no device record is created or updated for them

#### Scenario: Other clients are unaffected
- **WHEN** one client IP has exhausted its register budget
- **THEN** requests from a different client IP are still evaluated against their own budget

#### Scenario: IPv6 addresses in one /64 share a bucket
- **WHEN** `POST /register` requests arrive from different IPv6 addresses inside the same /64 prefix
- **THEN** they are counted against one bucket, and an address in a different /64 has its own bucket

### Requirement: Register endpoint rejects oversized and malformed bodies
The system MUST limit request bodies to 1 MiB and MUST reject bodies that are too large or are not valid JSON before any token lookup.

#### Scenario: Body exceeds the size limit
- **WHEN** `POST /register` receives a body larger than 1 MiB
- **THEN** the service returns HTTP `413`

#### Scenario: Body is not valid JSON
- **WHEN** `POST /register` receives a body that cannot be parsed as JSON
- **THEN** the service returns HTTP `400`

### Requirement: Register endpoint canonicalizes node keys
The system MUST parse `nodeKey` as a Tailscale node public key and MUST store it in the canonical form that `/verify` derives from derper requests.

#### Scenario: Node key is not a valid node public key
- **WHEN** `POST /register` is called with a `nodeKey` that cannot be parsed as a Tailscale node public key, or that is the zero key
- **THEN** the service returns HTTP `400` and does not create or update any device record

#### Scenario: Valid node key is stored canonically
- **WHEN** `POST /register` succeeds for a node key
- **THEN** the device's stored `node_key` equals the canonical string for that key, so a later `/verify` for the same key matches it

### Requirement: Register endpoint is safe under concurrent requests
The system MUST perform token re-validation, user re-validation, the device limit check and the device write for a registration inside one database transaction that serializes concurrent registrations for the same user.

#### Scenario: Concurrent registrations do not exceed the device limit
- **WHEN** several `POST /register` requests for different node keys arrive at the same time with a token whose `max_devices` is `1`
- **THEN** exactly one request returns HTTP `200`, the others return HTTP `403`, and exactly one device row exists

#### Scenario: Token is revoked or user is disabled during registration
- **WHEN** a token is revoked, expires, or its user is disabled after the request's first token check but before the device is written
- **THEN** the service returns HTTP `403` and does not create or update any device record

#### Scenario: Two requests register the same new node key
- **WHEN** two `POST /register` requests for the same unregistered node key race and one loses on the unique `node_key` constraint
- **THEN** the losing request returns HTTP `409` rather than HTTP `500`

### Requirement: Register endpoint enforces device ownership and refuses revoked node keys
The system MUST enforce unique `node_key` ownership, MUST prevent reassignment across users, MUST support idempotent retries for the same user, and MUST NOT reactivate a revoked device.

#### Scenario: Existing node key on another user is denied
- **WHEN** `POST /register` is called for a `node_key` already bound to a different `user_id`, whether or not that device is revoked
- **THEN** the service returns HTTP `409` and does not modify the existing binding

#### Scenario: Existing active node key on same user is idempotent
- **WHEN** `POST /register` is called for a `node_key` already bound to the same user with `revoked_at` null
- **THEN** the service returns HTTP `200` without creating a duplicate device row

#### Scenario: Existing revoked node key on same user is refused
- **WHEN** `POST /register` is called for a `node_key` already bound to the same user with `revoked_at` not null
- **THEN** the service returns HTTP `403` and changes nothing: `revoked_at`, `label` and every other field keep their values

#### Scenario: New node key is created
- **WHEN** `POST /register` is called for a `node_key` with no existing device record
- **THEN** the service creates a new device row bound to the token's user and returns HTTP `200`

### Requirement: Register endpoint enforces token device limits on new devices
The system MUST enforce `enroll_tokens.max_devices` for active devices of the token's user when `max_devices > 0`.

#### Scenario: Max devices reached
- **WHEN** `POST /register` is called with a token where `max_devices > 0` and active device count for the user is greater than or equal to `max_devices`
- **THEN** the service returns HTTP `403` and does not create a new active device binding

### Requirement: Revoke bans a node key and delete forgets it
A revoked device MUST keep its node key bound and refused at `POST /register` until the admin API re-enables or deletes it. A deleted device MUST leave no binding, so its node key can be enrolled again with a valid token.

#### Scenario: Revoked device tries to re-enrol
- **WHEN** an admin revokes a device and its owner calls `POST /register` for the same node key with a valid token
- **THEN** the service returns HTTP `403` and the device stays revoked

#### Scenario: Deleted device enrols again
- **WHEN** an admin deletes a device and `POST /register` is then called for the same node key with a valid token
- **THEN** the service creates a new device row for that node key and returns HTTP `200`
