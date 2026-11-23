## ADDED Requirements

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

## MODIFIED Requirements

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

## REMOVED Requirements

### Requirement: Register endpoint enforces device ownership and idempotency
**Reason**: Its scenario "Existing revoked node key on same user is reactivated" becomes false: `/register` now refuses a revoked node key (owner answer 4, decision E3). OpenSpec cannot drop a scenario under MODIFIED, so the requirement is replaced by "Register endpoint enforces device ownership and refuses revoked node keys", which keeps the other three scenarios word for word.
**Migration**: Clients that re-registered a revoked device to reactivate it now get HTTP `403`. An admin re-enables the device with `POST /admin/devices/:id/enable`, or deletes it so that it can enrol again.

### Requirement: Register endpoint enforces token max device limits
**Reason**: Its scenario "Reactivation counts against the limit", added by `harden-registration-and-admin-api`, becomes false because `/register` no longer reactivates devices (decision E3). Replaced by "Register endpoint enforces token device limits on new devices", which keeps the "Max devices reached" scenario word for word.
**Migration**: None. The limit still applies to every new device.
