## ADDED Requirements

### Requirement: Register endpoint is rate limited per client IP
The system MUST apply an independent rate limit, configured by `REGISTER_RATE_LIMIT_RPS` and `REGISTER_RATE_LIMIT_BURST`, to each client IP calling `POST /register`, and MUST take the client IP from the TCP peer address without trusting forwarded-for headers.

#### Scenario: One client exceeds its budget
- **WHEN** a client IP sends `POST /register` requests faster than the configured rate and burst allow
- **THEN** that client's excess requests receive HTTP `429` and no device record is created or updated for them

#### Scenario: Other clients are unaffected
- **WHEN** one client IP has exhausted its register budget
- **THEN** requests from a different client IP are still evaluated against their own budget

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

## MODIFIED Requirements

### Requirement: Register endpoint enforces token max device limits
The system MUST enforce `enroll_tokens.max_devices` for active devices of the token's user when `max_devices > 0`, both when creating a device and when reactivating a revoked one.

#### Scenario: Max devices reached
- **WHEN** `POST /register` is called with a token where `max_devices > 0` and active device count for the user is greater than or equal to `max_devices`
- **THEN** the service returns HTTP `403` and does not create a new active device binding

#### Scenario: Reactivation counts against the limit
- **WHEN** `POST /register` is called for a revoked node key of the same user with a token where `max_devices > 0` and active device count for the user is greater than or equal to `max_devices`
- **THEN** the service returns HTTP `403` and the device stays revoked
