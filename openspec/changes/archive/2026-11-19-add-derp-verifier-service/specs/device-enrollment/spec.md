## ADDED Requirements

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

### Requirement: Register endpoint enforces device ownership and idempotency
The system MUST enforce unique `node_key` ownership and MUST prevent reassignment across users while supporting idempotent retries for the same user.

#### Scenario: Existing node key on another user is denied
- **WHEN** `POST /register` is called for a `node_key` already bound to a different `user_id`
- **THEN** the service returns HTTP `409` and does not modify the existing binding

#### Scenario: Existing active node key on same user is idempotent
- **WHEN** `POST /register` is called for a `node_key` already bound to the same user with `revoked_at` null
- **THEN** the service returns HTTP `200` without creating a duplicate device row

#### Scenario: Existing revoked node key on same user is reactivated
- **WHEN** `POST /register` is called for a `node_key` already bound to the same user with `revoked_at` not null
- **THEN** the service clears `revoked_at`, updates mutable fields such as `label`, and returns HTTP `200`

#### Scenario: New node key is created
- **WHEN** `POST /register` is called for a `node_key` with no existing device record
- **THEN** the service creates a new device row bound to the token's user and returns HTTP `200`

### Requirement: Register endpoint enforces token max device limits
The system MUST enforce `enroll_tokens.max_devices` for active devices of the token's user when `max_devices > 0`.

#### Scenario: Max devices reached
- **WHEN** `POST /register` is called with a token where `max_devices > 0` and active device count for the user is greater than or equal to `max_devices`
- **THEN** the service returns HTTP `403` and does not create a new active device binding

### Requirement: Register endpoint protects token secret material
The system MUST hash tokens as `hex(sha256(token + ":" + TOKEN_PEPPER))` for lookup and MUST NOT write token plaintext to logs or database fields.

#### Scenario: Token handling in request processing
- **WHEN** `POST /register` processes a valid or invalid token
- **THEN** only token hash is used for persistence/query and logs exclude token plaintext values
