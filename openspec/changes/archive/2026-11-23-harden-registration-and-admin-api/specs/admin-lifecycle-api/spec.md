## ADDED Requirements

### Requirement: Admin API is mounted only when an admin key is configured
The system MUST mount the `/admin` routes only when `ADMIN_API_KEY` is set, and MUST fail configuration loading when the key is set but shorter than 16 characters.

#### Scenario: Admin key is not configured
- **WHEN** the service starts without `ADMIN_API_KEY` and a request is sent to any `/admin` path
- **THEN** the service returns HTTP `404`, even if the request carries a bearer key

#### Scenario: Admin key is too short
- **WHEN** configuration is loaded with an `ADMIN_API_KEY` shorter than 16 characters
- **THEN** configuration loading fails with an error

### Requirement: Admin API requires bearer authentication
The system MUST require `Authorization: Bearer <ADMIN_API_KEY>` on every `/admin` route and MUST compare the presented key in constant time.

#### Scenario: Missing or wrong key is rejected
- **WHEN** a request to an `/admin` route has no `Authorization` header or a bearer key that differs from the configured key
- **THEN** the service returns HTTP `401` and performs no admin operation

#### Scenario: Correct key is accepted
- **WHEN** a request to an `/admin` route carries the configured key as a bearer token
- **THEN** the request is processed

### Requirement: Admin API is rate limited before authentication
The system MUST apply a shared rate limit, configured by `ADMIN_RATE_LIMIT_RPS` and `ADMIN_RATE_LIMIT_BURST`, to every `/admin` request before the key is checked.

#### Scenario: Limit is exceeded
- **WHEN** `/admin` requests arrive faster than the configured rate and burst allow
- **THEN** the excess requests receive HTTP `429` whether or not they carry a valid key

### Requirement: Admin API manages users
The system MUST allow an authenticated caller to create, list, disable and enable users.

#### Scenario: User is created
- **WHEN** `POST /admin/users` is called with a non-blank `username` and an optional `email`
- **THEN** the service creates the user and returns HTTP `201` with the user's id, username, email, `disabledAt` and `createdAt`

#### Scenario: Username is blank
- **WHEN** `POST /admin/users` is called with a missing or blank `username`
- **THEN** the service returns HTTP `400` and creates no user

#### Scenario: Username or email is already taken
- **WHEN** `POST /admin/users` is called with a `username` or `email` that an existing user already has
- **THEN** the service returns HTTP `409` and creates no user

#### Scenario: Users are listed
- **WHEN** `GET /admin/users` is called
- **THEN** the service returns HTTP `200` with all users ordered by creation time

#### Scenario: User is disabled or enabled
- **WHEN** `POST /admin/users/:id/disable` or `POST /admin/users/:id/enable` is called for an existing user
- **THEN** the service sets or clears `disabled_at` and returns HTTP `200`

#### Scenario: User is already in the requested state
- **WHEN** `POST /admin/users/:id/disable` is called for a user that is already disabled, or `.../enable` for a user that is not disabled
- **THEN** the service returns HTTP `200` and leaves the existing `disabled_at` value unchanged

#### Scenario: User id is unknown or malformed
- **WHEN** a user route is called with an id that is not a UUID, or a UUID that matches no user
- **THEN** the service returns HTTP `400` for a malformed id and HTTP `404` for an unknown one

### Requirement: Admin API mints and revokes enroll tokens
The system MUST allow an authenticated caller to mint, list and revoke enroll tokens, MUST generate tokens server-side from 32 random bytes, and MUST return the token plaintext only in the response that creates it.

#### Scenario: Token is minted
- **WHEN** `POST /admin/tokens` is called with the `userId` of an existing user and optional `expiresAt`, `maxDevices` and `note`
- **THEN** the service stores only the token hash and returns HTTP `201` with the plaintext token and the token's metadata

#### Scenario: Max devices is omitted
- **WHEN** `POST /admin/tokens` is called without `maxDevices`
- **THEN** the token is created with `max_devices` equal to `1`

#### Scenario: Max devices is zero
- **WHEN** `POST /admin/tokens` is called with `maxDevices` equal to `0`
- **THEN** the token is created with no device limit

#### Scenario: Max devices is negative
- **WHEN** `POST /admin/tokens` is called with a negative `maxDevices`
- **THEN** the service returns HTTP `400` and creates no token

#### Scenario: Token user is unknown or malformed
- **WHEN** `POST /admin/tokens` is called with a `userId` that is not a UUID, or a UUID that matches no user
- **THEN** the service returns HTTP `400` for a malformed id and HTTP `404` for an unknown one, and creates no token

#### Scenario: Tokens are listed
- **WHEN** `GET /admin/tokens` is called
- **THEN** the service returns HTTP `200` with each token's metadata and neither the plaintext nor the hash

#### Scenario: Token is revoked
- **WHEN** `POST /admin/tokens/:id/revoke` is called for an existing token
- **THEN** the service sets `revoked_at` and returns HTTP `200`; a token that is already revoked keeps its original `revoked_at`

### Requirement: Admin API lists, revokes and re-enables devices
The system MUST allow an authenticated caller to list devices and to revoke or re-enable a device.

#### Scenario: Devices are listed
- **WHEN** `GET /admin/devices` is called, optionally with a `userId` query parameter
- **THEN** the service returns HTTP `200` with all devices, or only that user's devices, ordered by creation time

#### Scenario: Device filter is malformed
- **WHEN** `GET /admin/devices` is called with a `userId` that is not a UUID
- **THEN** the service returns HTTP `400`

#### Scenario: Device is revoked or re-enabled
- **WHEN** `POST /admin/devices/:id/revoke` or `POST /admin/devices/:id/enable` is called for an existing device
- **THEN** the service sets or clears `revoked_at` and returns HTTP `200`

#### Scenario: Device is already in the requested state
- **WHEN** `POST /admin/devices/:id/revoke` is called for a device that is already revoked, or `.../enable` for a device that is not revoked
- **THEN** the service returns HTTP `200` and leaves the existing `revoked_at` value unchanged

#### Scenario: Device id is unknown or malformed
- **WHEN** a device route is called with an id that is not a UUID, or a UUID that matches no device
- **THEN** the service returns HTTP `400` for a malformed id and HTTP `404` for an unknown one
