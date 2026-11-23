# admin-lifecycle-api Specification

## Purpose
Define the `/admin` operations on users, enroll tokens and devices: creating, listing, disabling, revoking and deleting them, and how list endpoints are paginated. Who may call the API is defined in `admin-access-control`.

## Requirements

### Requirement: Admin API manages users
The system MUST allow a caller whose tier permits it (see `admin-access-control`) to create, list, disable and enable users. User views MUST include the user's role names as `roles`.

#### Scenario: User is created
- **WHEN** `POST /admin/users` is called with a non-blank `username` and an optional `email`
- **THEN** the service creates the user and returns HTTP `201` with the user's id, username, email, `disabledAt`, `createdAt` and `roles`

#### Scenario: User is created without roles field
- **WHEN** `POST /admin/users` is called without a `roles` field
- **THEN** the user is created bound to role `standard`, and the response lists `roles` as `["standard"]`

#### Scenario: User is created with explicit roles
- **WHEN** `POST /admin/users` is called with `roles` set to a list of existing role names
- **THEN** the user is created bound to exactly those roles

#### Scenario: User is created with an empty roles list
- **WHEN** `POST /admin/users` is called with `roles` set to `[]`
- **THEN** the user is created with no role bindings, and the user's devices are denied with `policy denied` until a role is bound

#### Scenario: User is created with an unknown role
- **WHEN** `POST /admin/users` is called with a `roles` entry that names no existing role
- **THEN** the service returns HTTP `400` and creates no user

#### Scenario: Username is blank
- **WHEN** `POST /admin/users` is called with a missing or blank `username`
- **THEN** the service returns HTTP `400` and creates no user

#### Scenario: Username or email is already taken
- **WHEN** `POST /admin/users` is called with a `username` or `email` that an existing user already has
- **THEN** the service returns HTTP `409` and creates no user

#### Scenario: Users are listed
- **WHEN** `GET /admin/users` is called
- **THEN** the service returns HTTP `200` with a page of users, each with its `roles`, paginated as defined in "Admin list endpoints are paginated"

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
The system MUST allow a caller whose tier permits it (see `admin-access-control`) to mint, list and revoke enroll tokens, MUST generate tokens server-side from 32 random bytes, and MUST return the token plaintext only in the response that creates it.

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
- **THEN** the service returns HTTP `200` with a page of tokens, paginated as defined in "Admin list endpoints are paginated", showing each token's metadata and neither the plaintext nor the hash

#### Scenario: Token is revoked
- **WHEN** `POST /admin/tokens/:id/revoke` is called for an existing token
- **THEN** the service sets `revoked_at` and returns HTTP `200`; a token that is already revoked keeps its original `revoked_at`

### Requirement: Admin API lists, revokes and re-enables devices
The system MUST allow a caller whose tier permits it (see `admin-access-control`) to list devices and to revoke or re-enable a device. Re-enabling through this API is the only way to clear a device's revocation.

#### Scenario: Devices are listed
- **WHEN** `GET /admin/devices` is called, optionally with a `userId` query parameter
- **THEN** the service returns HTTP `200` with a page of all devices, or of only that user's devices, paginated as defined in "Admin list endpoints are paginated"

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

### Requirement: Admin list endpoints are paginated
Every `/admin` endpoint that returns a list MUST accept `limit` and `cursor` query parameters and MUST return a `nextCursor` field. `limit` defaults to 50 and MUST be between 1 and 200. Entity lists MUST be ordered by creation time ascending with a unique tie-break, and audit lists newest first. A page MUST continue exactly where the previous page ended.

#### Scenario: Default page size
- **WHEN** a list endpoint is called without `limit` and more than 50 rows exist
- **THEN** the service returns HTTP `200` with the first 50 rows in order and a non-null `nextCursor`

#### Scenario: Following the cursor
- **WHEN** a list endpoint is called again with the `nextCursor` from the previous response and the same filters
- **THEN** the response starts with the row that follows the last row of the previous page, with no row repeated or skipped

#### Scenario: Last page
- **WHEN** a list endpoint returns the last rows that match
- **THEN** `nextCursor` is absent or null

#### Scenario: Limit out of range or not a number
- **WHEN** a list endpoint is called with a `limit` that is not an integer, is less than 1, or is greater than 200
- **THEN** the service returns HTTP `400`

#### Scenario: Cursor is not valid
- **WHEN** a list endpoint is called with a `cursor` that the service did not issue
- **THEN** the service returns HTTP `400`

### Requirement: A pagination cursor is bound to its filters
A `nextCursor` MUST be bound to the list and the filter values it was issued under. Sent with other filter values, it MUST be rejected with HTTP `400`, like a cursor issued by another list.

#### Scenario: Cursor is sent with different filters
- **WHEN** a list endpoint is called with a `nextCursor` issued under one set of filter values, such as `GET /admin/devices?userId=<a>`, together with different filter values, such as `userId=<b>` or no `userId`
- **THEN** the service returns HTTP `400`, as for a cursor issued by another list

### Requirement: Admin API deletes users
The system MUST provide `DELETE /admin/users/:id`. It removes the user together with the user's enroll tokens, devices, role bindings and the legacy device rules of those devices, in one transaction.

#### Scenario: User is deleted
- **WHEN** `DELETE /admin/users/:id` is called for an existing user
- **THEN** the service returns HTTP `200`, and the user, the user's tokens, devices, role bindings and legacy `g, device:<node_key>, user:<user_id>` rules no longer exist

#### Scenario: Deleted user's device is no longer admitted
- **WHEN** a user with an admitted device is deleted and the device's node key then calls `POST /verify`
- **THEN** the response contains `Allow=false` and `DenyReason="not registered"`

#### Scenario: User id is unknown or malformed on delete
- **WHEN** `DELETE /admin/users/:id` is called with an id that is not a UUID, or a UUID that matches no user
- **THEN** the service returns HTTP `400` for a malformed id and HTTP `404` for an unknown one, and deletes nothing

### Requirement: Admin API deletes enroll tokens
The system MUST provide `DELETE /admin/tokens/:id`, which removes the token. Devices already enrolled with the token MUST be kept.

#### Scenario: Token is deleted
- **WHEN** `DELETE /admin/tokens/:id` is called for an existing token
- **THEN** the service returns HTTP `200`, the token no longer exists, and a later `POST /register` with its plaintext returns HTTP `401`

#### Scenario: Devices enrolled with a deleted token are kept
- **WHEN** a token that enrolled a device is deleted
- **THEN** the device row is unchanged

#### Scenario: Token id is unknown or malformed on delete
- **WHEN** `DELETE /admin/tokens/:id` is called with an id that is not a UUID, or a UUID that matches no token
- **THEN** the service returns HTTP `400` for a malformed id and HTTP `404` for an unknown one

### Requirement: Admin API deletes devices
The system MUST provide `DELETE /admin/devices/:id`, which removes the device and its legacy `g, device:<node_key>, user:<user_id>` rule. The rule that delete forgets a node key and revoke bans it is defined in `device-enrollment`.

#### Scenario: Device is deleted
- **WHEN** `DELETE /admin/devices/:id` is called for an existing device
- **THEN** the service returns HTTP `200` and the device no longer exists

#### Scenario: Deleted device is no longer admitted
- **WHEN** a device is deleted and its node key then calls `POST /verify`
- **THEN** the response contains `Allow=false` and `DenyReason="not registered"`

#### Scenario: Device id is unknown or malformed on delete
- **WHEN** `DELETE /admin/devices/:id` is called with an id that is not a UUID, or a UUID that matches no device
- **THEN** the service returns HTTP `400` for a malformed id and HTTP `404` for an unknown one
