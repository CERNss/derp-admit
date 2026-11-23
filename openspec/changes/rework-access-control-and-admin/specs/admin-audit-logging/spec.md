## Purpose

Define the audit trail for admin operations: which admin requests and startup actions are recorded, what each record holds, how a record stays consistent with the change it describes, and how the trail is queried.

## ADDED Requirements

### Requirement: Authenticated mutating admin requests are audited
The system MUST write one admin audit row for every `POST`, `PUT` or `DELETE` request to `/admin` that passes authentication, whatever its outcome, including HTTP `403` for an insufficient tier. Read-only requests MUST NOT be audited.

#### Scenario: Successful mutation is audited
- **WHEN** an `operator` key revokes a device with `POST /admin/devices/:id/revoke`
- **THEN** one admin audit row records the key's id, name and tier, the action, target type `device`, the device id, a success outcome, HTTP status `200`, the client IP and the current time

#### Scenario: Rejected mutation is audited
- **WHEN** an authenticated mutating request fails with HTTP `400`, `404` or `409`
- **THEN** one admin audit row records the attempt with a failure outcome and that HTTP status

#### Scenario: Insufficient tier is audited
- **WHEN** a `viewer` key calls `DELETE /admin/users/:id`
- **THEN** the service returns HTTP `403` and one admin audit row records the attempt with HTTP status `403`

#### Scenario: Read-only request is not audited
- **WHEN** any key calls a `GET` route under `/admin`
- **THEN** no admin audit row is written

### Requirement: Unauthenticated admin requests are not stored
The system MUST NOT write an admin audit row for a request that fails authentication or is rate limited. Such requests MUST be logged and counted in metrics only.

#### Scenario: Request with an unknown key
- **WHEN** a `POST /admin/users` request carries a key that matches no stored admin key
- **THEN** the service returns HTTP `401`, writes no admin audit row, logs the attempt and increments the admin request counter

### Requirement: Audit row of a successful mutation is atomic with the change
For a successful mutation, the system MUST write the admin audit row in the same database transaction as the change. If the audit row cannot be written, the change MUST NOT be committed.

#### Scenario: Audit write fails
- **WHEN** a mutation's change succeeds but its audit row cannot be written
- **THEN** the transaction is rolled back, the change does not persist, and the service returns HTTP `500`

### Requirement: Admin audit rows contain no secrets
Each admin audit row MUST carry a summary of the requested change. The summary and every other field MUST NOT contain a plaintext admin key, enroll token or `ADMIN_API_KEY` value, or any hash of them.

#### Scenario: Key creation is audited without the key
- **WHEN** `POST /admin/keys` creates a key
- **THEN** the audit row's summary has the key's name and tier, and neither the plaintext key nor its hash

#### Scenario: Token mint is audited without the token
- **WHEN** `POST /admin/tokens` mints a token
- **THEN** the audit row's summary has the user id and token metadata, and neither the plaintext token nor its hash

### Requirement: Startup actions are audited as system
The system MUST write an admin audit row with actor `system` whenever startup creates or reactivates the `bootstrap` key or changes its hash, and for each device the one-time upgrade revokes. A startup that changes neither MUST NOT write a row.

#### Scenario: Bootstrap key is created at startup
- **WHEN** the service creates the `bootstrap` key at startup
- **THEN** an admin audit row records actor `system`, the action, target type admin key and the `bootstrap` key's id

#### Scenario: Upgrade revokes a device
- **WHEN** the one-time upgrade revokes a device
- **THEN** an admin audit row records actor `system`, a revoke action, target type `device`, the device id and a summary saying the upgrade revoked it

#### Scenario: Restart with the same ADMIN_API_KEY
- **WHEN** the service restarts while the `bootstrap` key is active and `ADMIN_API_KEY` is unchanged
- **THEN** no admin audit row is written

### Requirement: Admin audit is queryable
The system MUST provide `GET /admin/audit/admin`, newest first and paginated as defined in `admin-lifecycle-api`, with optional filters `actorKeyId`, `action`, `targetType`, `targetId`, `since` and `until`. Filters combine with AND.

#### Scenario: Filter by actor
- **WHEN** `GET /admin/audit/admin?actorKeyId=<id>` is called
- **THEN** only rows whose actor key id is `<id>` are returned, newest first

#### Scenario: Filter by time range
- **WHEN** `GET /admin/audit/admin` is called with `since` and `until` timestamps
- **THEN** only rows whose timestamp is within that range are returned

#### Scenario: Filter value is malformed
- **WHEN** `actorKeyId` is not a UUID, or `since` or `until` is not an RFC 3339 timestamp
- **THEN** the service returns HTTP `400`
