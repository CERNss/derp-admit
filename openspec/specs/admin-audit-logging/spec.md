# admin-audit-logging Specification

## Purpose
Define the audit trail for admin operations: which admin requests and startup actions are recorded, what each record holds, how a record stays consistent with the change it describes, and how the trail is queried.

## Requirements

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
The system MUST write an admin audit row with actor `system` whenever startup creates or reactivates the `bootstrap` key or changes its hash, for each device the one-time upgrade revokes, and once with action `upgrade.run` for a one-time upgrade that runs on a database with at least one user. A startup that does none of these MUST NOT write a row.

#### Scenario: Bootstrap key is created at startup
- **WHEN** the service creates the `bootstrap` key at startup
- **THEN** an admin audit row records actor `system`, the action, target type admin key and the `bootstrap` key's id

#### Scenario: Upgrade revokes a device
- **WHEN** the one-time upgrade revokes a device
- **THEN** an admin audit row records actor `system`, a revoke action, target type `device`, the device id and a summary saying the upgrade revoked it

#### Scenario: Upgrade run is audited
- **WHEN** the one-time upgrade runs on a database with users
- **THEN** one admin audit row with actor `system` and action `upgrade.run` is written in the upgrade's transaction, and its summary holds the mode and how it was determined, and the counts of users bound to `standard`, users left without access on `default`, devices revoked, unmanaged rules, and roles and relays imported, with no user or device id

#### Scenario: Upgrade on a fresh database
- **WHEN** the one-time upgrade runs on a database with no users
- **THEN** the marker is written and no `upgrade.run` audit row is written

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

### Requirement: Logs contain no key hashes, token hashes or bound query values
The service MUST NOT write admin key hashes, enroll token hashes or any other bound query value to its logs. This includes the database driver's log of failed, slow or "record not found" statements, which MAY name the statement but MUST NOT include its bound values.

#### Scenario: Unknown admin key
- **WHEN** a request to an `/admin` route carries a bearer key whose hash matches no stored admin key and the service returns HTTP `401`
- **THEN** no log line, including the database driver's log of the lookup, contains the key or its hash

#### Scenario: Unknown enroll token at register
- **WHEN** `POST /register` carries an enroll token whose hash matches no stored token
- **THEN** no log line, including the database driver's log of the lookup, contains the token or its hash

### Requirement: Admin audit rows are kept for the configured retention period
When `ADMIN_AUDIT_RETENTION_DAYS` is greater than zero, every instance MUST delete `admin_audit_logs` rows whose timestamp is older than that many days before now, including `system` rows such as `upgrade.run` and `bootstrap.create`, shortly after startup and then about once an hour, in batches of at most 1000 rows per statement. When it is `0` (the default), no admin audit row MUST be deleted. Pruning MUST NOT touch `audit_logs`.

#### Scenario: Old admin rows are pruned
- **WHEN** `ADMIN_AUDIT_RETENTION_DAYS` is `90` and `admin_audit_logs` holds rows 91 days old and rows 89 days old
- **THEN** a pruning pass deletes the 91-day-old rows and keeps the 89-day-old rows and every `audit_logs` row

#### Scenario: Old system rows are pruned too
- **WHEN** `ADMIN_AUDIT_RETENTION_DAYS` is `90` and the `upgrade.run` row is 91 days old
- **THEN** that row is deleted, and the one-time upgrade still does not run again, because its marker is kept in `policy_state`

#### Scenario: Admin retention disabled
- **WHEN** `ADMIN_AUDIT_RETENTION_DAYS` is `0`
- **THEN** no admin audit row is ever deleted by pruning, however old

### Requirement: Admin audit pruning ends only when no old row is left to it
In a pruning pass each instance MUST repeat batches until a statement deletes nothing. Together the instances MUST delete every admin audit row older than the cutoff; a single instance may stop while another instance still holds some of those rows, and that instance deletes them.

#### Scenario: More old admin rows than one batch
- **WHEN** more than 1000 admin audit rows are older than the retention period and a single instance prunes
- **THEN** one pruning pass deletes all of them, using more than one statement

### Requirement: Admin audit pruning does not disturb the service
Admin audit pruning MUST be harmless when several instances run it at the same time: no error, no deadlock, and no row newer than the cutoff deleted. It MUST NOT change `policy_state.version` or the verify cache, MUST NOT write an admin audit row of its own, and MUST stop when the instance shuts down. A pass that deletes rows MUST log one info line with the table, the count and the cutoff; a failed pass MUST be logged at error level and retried at the next tick.

#### Scenario: Pruning writes no admin audit row
- **WHEN** a pruning pass deletes admin audit rows
- **THEN** no new admin audit row is written and `policy_state.version` is unchanged

#### Scenario: Prune between two admin audit pages
- **WHEN** a caller reads page 1 of `GET /admin/audit/admin`, rows on later pages are pruned, and the caller then follows `nextCursor`
- **THEN** page 2 returns HTTP `200` with the remaining rows older than the cursor, no row from page 1 repeated, and a null `nextCursor` if none remain
