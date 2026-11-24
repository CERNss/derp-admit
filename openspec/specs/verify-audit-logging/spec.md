# verify-audit-logging Specification

## Purpose
Define the audit trail for verify decisions: every decision is recorded, and denials keep their reason for diagnostics.

## Requirements

### Requirement: Verify decisions are always audited
The system MUST create an `audit_logs` record for every `POST /verify` and `POST /verify/:relay` decision, including allow and deny outcomes and every deny produced after the verify rate limit, also for a body that is not valid JSON (node key empty). Requests rejected by the rate limit, and requests rejected by `VERIFY_ALLOWED_CIDRS`, MUST NOT be audited. Each record MUST store the relay name the request named when it matches the relay name format, even if it is not in the registry, and null when it is malformed. Rows written before the upgrade keep a null relay; there is no backfill.

#### Scenario: Body that is not valid JSON is logged
- **WHEN** `POST /verify/eu-1` receives a body that is not valid JSON
- **THEN** the response is a deny with `invalid request`, and an audit row is created with `allowed=false`, an empty `node_key`, relay `eu-1`, reason `invalid request`, and current timestamp

#### Scenario: Rate-limited request is not logged
- **WHEN** `POST /verify` is rejected by the verify rate limit
- **THEN** the response is a deny with `rate limited`, and no audit row is created

#### Scenario: Caller outside the allowlist is not logged
- **WHEN** `POST /verify` or `POST /verify/eu-1` comes from a peer outside `VERIFY_ALLOWED_CIDRS`
- **THEN** the response is HTTP `403`, and no audit row is created

#### Scenario: Allow decision is logged
- **WHEN** `POST /verify/:relay` returns `Allow=true` for a known device
- **THEN** an audit row is created with `allowed=true`, matching `device_id`, matching `node_key`, the relay, and current timestamp

#### Scenario: Deny decision for known device is logged
- **WHEN** `POST /verify/:relay` returns `Allow=false` for a known device
- **THEN** an audit row is created with `allowed=false`, matching `device_id`, the relay, deny reason text, and current timestamp

#### Scenario: Deny decision for unknown device is logged
- **WHEN** `POST /verify/:relay` returns `Allow=false` because `node_key` is not registered
- **THEN** an audit row is created with `allowed=false`, `device_id` null, captured `node_key`, the relay, reason `not registered`, and current timestamp

#### Scenario: Plain verify is logged as relay default
- **WHEN** `POST /verify` without a relay segment returns a decision
- **THEN** the audit row records relay `default`

#### Scenario: Unknown relay is logged
- **WHEN** `POST /verify/does-not-exist` is denied with `unknown relay`
- **THEN** an audit row is created with `allowed=false`, captured `node_key`, relay `does-not-exist`, reason `unknown relay`, and current timestamp

#### Scenario: Malformed relay is logged with null relay
- **WHEN** `POST /verify/Bad_Name` is denied with `unknown relay`
- **THEN** the audit row stores a null relay

#### Scenario: Rows written before the upgrade
- **WHEN** the upgrade adds the relay column to existing `audit_logs` rows
- **THEN** those rows hold a null relay

### Requirement: Audit logs preserve deny reason for diagnostics
The system MUST persist a non-empty `reason` value for deny decisions to support troubleshooting and security review.

#### Scenario: Deny reason stored
- **WHEN** `POST /verify` produces a deny response with `DenyReason`
- **THEN** the created audit row stores the same reason text in `audit_logs.reason`

### Requirement: Verify audit rows survive device and user deletion
When a device is deleted, directly or by deleting its user, the system MUST keep that device's verify audit rows with their `node_key` and set their `device_id` to null, on both sqlite and Postgres.

#### Scenario: User is deleted
- **WHEN** a user whose device has verify audit rows is deleted through `DELETE /admin/users/:id`
- **THEN** those rows still exist with the same `node_key`, `allowed`, `reason`, relay and timestamp, and `device_id` null

#### Scenario: Device is deleted
- **WHEN** a device with verify audit rows is deleted through `DELETE /admin/devices/:id`
- **THEN** those rows still exist with the same `node_key` and `device_id` null

### Requirement: Verify audit is queryable
The system MUST provide `GET /admin/audit/verify`, newest first and paginated as defined in `admin-lifecycle-api`, with optional filters `nodeKey`, `deviceId`, `relay`, `allowed`, `since` and `until`. Filters combine with AND.

#### Scenario: Filter by node key and outcome
- **WHEN** `GET /admin/audit/verify?nodeKey=<key>&allowed=false` is called
- **THEN** only deny rows for that node key are returned, newest first

#### Scenario: Filter by relay
- **WHEN** `GET /admin/audit/verify?relay=eu-1` is called
- **THEN** only rows whose stored relay is exactly `eu-1` are returned; rows with a null relay are not

#### Scenario: Filter value is malformed
- **WHEN** `deviceId` is not a UUID, `allowed` is not `true` or `false`, or `since` or `until` is not an RFC 3339 timestamp
- **THEN** the service returns HTTP `400`

### Requirement: Verify audit rows are kept for the configured retention period
When `VERIFY_AUDIT_RETENTION_DAYS` is greater than zero, every instance MUST delete `audit_logs` rows whose timestamp is older than that many days before now, shortly after startup and then about once an hour, in batches of at most 1000 rows per statement. When it is `0` (the default), no verify audit row MUST be deleted. Pruning MUST NOT touch `admin_audit_logs`.

#### Scenario: Old rows are pruned
- **WHEN** `VERIFY_AUDIT_RETENTION_DAYS` is `30` and `audit_logs` holds rows 31 days old and rows 29 days old
- **THEN** a pruning pass deletes the 31-day-old rows and keeps the 29-day-old rows and every `admin_audit_logs` row

#### Scenario: More old rows than one batch
- **WHEN** more than 1000 verify audit rows are older than the retention period and a single instance prunes
- **THEN** one pruning pass deletes all of them, using more than one statement

#### Scenario: Retention disabled
- **WHEN** `VERIFY_AUDIT_RETENTION_DAYS` is `0`
- **THEN** no verify audit row is ever deleted by pruning, however old

### Requirement: Verify audit pruning ends only when no old row is left to it
In a pruning pass each instance MUST repeat batches until a statement deletes nothing. Together the instances MUST delete every verify audit row older than the cutoff; a single instance may stop while another instance still holds some of those rows, and that instance deletes them.

#### Scenario: One instance holds part of the old rows
- **WHEN** one instance's pass finds some old verify audit rows locked by another instance's pass
- **THEN** it deletes the others without waiting and ends, and the other instance deletes the rows it holds

### Requirement: Verify audit pruning does not disturb the service
Verify audit pruning MUST be harmless when several instances run it at the same time: no error, no deadlock, and no row newer than the cutoff deleted. It MUST NOT change `policy_state.version`, the verify cache, `/verify` decisions or `/readyz`, and MUST NOT write an admin audit row. A pass that deletes rows MUST log one info line with the table, the count and the cutoff. A failed pass MUST be logged at error level and retried at the next tick. Pruning MUST stop when the instance shuts down.

#### Scenario: Two instances prune at once
- **WHEN** two instances run a pruning pass over the same old verify audit rows concurrently
- **THEN** both finish without error, together they delete every old row exactly once, and every newer row remains

#### Scenario: Pruning failure
- **WHEN** a pruning pass fails, for example because the database is unreachable
- **THEN** the failure is logged at error level, `/readyz` and `/verify` are unaffected by it, and the next tick tries again

#### Scenario: Prune between two audit pages
- **WHEN** a caller reads page 1 of `GET /admin/audit/verify`, rows on later pages are pruned, and the caller then follows `nextCursor`
- **THEN** page 2 returns HTTP `200` with the remaining rows older than the cursor, no row from page 1 repeated, and a null `nextCursor` if none remain
