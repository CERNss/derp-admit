## ADDED Requirements

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
