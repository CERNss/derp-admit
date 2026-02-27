## ADDED Requirements

### Requirement: Verify decisions are always audited
The system MUST create an `audit_logs` record for every `POST /verify` decision, including allow and deny outcomes.

#### Scenario: Allow decision is logged
- **WHEN** `POST /verify` returns `Allow=true` for a known device
- **THEN** an audit row is created with `allowed=true`, matching `device_id`, matching `node_key`, and current timestamp

#### Scenario: Deny decision for known device is logged
- **WHEN** `POST /verify` returns `Allow=false` for a known device
- **THEN** an audit row is created with `allowed=false`, matching `device_id`, deny reason text, and current timestamp

#### Scenario: Deny decision for unknown device is logged
- **WHEN** `POST /verify` returns `Allow=false` because `node_key` is not registered
- **THEN** an audit row is created with `allowed=false`, `device_id` null, captured `node_key`, reason `not registered`, and current timestamp

### Requirement: Audit logs preserve deny reason for diagnostics
The system MUST persist a non-empty `reason` value for deny decisions to support troubleshooting and security review.

#### Scenario: Deny reason stored
- **WHEN** `POST /verify` produces a deny response with `DenyReason`
- **THEN** the created audit row stores the same reason text in `audit_logs.reason`
