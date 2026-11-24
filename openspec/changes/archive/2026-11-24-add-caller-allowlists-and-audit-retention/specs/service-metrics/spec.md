## MODIFIED Requirements

### Requirement: Metrics endpoint is served on the main listener
When `METRICS_ENABLED` is true (the default), the system MUST serve `GET /metrics` in the Prometheus text exposition format on the main listener, without authentication. When `METRICS_ALLOWED_CIDRS` is set, a caller whose TCP peer address is outside the list MUST get HTTP `403`, matched as defined for verify callers in `derp-client-verification`; when it is unset or empty, every caller is served. When `METRICS_ENABLED` is false, `GET /metrics` MUST return HTTP `404`.

#### Scenario: Metrics enabled by default
- **WHEN** the service starts without `METRICS_ENABLED` and `GET /metrics` is called without credentials
- **THEN** the service returns HTTP `200` with a body in the Prometheus text exposition format

#### Scenario: Metrics disabled
- **WHEN** the service starts with `METRICS_ENABLED=false` and `GET /metrics` is called
- **THEN** the service returns HTTP `404`

#### Scenario: Metrics setting is not a boolean
- **WHEN** configuration is loaded with `METRICS_ENABLED` set to a value that does not parse as a boolean
- **THEN** configuration loading fails with an error

#### Scenario: Scrape from an allowed peer
- **WHEN** `METRICS_ALLOWED_CIDRS` is `10.0.0.0/8` and `GET /metrics` is called from peer `10.9.9.9`
- **THEN** the service returns HTTP `200` with the metrics body

#### Scenario: Scrape from a peer outside the list
- **WHEN** `METRICS_ALLOWED_CIDRS` is `10.0.0.0/8` and `GET /metrics` is called from peer `192.0.2.1`, also with `X-Forwarded-For: 10.0.0.5`
- **THEN** the service returns HTTP `403` and no metrics body

## ADDED Requirements

### Requirement: Metrics cover caller rejections
The metrics MUST include a counter of requests rejected by a caller allowlist, labelled by endpoint (`verify` or `metrics`).

#### Scenario: Verify caller rejection is counted
- **WHEN** a `POST /verify/eu-1` request is rejected by `VERIFY_ALLOWED_CIDRS`
- **THEN** the caller rejection counter for endpoint `verify` increases by one

#### Scenario: Metrics caller rejection is counted
- **WHEN** a `GET /metrics` request is rejected by `METRICS_ALLOWED_CIDRS`
- **THEN** the caller rejection counter for endpoint `metrics` increases by one

### Requirement: Metrics cover audit pruning
The metrics MUST include a counter of audit rows deleted by retention pruning, labelled by table (`verify` for `audit_logs`, `admin` for `admin_audit_logs`).

#### Scenario: Pruned rows are counted
- **WHEN** a pruning pass deletes 1500 verify audit rows and 3 admin audit rows
- **THEN** the pruned row counter for table `verify` increases by 1500 and for table `admin` by 3
