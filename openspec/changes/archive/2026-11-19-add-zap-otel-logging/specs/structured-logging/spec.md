## ADDED Requirements

### Requirement: Service SHALL emit structured logs with zap
The system MUST use zap as the application logger for startup, HTTP handlers, and service-level operational events.

#### Scenario: Startup log format
- **WHEN** the verifier process starts successfully
- **THEN** startup logs are emitted in structured JSON format with stable key/value fields

### Requirement: Sensitive enrollment token data MUST NOT be logged
The system MUST NOT log registration token plaintext at any log level or in error metadata.

#### Scenario: Register request handling
- **WHEN** `POST /register` processes valid or invalid requests
- **THEN** logs do not contain the request token value

### Requirement: Error logs SHALL carry machine-readable fields
The system MUST include structured fields (for example `error`, `reason`, and request identifiers) for operational errors.

#### Scenario: Verify database error
- **WHEN** `/verify` encounters a database access error
- **THEN** an error log is emitted with structured fields including the error detail
