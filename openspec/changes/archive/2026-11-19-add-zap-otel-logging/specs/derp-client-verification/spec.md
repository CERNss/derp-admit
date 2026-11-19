## MODIFIED Requirements

### Requirement: Verify endpoint enforces registration and lifecycle checks
The system MUST deny device connection when device registration or user lifecycle constraints are not satisfied, and MUST emit structured operational logs for deny/error paths without exposing sensitive token data.

#### Scenario: Unregistered node key is denied
- **WHEN** `POST /verify` is called with a `node_key` that has no matching device record
- **THEN** the response contains `Allow=false` and `DenyReason="not registered"`

#### Scenario: Revoked device is denied
- **WHEN** `POST /verify` is called for a device with `revoked_at` not null
- **THEN** the response contains `Allow=false` and `DenyReason="revoked"`

#### Scenario: Disabled user is denied
- **WHEN** `POST /verify` resolves a device whose owner user has `disabled_at` not null
- **THEN** the response contains `Allow=false` and `DenyReason="user disabled"`

#### Scenario: Deny and error path logging
- **WHEN** `/verify` returns a deny decision or internal error
- **THEN** the service emits structured logs with machine-readable fields for reason and error details
