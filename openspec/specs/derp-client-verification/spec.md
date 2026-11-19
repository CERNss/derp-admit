# derp-client-verification Specification

## Purpose
Define the `POST /verify` endpoint that derper calls to admit a client: the request contract it consumes, the registration and lifecycle checks it enforces, and what it records when a device is admitted.

## Requirements

### Requirement: Verify endpoint consumes DERP admit request contract
The system MUST provide `POST /verify` that parses request bodies as `tailcfg.DERPAdmitClientRequest` and returns responses as `tailcfg.DERPAdmitClientResponse`.

#### Scenario: Malformed or unparsable verify request
- **WHEN** `POST /verify` receives a body that cannot be parsed into `tailcfg.DERPAdmitClientRequest` or does not yield a valid `node_key`
- **THEN** the service returns a deny response with `Allow=false` and a non-empty deny reason

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

### Requirement: Verify endpoint allows authorized active devices
The system MUST return `Allow=true` only when device exists, is not revoked, owner user is enabled, and authorization checks pass.

#### Scenario: Registered and authorized device is allowed
- **WHEN** `POST /verify` is called for a registered active device whose owner is enabled and policy allows connection
- **THEN** the response contains `Allow=true` with no deny reason

### Requirement: Verify endpoint updates last seen on successful admit
The system MUST update `devices.last_seen_at` to current timestamp only for allow decisions.

#### Scenario: Allow decision updates last seen
- **WHEN** `POST /verify` returns `Allow=true` for a device
- **THEN** the corresponding `devices.last_seen_at` value is updated to current time

#### Scenario: Deny decision does not update last seen
- **WHEN** `POST /verify` returns `Allow=false` for a device
- **THEN** the corresponding `devices.last_seen_at` value remains unchanged
