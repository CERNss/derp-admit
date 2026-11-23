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

### Requirement: Verify decision cache does not outlive lifecycle changes
When `VERIFY_CACHE_TTL` is greater than zero, the system MUST drop a node key's cached decision when its device is registered, revoked or re-enabled, MUST drop the cached decisions of all of a user's devices when that user is disabled or enabled, and MUST NOT cache a decision that was computed before such a change.

#### Scenario: Device is revoked while an allow is cached
- **WHEN** a device has a cached allow decision and an admin revokes it
- **THEN** the next `POST /verify` for that node key returns `Allow=false` with `DenyReason="revoked"` without waiting for the cache TTL

#### Scenario: User is disabled while an allow is cached
- **WHEN** a device has a cached allow decision and an admin disables its owner
- **THEN** the next `POST /verify` for that node key returns `Allow=false` with `DenyReason="user disabled"` without waiting for the cache TTL

#### Scenario: Decision is computed while an invalidation happens
- **WHEN** a verify reads device state, an invalidation happens, and the verify then tries to cache its decision
- **THEN** the decision is not cached

### Requirement: Verify decision cache is bounded
The system MUST bound the number of cached verify decisions so that requests for many distinct node keys cannot grow the cache without limit.

#### Scenario: Cache is full
- **WHEN** a decision for a new node key is cached while the cache is at its maximum size
- **THEN** existing entries are evicted so the cache does not exceed its maximum size

#### Scenario: Cache is disabled
- **WHEN** `VERIFY_CACHE_TTL` is zero
- **THEN** no verify decision is cached and every `/verify` is evaluated against the database
