## Purpose

Define how changes that affect verify decisions reach every running instance without a restart: the database is the source of truth, a version stored with it tells instances when to catch up, staleness is bounded, and an instance that cannot confirm it is current fails closed.

## ADDED Requirements

### Requirement: Decision-affecting changes bump a stored policy version atomically
Every change that can affect a verify decision MUST increment a policy version stored in the database, in the same transaction as the change and, for admin requests, as its admin audit row. These changes are: role, grant, binding and relay changes; device revoke, enable and delete; user disable, enable and delete; and a successful registration.

#### Scenario: Role grant change
- **WHEN** `PUT /admin/roles/:name/relays` succeeds
- **THEN** the grant change, the version increment and the admin audit row are committed together

#### Scenario: Change fails
- **WHEN** a decision-affecting change is rolled back
- **THEN** the stored policy version is unchanged

#### Scenario: Registration
- **WHEN** `POST /register` creates a device
- **THEN** the stored policy version is incremented in the same transaction as the device row

### Requirement: The instance that made a change applies it before responding
The instance that handles a decision-affecting change MUST apply it locally before it sends the response: it MUST reload its policy snapshot after a role, grant, binding or relay change, and MUST drop affected cached verify decisions after any decision-affecting change.

#### Scenario: Grant removed then verify on the same instance
- **WHEN** a role's grant on relay `default` is removed and the response has been received, and a device whose user has only that role then calls `POST /verify` on the same instance
- **THEN** the response contains `Allow=false` and `DenyReason="policy denied"`

### Requirement: Other instances catch up within two sync intervals
Each instance MUST check the stored policy version every `POLICY_SYNC_INTERVAL` (default `2s`). When it has changed, the instance MUST bring its policy snapshot and cached verify decisions in line with the database. A committed change MUST be reflected by every other healthy instance within two sync intervals.

#### Scenario: Revoke on another instance
- **WHEN** instance A revokes a device that has a cached allow on instance B
- **THEN** within two sync intervals, `POST /verify` for that node key on instance B returns `Allow=false` with `DenyReason="revoked"`

#### Scenario: New role binding on another instance
- **WHEN** instance A binds a user to a role that grants relay `eu-1`
- **THEN** within two sync intervals, the user's devices are allowed on `POST /verify/eu-1` at instance B

#### Scenario: No change
- **WHEN** the stored policy version has not changed since the instance's last check
- **THEN** the instance keeps its policy snapshot and cached decisions

### Requirement: Policy sync interval is configurable
The system MUST read `POLICY_SYNC_INTERVAL` as a duration with default `2s`, and MUST fail configuration loading when it does not parse or is not greater than zero.

#### Scenario: Interval is not valid
- **WHEN** configuration is loaded with `POLICY_SYNC_INTERVAL` set to `0s` or to `soon`
- **THEN** configuration loading fails with an error

### Requirement: An instance that cannot confirm it is current fails closed
When an instance has gone longer than three sync intervals without a successful version check, `/readyz` MUST return HTTP `503`. Every `/verify` request that it would otherwise evaluate, including one that would be answered from the cache, MUST be denied with `DenyReason="internal error"` and audited. This MUST last until a check succeeds and any needed reload has completed.

#### Scenario: Database unreachable for the policy check
- **WHEN** an instance's version checks have failed for longer than three sync intervals
- **THEN** `/readyz` returns HTTP `503`, and `POST /verify` for a device that was allowed before returns `Allow=false` with `DenyReason="internal error"`

#### Scenario: Check succeeds again
- **WHEN** a version check succeeds after such a period and any reload it needs has completed
- **THEN** `/readyz` returns HTTP `200` again and `/verify` is evaluated normally

### Requirement: Policy is provisioned only through the admin API
The admin API MUST be the only supported way to create or change roles, grants, bindings and relays. Rows changed directly in the database MUST be applied by a running instance no later than its next restart, and are not required to be applied earlier.

#### Scenario: User inserted by SQL
- **WHEN** a deployment without `ADMIN_API_KEY` inserts a user and an enroll token by SQL and the user registers a device
- **THEN** the device is denied with `policy denied` until the user is bound to a role through the admin API

#### Scenario: Role binding inserted by SQL
- **WHEN** an operator inserts a role binding by SQL
- **THEN** running instances are not required to apply it, and every instance applies it once it restarts
