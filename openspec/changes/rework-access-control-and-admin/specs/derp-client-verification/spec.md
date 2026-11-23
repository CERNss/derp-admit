## ADDED Requirements

### Requirement: Verify identifies the relay from the URL path
The system MUST serve `POST /verify/:relay`, where `:relay` names the relay to evaluate. `POST /verify` with no relay segment MUST be treated as relay `default`, so existing derper configurations keep working.

#### Scenario: Derper still calls plain /verify
- **WHEN** a derper configured with `--verify-client-url=http://verifier:8080/verify` sends an admit request for an active device whose user has role `standard` with its built-in grant
- **THEN** the request is evaluated for relay `default` and the response contains `Allow=true`

#### Scenario: Named relay
- **WHEN** a derper calls `POST /verify/eu-1` and relay `eu-1` exists
- **THEN** the request is evaluated for relay `eu-1`

### Requirement: Unknown relay is denied
A verify request whose relay name is not in the relay registry, or is not a valid relay name, MUST be denied with HTTP `200` in the `tailcfg.DERPAdmitClientResponse` format, with `Allow=false` and `DenyReason="unknown relay"`, and MUST be audited.

#### Scenario: Relay does not exist
- **WHEN** `POST /verify/does-not-exist` is called with a valid admit request for an active, authorized device
- **THEN** the service returns HTTP `200` with `Allow=false` and `DenyReason="unknown relay"`, and an audit row records the decision

#### Scenario: Relay name is malformed
- **WHEN** `POST /verify/Bad_Name` is called with a valid admit request
- **THEN** the service returns HTTP `200` with `Allow=false` and `DenyReason="unknown relay"`

### Requirement: Verify checks run in a fixed order
The system MUST evaluate a verify request in this order and MUST return the first failing check's deny reason: parse the request (`invalid request`), relay is known (`unknown relay`), device is registered (`not registered`), device is not revoked (`revoked`), owner user is not disabled (`user disabled`), policy allows (`policy denied`).

#### Scenario: Unknown relay and unregistered device
- **WHEN** `POST /verify/does-not-exist` is called for a node key that is not registered
- **THEN** the deny reason is `unknown relay`

#### Scenario: Revoked device of a disabled user
- **WHEN** `POST /verify` is called for a revoked device whose owner is disabled
- **THEN** the deny reason is `revoked`

#### Scenario: Malformed body on an unknown relay
- **WHEN** `POST /verify/does-not-exist` is called with a body that is not a valid admit request
- **THEN** the deny reason is `invalid request`

### Requirement: Relay name is trusted as asserted by the caller
`/verify` MUST NOT authenticate its caller. The relay name selects which policy is evaluated. It keeps a role from being used on the wrong relay when each derper is configured with its own relay URL. It does not stop a derper operator from pointing a relay at a more permissive relay name.

#### Scenario: Caller names a different relay
- **WHEN** a caller sends an admit request to `POST /verify/eu-1` for a device whose user's roles grant only `eu-1`
- **THEN** the decision is evaluated for `eu-1` and allowed, whichever derper sent it

## MODIFIED Requirements

### Requirement: Verify endpoint consumes DERP admit request contract
The system MUST provide `POST /verify` and `POST /verify/:relay`, which parse request bodies as `tailcfg.DERPAdmitClientRequest` and return responses as `tailcfg.DERPAdmitClientResponse`.

#### Scenario: Malformed or unparsable verify request
- **WHEN** `POST /verify` or `POST /verify/:relay` receives a body that cannot be parsed into `tailcfg.DERPAdmitClientRequest` or does not yield a valid `node_key`
- **THEN** the service returns a deny response with `Allow=false` and a non-empty deny reason

### Requirement: Verify endpoint allows authorized active devices
The system MUST return `Allow=true` only when the relay is known, the device exists, is not revoked, its owner user is enabled, and one of the owner's roles grants `connect` on that relay.

#### Scenario: Registered and authorized device is allowed
- **WHEN** `POST /verify/:relay` is called for a known relay and a registered active device whose owner is enabled and has a role granting that relay
- **THEN** the response contains `Allow=true` with no deny reason

### Requirement: Verify decision cache does not outlive lifecycle changes
When `VERIFY_CACHE_TTL` is greater than zero, the system MUST key cached decisions by relay and node key. It MUST drop cached decisions on device registration, revoke, enable or delete, on user disable, enable or delete, and on any role, grant, binding or relay change. It MUST NOT cache a decision computed before such a change. Propagation to other instances is defined in `policy-sync`.

#### Scenario: Device is revoked while an allow is cached
- **WHEN** a device has a cached allow decision and an admin revokes it
- **THEN** the next `POST /verify` for that node key returns `Allow=false` with `DenyReason="revoked"` without waiting for the cache TTL

#### Scenario: User is disabled while an allow is cached
- **WHEN** a device has a cached allow decision and an admin disables its owner
- **THEN** the next `POST /verify` for that node key returns `Allow=false` with `DenyReason="user disabled"` without waiting for the cache TTL

#### Scenario: Device is deleted while an allow is cached
- **WHEN** a device has a cached allow decision and an admin deletes it
- **THEN** the next `POST /verify` for that node key returns `Allow=false` with `DenyReason="not registered"` without waiting for the cache TTL

#### Scenario: Grant is removed while an allow is cached
- **WHEN** a device has a cached allow decision for relay `eu-1` and the only grant covering `eu-1` for its user's roles is removed
- **THEN** the next `POST /verify/eu-1` for that node key returns `Allow=false` with `DenyReason="policy denied"` without waiting for the cache TTL

#### Scenario: Decisions are cached per relay
- **WHEN** a node key has a cached allow for relay `default` and `POST /verify/eu-1` is called for it
- **THEN** the cached `default` decision is not used for `eu-1`

#### Scenario: Decision is computed while an invalidation happens
- **WHEN** a verify reads device or policy state, an invalidation happens, and the verify then tries to cache its decision
- **THEN** the decision is not cached
