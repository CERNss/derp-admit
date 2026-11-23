## ADDED Requirements

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
