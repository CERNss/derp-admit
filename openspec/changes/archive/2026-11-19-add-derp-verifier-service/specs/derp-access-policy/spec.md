## ADDED Requirements

### Requirement: Authorization target is fixed for single-region DERP
The system MUST evaluate verifier authorization using object `derp:default` and action `connect`.

#### Scenario: Verify policy evaluation target
- **WHEN** `POST /verify` executes authorization for a device subject
- **THEN** the policy engine is called with object `derp:default` and action `connect`

### Requirement: Device authorization uses Casbin RBAC relationships
The system MUST represent and evaluate access using Casbin subjects `device:<node_key>`, `user:<user_id>`, and role inheritance.

#### Scenario: Device registration establishes grouping links
- **WHEN** `POST /register` successfully binds a device to a user
- **THEN** Casbin grouping rules include `g, device:<node_key>, user:<user_id>` and `g, user:<user_id>, role:standard`

#### Scenario: Baseline connect policy exists
- **WHEN** verifier starts or policy bootstrap runs
- **THEN** Casbin includes policy `p, role:standard, derp:default, connect` exactly once in an idempotent way

### Requirement: Policy deny is returned as verify deny reason
The system MUST deny verify requests that fail Casbin enforcement even when registration and lifecycle checks pass.

#### Scenario: Policy denied
- **WHEN** `POST /verify` reaches policy enforcement and Casbin returns false for subject `device:<node_key>` on `derp:default/connect`
- **THEN** the response contains `Allow=false` and `DenyReason="policy denied"`
