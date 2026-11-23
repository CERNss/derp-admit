## ADDED Requirements

### Requirement: Authorization target is the requested relay
The system MUST evaluate verifier authorization using object `derp:<relay>` and action `connect`, where `<relay>` is the relay the verify request names (see `derp-client-verification`).

#### Scenario: Named relay
- **WHEN** `POST /verify/eu-1` reaches policy enforcement
- **THEN** the policy is evaluated with object `derp:eu-1` and action `connect`

#### Scenario: Plain verify
- **WHEN** `POST /verify` reaches policy enforcement
- **THEN** the policy is evaluated with object `derp:default` and action `connect`

### Requirement: Authorization subject is the device's owner user
The system MUST resolve the device to its owner from the `devices` table and MUST enforce subject `user:<user_id>`. Rules with a `device:<node_key>` subject MUST NOT affect a decision.

#### Scenario: Two devices of one user
- **WHEN** two active devices belong to the same enabled user and that user's role grants relay `default`
- **THEN** `POST /verify` allows both devices

#### Scenario: Device moved by deletion and re-enrolment
- **WHEN** a device is deleted and its node key is enrolled again for another user
- **THEN** the decision for that node key follows the roles of the new owner

### Requirement: Access is granted to roles and only allows
A role MUST be grantable `connect` on named relays or on all relays (`*`). A user MUST be allowed on a relay only when at least one of the user's roles has a grant covering it. There MUST be no grants to users directly and no deny rules.

#### Scenario: Role covers the relay
- **WHEN** a user is bound to a role granted relay `eu-1`
- **THEN** the user's active devices are allowed on `POST /verify/eu-1`

#### Scenario: Role does not cover the relay
- **WHEN** a user's only role is granted relay `default` and not `eu-1`
- **THEN** `POST /verify/eu-1` for the user's device returns `Allow=false` with `DenyReason="policy denied"`

#### Scenario: Wildcard grant
- **WHEN** a user is bound to a role granted `*`
- **THEN** the user's active devices are allowed on every relay in the registry

#### Scenario: Several roles
- **WHEN** a user is bound to one role granted `default` and another granted `eu-1`
- **THEN** the user's devices are allowed on both relays

### Requirement: A user without a role is denied
A user with no role binding MUST be denied on every relay with `DenyReason="policy denied"`. This MUST also hold for a user row that was inserted directly into the database after the upgrade.

#### Scenario: SQL-provisioned user with no binding
- **WHEN** a user is inserted by SQL after the one-time upgrade has run, a device is registered for that user, and the device calls `POST /verify`
- **THEN** the response contains `Allow=false` and `DenyReason="policy denied"`

### Requirement: Registration writes no policy rules
`POST /register` MUST NOT create, change or remove any policy rule or role binding.

#### Scenario: Device is registered
- **WHEN** `POST /register` succeeds for a new node key
- **THEN** no policy rule or role binding was added, changed or removed

### Requirement: Built-in relay and role are seeded at startup
At every startup the system MUST ensure, idempotently, that relay `default` exists and that role `standard` exists. It MUST grant `standard` `connect` on `default` only when it creates `standard`, so that edited grants of `standard` are kept on restart.

#### Scenario: First start
- **WHEN** the service starts on an empty database
- **THEN** relay `default` and role `standard` exist, and `standard` is granted `connect` on `default`

#### Scenario: Restart
- **WHEN** the service restarts
- **THEN** there is still exactly one relay `default`, one role `standard`, and at most one grant of `standard` on `default`

#### Scenario: Edited grants of standard are kept
- **WHEN** the grants of `standard` were replaced with `["eu-1"]` and the service restarts
- **THEN** `standard` is still granted only `eu-1`

### Requirement: Policy is always enforced
The system MUST always enforce policy. A leftover `ENABLE_CASBIN` setting from any configuration source MUST be ignored for enforcement whatever its value, including one that does not parse, and MUST produce a startup warning. Its only remaining use is as input to the one-time upgrade.

#### Scenario: ENABLE_CASBIN=false is still configured
- **WHEN** the service starts with `ENABLE_CASBIN=false` in the environment, `.env` or `enable_casbin: false` in `config.yaml`
- **THEN** startup succeeds, a warning says the setting is ignored, and `/verify` enforces policy

#### Scenario: ENABLE_CASBIN has an unparsable value
- **WHEN** the service starts with `ENABLE_CASBIN=maybe`
- **THEN** startup succeeds with the same warning

### Requirement: Existing policy data is upgraded once per database
On the first start of this version against a database, the system MUST run a one-time upgrade in one transaction, on sqlite and Postgres, and MUST record a durable marker so it never runs again. The upgrade MUST NOT delete any existing `casbin_rule` row.

#### Scenario: Existing device to user to standard rules
- **WHEN** a database has `p, role:standard, derp:default, connect`, `g, device:<node_key>, user:<user_id>` and `g, user:<user_id>, role:standard` for a user with an active device, and this version starts with policy enforced before the upgrade
- **THEN** all three rules are kept unchanged, the device is not revoked, and `POST /verify` for that device still returns `Allow=true`

#### Scenario: Upgrade does not run again
- **WHEN** after the upgrade a user is set to no roles, or a user is inserted by SQL without a binding, and the service restarts
- **THEN** that user is still not bound to any role and no device is revoked

### Requirement: One-time upgrade never loosens access
No device that `POST /verify` denied immediately before the one-time upgrade MUST be allowed by it immediately after. A user is covered on `default` when, after the role and relay import, the user has a `g, user:<id>, role:<name>` binding to a registered role with a managed grant on `default`. Policy counts as enforced before unless `ENABLE_CASBIN=false` or `enable_casbin: false` is in effect on the upgrading instance.

#### Scenario: Deployment that ran with ENABLE_CASBIN=false
- **WHEN** the first start of this version runs with `ENABLE_CASBIN=false` still configured
- **THEN** every user who is not covered on `default` is bound to `standard`, `standard` is granted `default`, and every device allowed before is still allowed on `POST /verify`

#### Scenario: Not enforced, user bound only to a role without a grant on default
- **WHEN** policy was not enforced before the upgrade and a user's only binding is to a role that has no grant on `default`
- **THEN** the upgrade also binds the user to `standard`, and the user's active devices are still allowed on `POST /verify`

#### Scenario: Enforced, user not covered and without devices
- **WHEN** policy was enforced before the upgrade and a user is not covered on `default` and has no device rows
- **THEN** the upgrade binds the user to `standard`

#### Scenario: Enforced, user not covered but with devices
- **WHEN** policy was enforced before the upgrade and a user is not covered on `default` and has device rows
- **THEN** the user's bindings are left as they are, the user is reported, and the user's devices are still denied with `policy denied`

#### Scenario: Enforced, user bound only to a role without a grant on default
- **WHEN** policy was enforced before the upgrade, a user's only binding is to a role that has no grant on `default`, and the user has device rows
- **THEN** the user is left as is and reported, and the user's devices are still denied on `POST /verify`

#### Scenario: Enforced, covered user's device without legacy device rule
- **WHEN** policy was enforced before the upgrade, a user is covered on `default`, and one of the user's non-revoked devices has no `g, device:<node_key>, user:<owner id>` rule naming that user
- **THEN** the upgrade sets the device's `revoked_at` and reports it, so `POST /verify` denies it with `revoked`, and an admin can re-enable it with `POST /admin/devices/:id/enable`

#### Scenario: ENABLE_CASBIN removed before the first start
- **WHEN** a deployment that ran with `ENABLE_CASBIN=false` removes the setting before the first start of this version
- **THEN** the upgrade treats policy as enforced before the upgrade and applies the enforced rules

### Requirement: One-time upgrade keeps unregistered devices denied on every relay
When policy was enforced before the upgrade, the upgrade MUST revoke and report every non-revoked device that has no `g, device:<node_key>, user:<owner id>` rule naming its owner, whenever that owner, after the import, has a managed binding to a role with a grant on any relay, named or all relays. Devices of a user with no such grant MUST be left as they are. A device that was never properly registered therefore stays denied on every relay, not only on `default`.

#### Scenario: Enforced, user covered only on another relay, device without legacy device rule
- **WHEN** policy was enforced before the upgrade, a user's only binding is `g, user:<id>, role:ops`, the only grant of `ops` is `p, role:ops, derp:eu-1, connect`, and one of the user's non-revoked devices has no `g, device:<node_key>, user:<owner id>` rule naming that user
- **THEN** the upgrade sets the device's `revoked_at` and reports it, so `POST /verify/eu-1` denies it with `revoked`; the user's bindings are left as they are and the user is reported as not covered on `default`

#### Scenario: Enforced, user without any grant keeps devices without legacy device rule
- **WHEN** policy was enforced before the upgrade, a user has no managed binding to a role with a grant on any relay, and one of the user's non-revoked devices has no legacy device rule
- **THEN** the upgrade does not revoke that device

### Requirement: One-time upgrade imports roles and relays from existing rules
The upgrade MUST add to the role registry every name that matches the role name format and appears in a `g, user:<uuid>, role:<name>` or `p, role:<name>, derp:<relay>, connect` rule. It MUST add to the relay registry every relay name that matches the name format in such a `p` rule. Those rules then keep working.

#### Scenario: Custom role on the default relay
- **WHEN** a database has `g, device:<node_key>, user:<user_id>`, `g, user:<user_id>, role:ops` and `p, role:ops, derp:default, connect` for an active device, and the upgrade runs with policy enforced before
- **THEN** role `ops` exists in the registry with a grant on `default`, and `POST /verify` for that device still returns `Allow=true`

#### Scenario: Grant on another relay
- **WHEN** a database has `p, role:ops, derp:eu-1, connect`
- **THEN** after the upgrade relay `eu-1` exists in the registry and `ops` is granted `eu-1`

### Requirement: Rules outside the managed shapes grant nothing
Under the new model, a `casbin_rule` row that is not a `g, user:<uuid>, role:<name>` binding or a `p, role:<name>, derp:<relay>, connect` grant with valid names MUST NOT allow any request at any time. This includes direct `p` rules on `user:` or `device:` subjects, other actions, invalid names, other grouping shapes, and a rule that existed before the upgrade with object `derp:*`. The upgrade MUST leave such rows in place.

#### Scenario: Device allowed only by a direct rule
- **WHEN** before the upgrade a device was allowed only through `p, device:<node_key>, derp:default, connect`, and the upgrade runs
- **THEN** the rule stays in the table, `POST /verify` for that device returns `Allow=false` with `DenyReason="policy denied"`, the upgrade warning includes the rule in its count of unmanaged rules, and the device is not listed in the warning

#### Scenario: Role inheritance between roles
- **WHEN** a database has `g, role:a, role:b`
- **THEN** the rule stays in the table and does not give users bound to `a` any grant of `b`

### Requirement: One-time upgrade reports what it restricted
The upgrade MUST log one warning with the ids and count of users it left not covered on `default`, the ids and count of devices it revoked, and the count of rules that grant nothing under the new model. It is not required to list devices that lose access only because rules outside the managed shapes stop granting. Each revocation MUST be audited as described in `admin-audit-logging`.

#### Scenario: Upgrade leaves users not covered and revokes devices
- **WHEN** the upgrade leaves two users not covered on `default` and revokes one device
- **THEN** one warning lists both user ids and the device id with their counts, and one admin audit row with actor `system` records the revocation

### Requirement: Legacy device rules are removed with their device or user
Legacy `g, device:<node_key>, user:<user_id>` rules MUST grant nothing under the new model. The system MUST remove such a rule only when its device, or the device's user, is deleted.

#### Scenario: Device is deleted
- **WHEN** a device that has a legacy device rule is deleted through `DELETE /admin/devices/:id`
- **THEN** its legacy device rule no longer exists

#### Scenario: User is deleted
- **WHEN** a user whose devices have legacy device rules is deleted through `DELETE /admin/users/:id`
- **THEN** none of those legacy device rules exists

#### Scenario: Revoke keeps the rule
- **WHEN** a device that has a legacy device rule is revoked
- **THEN** the legacy device rule is kept

## MODIFIED Requirements

### Requirement: Policy deny is returned as verify deny reason
The system MUST deny verify requests that fail policy enforcement even when relay, registration and lifecycle checks pass.

#### Scenario: Policy denied
- **WHEN** `POST /verify/<relay>` reaches policy enforcement and no role of subject `user:<user_id>` grants `connect` on `derp:<relay>`
- **THEN** the response contains `Allow=false` and `DenyReason="policy denied"`

## REMOVED Requirements

### Requirement: Authorization target is fixed for single-region DERP
**Reason**: Each derper now names its relay, and the object is `derp:<relay>` (owner answer 1, decisions A1 and B1). Replaced by "Authorization target is the requested relay".
**Migration**: Derpers that call `/verify` are evaluated against `derp:default`, as before. The baseline rule `p, role:standard, derp:default, connect` keeps its format and stays valid.

### Requirement: Device authorization uses Casbin RBAC relationships
**Reason**: Policy subjects are users, not devices (decision A2), and registration no longer writes rules. Replaced by "Authorization subject is the device's owner user", "Registration writes no policy rules" and "Existing policy data is upgraded once per database".
**Migration**: The one-time upgrade keeps every existing rule. `g, device:<node_key>, user:<user_id>` rules grant nothing under the new model and are removed only when their device or user is deleted. `g, user:<user_id>, role:<name>` and `p, role:<name>, derp:<relay>, connect` rules keep their format and keep working.

### Requirement: Concurrent first starts upgrade exactly once
When several instances of this version start at the same time against one database, schema migration, seeding of built-ins and the one-time upgrade MUST each take effect exactly once, and every instance MUST start successfully. This does not make mixed-version operation supported.

#### Scenario: Two instances start together on a fresh upgrade
- **WHEN** two instances of this version start at the same time against a database that has not been upgraded
- **THEN** both start successfully, there is one relay `default`, one role `standard`, one upgrade marker, and each upgrade revocation and its `system` audit row exist once
