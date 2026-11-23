## Purpose

Define the admin endpoints that manage who may connect to which relay: the relay registry, the role registry with each role's relay grants, and the binding of users to roles. This includes the naming rules and the protection of the built-in role and relay. The tier each route needs is defined in `admin-access-control`.

## ADDED Requirements

### Requirement: Role and relay names follow one format
Role and relay names MUST match `^[a-z0-9][a-z0-9-]{0,62}$`. A create request with a name that does not match MUST be rejected with HTTP `400`.

#### Scenario: Name is not valid
- **WHEN** `POST /admin/roles` or `POST /admin/relays` is called with a name such as `Ops`, `-ops`, `ops_team` or a name longer than 63 characters
- **THEN** the service returns HTTP `400` and creates nothing

#### Scenario: Name is valid
- **WHEN** `POST /admin/relays` is called with the name `eu-1`
- **THEN** the relay is created

### Requirement: Admin API manages relays
The system MUST provide `POST /admin/relays` with `name` and optional `description`, `GET /admin/relays`, and `DELETE /admin/relays/:name`. Deleting a relay MUST also remove every grant that names it. How a new relay starts is defined in "A role or relay created through the API starts clean". When a relay is deleted while another request grants a role on it, afterwards no grant MUST name a relay that is not registered.

#### Scenario: Relay is created
- **WHEN** `POST /admin/relays` is called with a new valid `name`
- **THEN** the service returns HTTP `201` with the relay's name, description and `createdAt`

#### Scenario: Relay is deleted while a role is granted on it
- **WHEN** `DELETE /admin/relays/eu-1` and `PUT /admin/roles/ops/relays` with `["eu-1"]` run concurrently
- **THEN** afterwards either relay `eu-1` is registered or no grant names `derp:eu-1`

#### Scenario: Relay name is taken
- **WHEN** `POST /admin/relays` is called with the name of an existing relay
- **THEN** the service returns HTTP `409` and creates nothing

#### Scenario: Relays are listed
- **WHEN** `GET /admin/relays` is called
- **THEN** the service returns HTTP `200` with a page of relays, paginated as defined in `admin-lifecycle-api`

#### Scenario: Relay is deleted
- **WHEN** `DELETE /admin/relays/:name` is called for an existing relay that is not built in
- **THEN** the service returns HTTP `200`, the relay no longer exists, no role keeps a grant naming it, and `POST /verify/<name>` is then denied with `unknown relay`

#### Scenario: Relay is unknown
- **WHEN** `DELETE /admin/relays/:name` is called with a name that matches no relay
- **THEN** the service returns HTTP `404`

### Requirement: Admin API manages roles and their grants
The system MUST provide `POST /admin/roles` with `name`, optional `description` and optional `relays`, `GET /admin/roles`, and `PUT /admin/roles/:name/relays` with `relays`, which replaces the role's grants. A `relays` entry is either the name of an existing relay or `*`, which means all relays and MUST be the only entry when present. How a new role starts is defined in "A role or relay created through the API starts clean".

#### Scenario: Role is created with grants
- **WHEN** `POST /admin/roles` is called with a new valid `name` and `relays` set to `["default"]`
- **THEN** the service returns HTTP `201` and the role is granted `connect` on relay `default`

#### Scenario: Role is created without grants
- **WHEN** `POST /admin/roles` is called without `relays`
- **THEN** the role is created with no grants, and users bound only to it are denied on every relay

#### Scenario: Role is granted all relays
- **WHEN** a role's `relays` is set to `["*"]`
- **THEN** users bound to that role are allowed on every relay in the registry

#### Scenario: Role name is taken
- **WHEN** `POST /admin/roles` is called with the name of an existing role
- **THEN** the service returns HTTP `409` and creates nothing

#### Scenario: Grant names an unknown relay
- **WHEN** `POST /admin/roles` or `PUT /admin/roles/:name/relays` has a `relays` entry that is neither `*` nor the name of an existing relay
- **THEN** the service returns HTTP `400` and changes nothing

#### Scenario: Wildcard mixed with relay names
- **WHEN** a `relays` list contains `*` together with any other entry
- **THEN** the service returns HTTP `400` and changes nothing

#### Scenario: Grants are replaced
- **WHEN** `PUT /admin/roles/:name/relays` is called for an existing role with a new `relays` list
- **THEN** the service returns HTTP `200` and the role's grants are exactly that list

#### Scenario: Roles are listed with their grants
- **WHEN** `GET /admin/roles` is called
- **THEN** the service returns HTTP `200` with a page of roles, paginated as defined in `admin-lifecycle-api`, each with its name, description, `createdAt` and `relays`

#### Scenario: Role is unknown
- **WHEN** `PUT /admin/roles/:name/relays` or `DELETE /admin/roles/:name` is called with a name that matches no role
- **THEN** the service returns HTTP `404`

### Requirement: A role or relay created through the API starts clean
`POST /admin/roles` MUST remove every leftover rule that names the new role as `role:<name>`, before it writes the requested grants. `POST /admin/relays` MUST remove every leftover grant that names the new relay as `derp:<name>`. Both MUST do so in the same transaction as the creation, and the admin audit row's summary MUST report how many rules were removed. This does not apply to the one-time upgrade's import.

#### Scenario: Role is created over leftover rules
- **WHEN** `casbin_rule` holds `g, user:<id>, role:ops` and `p, role:ops, derp:default, connect`, role `ops` is not registered, and `POST /admin/roles` is called with the name `ops` and no `relays`
- **THEN** the role is created with no grants and no bindings, both leftover rules no longer exist, the user is not bound to `ops`, and the admin audit row's summary reports two removed rules

#### Scenario: Relay is created over a leftover grant
- **WHEN** `casbin_rule` holds `p, role:ops, derp:eu-2, connect`, relay `eu-2` is not registered, and `POST /admin/relays` is called with the name `eu-2`
- **THEN** the relay is created, the leftover rule no longer exists, users bound to `ops` are denied on `POST /verify/eu-2`, and the admin audit row's summary reports one removed rule

#### Scenario: Upgrade import keeps existing rules
- **WHEN** the one-time upgrade adds role `ops` and relay `eu-1` to the registries from existing rules
- **THEN** no rule naming `role:ops` or `derp:eu-1` is removed

### Requirement: Deleting a role removes its grants and bindings
`DELETE /admin/roles/:name` MUST remove the role, its grants and every user binding to it, and MUST report how many bindings it removed. When a role is deleted while another request binds a user to it, creates a user bound to it or replaces its grants, afterwards no rule MUST name a role that is not registered.

#### Scenario: Role with bound users is deleted
- **WHEN** `DELETE /admin/roles/:name` is called for a role that is not built in and that three users are bound to
- **THEN** the service returns HTTP `200` with the count `3`, and none of those users is bound to the role

#### Scenario: Role is deleted while a user is bound to it
- **WHEN** `DELETE /admin/roles/ops` and `PUT /admin/users/:id/roles` with `["ops"]` run concurrently
- **THEN** afterwards either role `ops` is registered or no rule names `role:ops`

#### Scenario: Role is deleted while its grants are replaced
- **WHEN** `DELETE /admin/roles/ops` and `PUT /admin/roles/ops/relays` with `["default"]` run concurrently
- **THEN** afterwards either role `ops` is registered or no grant names `role:ops`

### Requirement: Built-in role and relay cannot be deleted
The relay `default` and the role `standard` MUST NOT be deletable. The grants of `standard` MUST remain editable.

#### Scenario: Deleting a built-in
- **WHEN** `DELETE /admin/relays/default` or `DELETE /admin/roles/standard` is called
- **THEN** the service returns HTTP `409` and nothing changes

#### Scenario: Editing the grants of standard
- **WHEN** `PUT /admin/roles/standard/relays` is called with a valid `relays` list
- **THEN** the grants of `standard` are replaced and the service returns HTTP `200`

### Requirement: Admin API replaces a user's roles
The system MUST provide `PUT /admin/users/:id/roles` with `roles`, which replaces the set of roles the user is bound to. An empty list removes every binding.

#### Scenario: Roles are replaced
- **WHEN** `PUT /admin/users/:id/roles` is called for an existing user with `roles` naming existing roles
- **THEN** the service returns HTTP `200` and the user is bound to exactly those roles

#### Scenario: Roles are cleared
- **WHEN** `PUT /admin/users/:id/roles` is called with `roles` set to `[]`
- **THEN** the user has no role bindings and the user's devices are denied with `policy denied`

#### Scenario: Unknown role
- **WHEN** `PUT /admin/users/:id/roles` has an entry that names no existing role
- **THEN** the service returns HTTP `400` and the user's bindings are unchanged

#### Scenario: User is unknown or malformed
- **WHEN** `PUT /admin/users/:id/roles` is called with an id that is not a UUID, or a UUID that matches no user
- **THEN** the service returns HTTP `400` for a malformed id and HTTP `404` for an unknown one
