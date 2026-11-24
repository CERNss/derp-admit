## MODIFIED Requirements

### Requirement: Verify endpoint consumes DERP admit request contract
The system MUST provide `POST /verify` and `POST /verify/:relay`, which, for every caller that passes the caller allowlist (see "Verify callers can be restricted by peer address"), parse request bodies as `tailcfg.DERPAdmitClientRequest` and return responses as `tailcfg.DERPAdmitClientResponse`. A caller refused by the allowlist gets HTTP `403` with a small JSON body that is not a `tailcfg.DERPAdmitClientResponse`, and its body is not read.

#### Scenario: Malformed or unparsable verify request
- **WHEN** `POST /verify` or `POST /verify/:relay` receives, from a caller that passes the allowlist, a body that cannot be parsed into `tailcfg.DERPAdmitClientRequest` or does not yield a valid `node_key`
- **THEN** the service returns a deny response with `Allow=false` and a non-empty deny reason

#### Scenario: Caller refused by the allowlist
- **WHEN** `VERIFY_ALLOWED_CIDRS` is set and `POST /verify` comes from a peer outside it
- **THEN** the service returns HTTP `403` with a JSON body that has no `Allow` field

### Requirement: Unknown relay is denied
For a caller that passes the caller allowlist, a verify request whose relay name is not in the relay registry, or is not a valid relay name, MUST be denied with HTTP `200` in the `tailcfg.DERPAdmitClientResponse` format, with `Allow=false` and `DenyReason="unknown relay"`, and MUST be audited. A caller refused by the allowlist gets HTTP `403` and no audit row, whatever relay it names.

#### Scenario: Relay does not exist
- **WHEN** `POST /verify/does-not-exist` is called by a caller that passes the allowlist with a valid admit request for an active, authorized device
- **THEN** the service returns HTTP `200` with `Allow=false` and `DenyReason="unknown relay"`, and an audit row records the decision

#### Scenario: Relay name is malformed
- **WHEN** `POST /verify/Bad_Name` is called by a caller that passes the allowlist with a valid admit request
- **THEN** the service returns HTTP `200` with `Allow=false` and `DenyReason="unknown relay"`

#### Scenario: Unknown relay from a refused caller
- **WHEN** `VERIFY_ALLOWED_CIDRS` is set and `POST /verify/does-not-exist` comes from a peer outside it
- **THEN** the service returns HTTP `403` and writes no audit row

### Requirement: An empty relay or a relay containing a slash is malformed
For a caller that passes the caller allowlist, an empty relay segment (`POST /verify/`) and a relay segment that contains `/`, whether literal (`POST /verify/a/b`) or encoded (`POST /verify/a%2Fb`), MUST be treated as a malformed relay name: the deny response of "Unknown relay is denied", audited with a null relay. The service MUST NOT redirect `/verify/` to `/verify`. Only `POST /verify` with no relay segment means relay `default`. A caller refused by the allowlist gets HTTP `403` on these paths too, without a redirect and without an audit row.

#### Scenario: Empty relay segment
- **WHEN** `POST /verify/` is called by a caller that passes the allowlist with a valid admit request for an active device whose user has role `standard` with its built-in grant
- **THEN** the service returns HTTP `200` with `Allow=false` and `DenyReason="unknown relay"`, without a redirect, and the audit row's relay is null

#### Scenario: Relay segment contains a slash
- **WHEN** `POST /verify/a/b` or `POST /verify/a%2Fb` is called by a caller that passes the allowlist with a valid admit request
- **THEN** the service returns HTTP `200` with `Allow=false` and `DenyReason="unknown relay"`, and the audit row's relay is null

#### Scenario: Malformed relay from a refused caller
- **WHEN** `VERIFY_ALLOWED_CIDRS` is set and `POST /verify/` or `POST /verify/a/b` comes from a peer outside it
- **THEN** the service returns HTTP `403`, without a redirect and without an audit row

### Requirement: Verify checks run in a fixed order
The system MUST evaluate a verify request in this order and MUST return the first failing check's result: caller allowlist when `VERIFY_ALLOWED_CIDRS` is set (HTTP `403`, not an admit response), verify rate limit (`rate limited`), parse the request (`invalid request`), policy sync is fresh (`internal error`), relay is known (`unknown relay`), device is registered (`not registered`), device is not revoked (`revoked`), owner user is not disabled (`user disabled`), policy allows (`policy denied`).

#### Scenario: Unknown relay and unregistered device
- **WHEN** `POST /verify/does-not-exist` is called for a node key that is not registered
- **THEN** the deny reason is `unknown relay`

#### Scenario: Revoked device of a disabled user
- **WHEN** `POST /verify` is called for a revoked device whose owner is disabled
- **THEN** the deny reason is `revoked`

#### Scenario: Malformed body on an unknown relay
- **WHEN** `POST /verify/does-not-exist` is called with a body that is not a valid admit request
- **THEN** the deny reason is `invalid request`

#### Scenario: Refused caller with an exhausted rate limit
- **WHEN** `VERIFY_ALLOWED_CIDRS` is set, the verify rate limit is exhausted, and `POST /verify` comes from a peer outside the list
- **THEN** the service returns HTTP `403`, not a `rate limited` deny

### Requirement: Relay name is trusted as asserted by the caller
`/verify` MUST NOT authenticate its caller. The caller allowlist (`VERIFY_ALLOWED_CIDRS`) is a filter on the network peer address only; it is not authentication and does not tie a relay name to a peer. The relay name selects which policy is evaluated. It keeps a role from being used on the wrong relay when each derper is configured with its own relay URL. It does not stop a derper operator, or any caller the allowlist admits, from pointing a relay at a more permissive relay name.

#### Scenario: Caller names a different relay
- **WHEN** a caller sends an admit request to `POST /verify/eu-1` for a device whose user's roles grant only `eu-1`
- **THEN** the decision is evaluated for `eu-1` and allowed, whichever derper sent it

#### Scenario: Allowed peer names another relay
- **WHEN** `VERIFY_ALLOWED_CIDRS` lists the addresses of two derpers and the derper configured for `us-1` sends an admit request to `POST /verify/eu-1`
- **THEN** the decision is evaluated for `eu-1`, as for any caller the allowlist admits

## ADDED Requirements

### Requirement: Verify callers can be restricted by peer address
When `VERIFY_ALLOWED_CIDRS` is set, the system MUST answer `POST /verify` and `POST /verify/:relay` from a TCP peer address outside the list with HTTP `403` and a small JSON body, outside the `tailcfg.DERPAdmitClientResponse` contract. This check MUST run before the verify rate limit and before any other check. When the setting is unset or empty, every caller MUST be accepted as before.

#### Scenario: Allowed peer
- **WHEN** `VERIFY_ALLOWED_CIDRS` is `10.0.0.0/8` and `POST /verify` and `POST /verify/eu-1` are called from peer `10.1.2.3`
- **THEN** both requests are evaluated as usual and return HTTP `200` with a `tailcfg.DERPAdmitClientResponse`

#### Scenario: Peer outside the list
- **WHEN** `VERIFY_ALLOWED_CIDRS` is `10.0.0.0/8` and `POST /verify` or `POST /verify/eu-1` is called from peer `192.0.2.1`
- **THEN** the service returns HTTP `403` with a JSON body, and evaluates nothing

#### Scenario: Setting unset
- **WHEN** `VERIFY_ALLOWED_CIDRS` is unset or empty and `POST /verify` is called from any peer
- **THEN** the request is evaluated as usual

### Requirement: Caller allowlists match only the TCP peer address
Caller allowlist matching MUST use only the TCP peer address of the connection. `X-Forwarded-For`, `X-Real-IP` and similar headers MUST NOT be consulted. An IPv4-mapped IPv6 peer address MUST be unmapped before matching. When a list is set, a peer address that cannot be parsed MUST be rejected.

#### Scenario: Spoofed header naming an allowed address
- **WHEN** `VERIFY_ALLOWED_CIDRS` is `10.0.0.0/8` and peer `192.0.2.1` calls `POST /verify` with `X-Forwarded-For: 10.0.0.5`
- **THEN** the service returns HTTP `403`

#### Scenario: Header naming a disallowed address
- **WHEN** `VERIFY_ALLOWED_CIDRS` is `10.0.0.0/8` and peer `10.0.0.5` calls `POST /verify` with `X-Forwarded-For: 192.0.2.1` and `X-Real-IP: 192.0.2.1`
- **THEN** the request is evaluated as usual

#### Scenario: IPv4-mapped IPv6 peer
- **WHEN** `VERIFY_ALLOWED_CIDRS` is `10.0.0.0/8` and `POST /verify` arrives from peer `::ffff:10.0.0.5`
- **THEN** the request is evaluated as usual

#### Scenario: Unparsable peer address
- **WHEN** `VERIFY_ALLOWED_CIDRS` is set and the peer address of a `POST /verify` request cannot be parsed as an IP address
- **THEN** the service returns HTTP `403`

### Requirement: A rejected verify caller leaves no trace in admission state
A verify caller rejected by `VERIFY_ALLOWED_CIDRS` MUST NOT consume a token from the verify rate limit, MUST NOT write an audit row, and MUST NOT be counted as a verify decision. The rejection MUST be logged at warn level with the peer IP and counted per endpoint.

#### Scenario: Outsider cannot drain the verify rate limit
- **WHEN** the verify rate limit has burst `1` and a negligible refill rate, many `POST /verify` requests from a peer outside `VERIFY_ALLOWED_CIDRS` are rejected, and then one request comes from an allowed peer
- **THEN** the allowed request is evaluated and not answered with `rate limited`

#### Scenario: Rejected caller is not audited
- **WHEN** a `POST /verify` request is rejected by `VERIFY_ALLOWED_CIDRS`
- **THEN** no `audit_logs` row is written and the verify decision counter does not change, and the caller rejection counter for endpoint `verify` increases by one

### Requirement: Allowlist state is logged at startup
At startup the system MUST log one info-level line for the verify allowlist and, when metrics are enabled, one for the metrics allowlist: the number of entries when the list is set, or a line saying that any peer may call `/verify` (or read `/metrics`) when it is unset. An unset list MUST NOT be logged as a warning.

#### Scenario: Lists unset
- **WHEN** the service starts with `VERIFY_ALLOWED_CIDRS` and `METRICS_ALLOWED_CIDRS` unset and metrics enabled
- **THEN** it logs at info level that any peer may call `/verify` and that any peer may read `/metrics`

#### Scenario: Lists set
- **WHEN** the service starts with `VERIFY_ALLOWED_CIDRS` holding two entries and `METRICS_ALLOWED_CIDRS` holding one
- **THEN** it logs at info level that the verify allowlist has 2 entries and the metrics allowlist has 1

#### Scenario: Metrics disabled
- **WHEN** the service starts with `METRICS_ENABLED=false`
- **THEN** no metrics allowlist line is logged

### Requirement: Other endpoints are not restricted by caller allowlists
The caller allowlists MUST NOT affect `/healthz`, `/readyz`, `/register`, `/admin/*` or `/`.

#### Scenario: Health, registration and admin from a disallowed peer
- **WHEN** `VERIFY_ALLOWED_CIDRS` and `METRICS_ALLOWED_CIDRS` are both `10.0.0.0/8` and peer `192.0.2.1` calls `GET /healthz`, `GET /readyz`, `GET /`, `POST /register` with a valid enroll token, and `GET /admin/users` with a valid admin key
- **THEN** each returns its usual response: `200` for each of them
