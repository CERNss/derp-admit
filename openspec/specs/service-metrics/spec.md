# service-metrics Specification

## Purpose
Define the operational metrics the service exposes for scraping: the endpoint and its switch, the series it must carry for verify, registration, admin, rate limiting, cache and policy sync, and the label rules that keep identities out of labels and label cardinality bounded.

## Requirements

### Requirement: Metrics endpoint is served on the main listener
When `METRICS_ENABLED` is true (the default), the system MUST serve `GET /metrics` in the Prometheus text exposition format on the main listener, without authentication. When it is false, `GET /metrics` MUST return HTTP `404`.

#### Scenario: Metrics enabled by default
- **WHEN** the service starts without `METRICS_ENABLED` and `GET /metrics` is called without credentials
- **THEN** the service returns HTTP `200` with a body in the Prometheus text exposition format

#### Scenario: Metrics disabled
- **WHEN** the service starts with `METRICS_ENABLED=false` and `GET /metrics` is called
- **THEN** the service returns HTTP `404`

#### Scenario: Metrics setting is not a boolean
- **WHEN** configuration is loaded with `METRICS_ENABLED` set to a value that does not parse as a boolean
- **THEN** configuration loading fails with an error

### Requirement: Metrics cover verify, registration, admin and rate limiting
The metrics MUST include: a counter of verify decisions labelled by relay, allowed and deny reason; a counter of register outcomes labelled by HTTP status; a counter of admin requests labelled by tier and HTTP status class; and a counter of rate-limit rejections labelled by endpoint (`verify`, `register`, `admin`).

#### Scenario: Verify decision is counted
- **WHEN** `POST /verify/default` is denied with `revoked`
- **THEN** the verify decision counter for relay `default`, allowed `false` and reason `revoked` increases by one

#### Scenario: Unauthenticated admin request is counted
- **WHEN** an `/admin` request fails authentication with HTTP `401`
- **THEN** the admin request counter for status class `4xx` increases by one, with a tier label value that names no tier

#### Scenario: Rate-limit rejection is counted
- **WHEN** a `POST /register` request is rejected with HTTP `429`
- **THEN** the rate-limit rejection counter for endpoint `register` increases by one

### Requirement: Metrics cover the verify cache and policy sync
The metrics MUST include verify cache hits and misses, the current policy version, the time of the last successful policy sync check, and counts of policy reloads and of failed sync checks or reloads.

#### Scenario: Cache hit is counted
- **WHEN** `VERIFY_CACHE_TTL` is greater than zero and a `/verify` decision is served from the cache
- **THEN** the cache hit counter increases by one

#### Scenario: Sync failure is visible
- **WHEN** a policy version check fails
- **THEN** the sync failure count increases and the last-successful-sync time does not advance

### Requirement: Metric labels carry no identities and are bounded
Metric labels MUST NOT contain node keys, user ids, device ids, admin key ids or admin key names. The relay label MUST be a relay name from the registry; any relay name that is not in the registry, or is malformed, MUST be labelled `unknown`.

#### Scenario: Unknown relay is labelled unknown
- **WHEN** `POST /verify/does-not-exist` and `POST /verify/Bad_Name` are called
- **THEN** both decisions are counted with relay label `unknown`, and no series has a relay label of `does-not-exist` or `Bad_Name`

#### Scenario: Plain verify is labelled default
- **WHEN** `POST /verify` is called without a relay segment
- **THEN** the decision is counted with relay label `default`
