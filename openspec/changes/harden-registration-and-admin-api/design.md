## Context

The verifier decides which devices may use a private DERP relay. Before commit `c565b78`, users, enroll tokens and device revocations could only be managed with SQL, registration had check-then-act races, and the optional verify cache could keep serving an allow after a revoke. That commit closed those gaps. This document records the decisions it made, as read from the code.

## Goals / Non-Goals

**Goals:**
- Record the shipped behaviour of the admin API, registration hardening and verify cache accurately enough to be the main spec.
- Record the trade-offs the implementation chose, including the ones still open.

**Non-Goals:**
- Changing any behaviour. Open questions are listed for the owner to decide and are not resolved here.

## Decisions

### 1) Admin API is opt-in and uses one static bearer key
- Decision: `/admin` routes are mounted only when `ADMIN_API_KEY` is set; a configured key shorter than 16 characters fails startup. Requests authenticate with `Authorization: Bearer <key>`, compared in constant time.
- Rationale: A deployment that does not set a key exposes no admin surface at all, and provisioning by SQL keeps working.

### 2) Admin rate limiting runs before authentication, on one shared bucket
- Decision: A single token bucket (`ADMIN_RATE_LIMIT_RPS`, `ADMIN_RATE_LIMIT_BURST`) throttles every `/admin` request before the key is checked.
- Rationale: The key cannot be guessed faster than the bucket allows, whatever number of source addresses is used.
- Trade-off: Unauthenticated traffic and legitimate admin calls draw from the same bucket. See Open Questions.

### 3) Register rate limiting is per client IP
- Decision: `POST /register` uses an independent token bucket per client IP. The router trusts no proxy headers, so the client IP is the TCP peer address. The limiter tracks at most 10000 addresses and sheds half when full.
- Rationale: One abusive client exhausts only its own budget, and the budget cannot be reset by spoofing `X-Forwarded-For`.
- Trade-off: Behind a reverse proxy every client shares the proxy's address and therefore one bucket.

### 4) Registration is one transaction with re-validation on locked rows
- Decision: After a cheap pre-check, registration locks the token and user rows (`SELECT ... FOR UPDATE` on Postgres), re-checks revoked, expired and disabled state, checks the device limit, and creates or updates the device, all in one transaction. sqlite is opened with `_txlock=immediate` so write transactions queue instead of failing with `SQLITE_BUSY`.
- Rationale: A revoke or disable that lands between the pre-check and the write can no longer produce an enrolled device, and concurrent registrations cannot exceed `max_devices`.

### 5) Node keys are canonicalized through Tailscale's key type
- Decision: `/register` parses the supplied node key as a Tailscale node public key and stores its canonical string. `/verify` derives the key from `tailcfg.DERPAdmitClientRequest.NodePublic` in the same form.
- Rationale: A key registered in a non-canonical spelling would never match at verify time.

### 6) Enroll tokens default to one device
- Decision: `POST /admin/tokens` treats an omitted `maxDevices` as `1`. `0` means unlimited and must be sent explicitly.
- Rationale: A leaked token minted with defaults cannot enroll an unbounded number of devices.

### 7) Verify cache invalidation uses an epoch
- Decision: Every invalidation increments a cache-wide epoch. A verify snapshots the epoch before reading the database and passes it when storing its decision; the store is dropped if the epoch moved. The cache holds at most 50000 entries and evicts in bounded batches.
- Rationale: A decision computed from pre-revoke state cannot be cached after the revoke, and a flood of unknown node keys cannot grow the cache without limit.
- Trade-off: An invalidation for one key discards in-flight stores for every key. This costs a cache miss, never a wrong decision.

## Risks / Trade-offs

- Shared admin bucket can be exhausted by unauthenticated requests -> the admin API returns `429` to its legitimate caller until the bucket refills. `/verify` and `/register` are not affected.
- Static bearer key with no rotation or per-caller identity -> admin actions are not attributable to a person.
- Admin mutations are not written to an audit log -> only verify decisions are audited.

## Open Questions

- Should a revoked device be reactivated by `POST /register`? The original enrollment spec requires it, and the code still does it. Now that `POST /admin/devices/:id/enable` exists, anyone holding a valid token for the same user can undo an admin's device revocation unless the token is revoked as well. Options: keep as is and document that a revoke must be paired with a token revoke; or make `/register` refuse revoked devices and leave re-enabling to the admin API.
- Should the pre-auth admin limiter be per client IP, like the register limiter, so unauthenticated traffic cannot starve authenticated admin calls?
