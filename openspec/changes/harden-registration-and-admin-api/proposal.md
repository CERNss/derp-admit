## Why

Commit `c565b78` hardened registration, added an authenticated admin API and fixed verify-cache races, but it was implemented without an OpenSpec change. The main specs therefore still describe the service as it was before that work. This change documents the behaviour that commit shipped so the specs match the code again.

This is a retroactive record. Every statement here is taken from the code and tests at `c565b78`; nothing new is proposed.

## What Changes

- Add an `/admin` lifecycle API for users, enroll tokens and devices, mounted only when `ADMIN_API_KEY` is set, authenticated with a bearer key and rate limited before the key check.
- Rate limit `POST /register` per client IP and reject oversized request bodies with `413`.
- Canonicalize node keys at registration so stored identities match what derper sends to `/verify`.
- Make registration transactional: token and user state are re-validated on locked rows, the device limit is checked inside the transaction, and losers of a same-node-key race get `409` instead of `500`.
- Count the reactivation of a revoked device against the token's device limit.
- Make the verify decision cache safe: bounded size, and decisions computed before a revoke, disable or registration are never cached past it.
- Serve HTTP through `http.Server` with timeouts and graceful shutdown, and open sqlite with `_txlock=immediate`.

## Capabilities

### New Capabilities
- `admin-lifecycle-api`: Authenticated HTTP API for provisioning users, minting and revoking enroll tokens, and revoking or re-enabling devices.

### Modified Capabilities
- `device-enrollment`: Adds per-IP rate limiting, body size limits, node key canonicalization and concurrency guarantees; extends the device limit to reactivations.
- `derp-client-verification`: Adds requirements for the verify decision cache.

## Impact

- Affected code: `server` (router, admin routes, rate limiter), `service` (registration, admin operations, verify cache), `derp` (request parsing), `db` (sqlite DSN, error translation), `config`, `cmd/derp_admit`.
- New configuration: `ADMIN_API_KEY`, `ADMIN_RATE_LIMIT_RPS`, `ADMIN_RATE_LIMIT_BURST`, `REGISTER_RATE_LIMIT_RPS`, `REGISTER_RATE_LIMIT_BURST`.
- Behaviour change for API callers: `POST /register` can now return `413`, `429`, and `400` for a node key that is not a valid Tailscale node public key.
