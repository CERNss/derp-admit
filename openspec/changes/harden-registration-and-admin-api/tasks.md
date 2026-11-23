These tasks record work already shipped in commit `c565b78`, except 5.3, which also needed the dependency fix in `e72dfe0`. The last group is the review this retroactive change still needs.

## 1. Admin API

- [x] 1.1 Add `ADMIN_API_KEY` and admin rate limit settings to config, with validation
- [x] 1.2 Mount `/admin` routes only when a key is configured, behind rate limiting and bearer authentication
- [x] 1.3 Implement user create, list, disable and enable
- [x] 1.4 Implement enroll token mint, list and revoke, defaulting `maxDevices` to `1`
- [x] 1.5 Implement device list, revoke and enable

## 2. Registration Hardening

- [x] 2.1 Rate limit `POST /register` per client IP and stop trusting proxy headers
- [x] 2.2 Limit request bodies to 1 MiB and return `413` when exceeded
- [x] 2.3 Canonicalize node keys at registration and parse verify requests through `tailcfg.NodePublic`
- [x] 2.4 Move token, user and device-limit checks into one transaction with row locks
- [x] 2.5 Open sqlite with `_txlock=immediate` and translate unique-constraint errors to `409`

## 3. Verify Cache

- [x] 3.1 Add epoch-based invalidation so stale decisions are not cached
- [x] 3.2 Bound the cache size with batched eviction
- [x] 3.3 Invalidate cached decisions on registration and on admin device and user changes

## 4. Runtime

- [x] 4.1 Serve through `http.Server` with timeouts and graceful shutdown

## 5. Validation and Docs

- [x] 5.1 Add admin API, rate limit, concurrency and cache tests
- [x] 5.2 Document the admin API and new settings in the README
- [x] 5.3 Run build, vet and race tests on Go 1.24.0, and on Go 1.27.2 once `e72dfe0` fixed the build there

## 6. Review

- [ ] 6.1 Owner reviews this retroactive spec against the code and corrects any wording
- [x] 6.2 Owner decides the two open questions in `design.md`
