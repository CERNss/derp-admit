## Context

See `proposal.md` for the motivation. The relevant current state:

- `server/router.go` builds one gin engine and calls `SetTrustedProxies(nil)`, so `ClientIP()` is already the TCP peer. `/verify` and `/verify/*relay` share `verifyHandler`, whose first step is the single global `rate.Limiter`. `/metrics` is `gin.WrapH` over the Prometheus handler.
- Verify audit rows are written in `service.Verify`; admin audit rows in `service/audit_admin.go` and `policy/upgrade.go`. The only readers of either table are the two keyset-paginated list queries in `service/admin_audit_query.go`. The one-time upgrade's "already ran" marker is `policy_state.upgraded_at`, and bootstrap reconciliation reads only `admin_keys`. Nothing reads an old audit row as state, so deleting old rows is safe.
- Indexes: `audit_logs` has `idx_audit_logs_ts (ts)`; `admin_audit_logs` has `idx_admin_audit_logs_ts_id (ts DESC, id DESC)`. Both serve a `ts < cutoff` range.
- The policy syncer runs as a goroutine started in `app.Build` on a context that `App.Close` cancels. `cmd/derp_admit` defers `App.Close`.

## Goals / Non-Goals

**Goals:**
- A network-level restriction of who may call `/verify` and `/metrics`, decided before any work or shared budget is spent on the caller.
- Bounded audit tables, without coordination between replicas and without touching policy state.

**Non-Goals:**
- Authenticating `derper` (it sends no credentials) or trusting a reverse proxy's forwarded headers.
- Restricting `/register`, `/admin`, `/healthz`, `/readyz` or `/`.
- Archiving or exporting audit rows before deletion, or a configurable prune interval or batch size.

## Decisions

### D1. Allowlist as gin middleware on the three routes, ahead of the handler

A `callerAllowlist(prefixes, endpoint, logger, rec)` middleware is attached to `POST /verify`, `POST /verify/*relay` and `GET /metrics` only, before the handler. A rejected request is answered `403 {"ok":false,"error":"forbidden"}` and aborted, so the verify limiter, `service.Verify`, the audit insert and the decision counter never run. An empty list attaches nothing, so the default path is byte-for-byte today's. Alternatives: a global middleware with a path switch (couples unrelated routes); a check inside `service.Verify` (too late: the limiter token is already spent).

### D2. Peer address from `Request.RemoteAddr`

The address is taken from `c.Request.RemoteAddr` (split host and port; fall back to the whole value when there is no port), parsed with `netip.ParseAddr`, unmapped (`::ffff:a.b.c.d` becomes `a.b.c.d`) and stripped of any zone. Parse failure means reject. `ClientIP()` would give the same value today, but reading `RemoteAddr` directly keeps the check correct even if someone later configures trusted proxies.

### D3. Parsing the lists at load time

Items are split on `,` and trimmed. A bare address becomes a full-length prefix; a CIDR is parsed with `netip.ParsePrefix` and masked. IPv4-mapped IPv6 items are converted to IPv4 (a bare mapped address becomes `/32`; a mapped prefix of length `>= 96` becomes the IPv4 prefix of length minus 96), because peers are unmapped before matching and an unconverted item would silently never match. Zoned addresses, empty items, and mapped prefixes shorter than `/96` are errors. Errors name the setting as written in the layer that supplied it (`VERIFY_ALLOWED_CIDRS` or `verify_allowed_cidrs`) and quote the item. The parsed `[]netip.Prefix` is stored in `config.Config`, so tests that build a `Config` directly pass prefixes.

An empty or whitespace-only value at a higher layer does not clear a lower layer's list: `.env` is applied, then the process environment, each only when non-blank after trimming (the pattern `UPGRADE_POLICY_MODE` uses). This differs from both `ADMIN_API_KEY`, where an empty process value stops the lookup so `.env` is never read and a whitespace-only value counts as set, and `OTEL_EXPORTER_OTLP_ENDPOINT`, where an empty value clears the lower layer. A stray `VERIFY_ALLOWED_CIDRS=` line in `.env`, or a process variable that a compose file expands to nothing, therefore cannot silently remove a restriction made in a lower layer. The cost is that a YAML list cannot be cleared from the environment; remove it from YAML instead.

### D4. Rejection logging and counting

Each rejection logs one warn line `"caller rejected by allowlist"` with `endpoint` and `client_ip`, through `logWithTrace`, the same way every verify rate-limit rejection is logged today (that path logs every rejection, so this one does too). The counter `derp_admit_caller_rejected_total{endpoint}` is pre-initialised for `verify` and `metrics`. At startup `NewRouter` always logs one info line per list: the entry count when it is set, and "verify caller allowlist not set: any peer may call /verify" (or the `/metrics` equivalent, only when metrics are enabled) when it is not. A misspelled YAML key or a `CONFIG_FILE` that does not exist loads without error and leaves the list unset, so this line is how an operator notices. It is info, not warn, because an unrestricted endpoint is a valid setup.

### D5. Pruner: one goroutine per instance, no coordination

`service.AuditPruner` holds the two retentions, the DB, the DB timeout, logger and metrics. `Start(ctx)` runs one goroutine: wait a short first delay (30 s), run a pass, then every hour. Each pass prunes `audit_logs` (if its retention is `> 0`) then `admin_audit_logs` (if `> 0`). With both retentions `0` no goroutine is started. Interval, first delay, clock and batch size are unexported fields so in-package tests can shrink them; there is no public setting. `App.Close` cancels the context and waits for the goroutine to exit, so no statement runs after shutdown returns. An exported `PruneOnce(ctx)` runs a single pass for tests in other packages.

Alternatives: a leader-elected pruner (needs a lock or lease table; harmless concurrency makes it unnecessary); a cron-style external job (an extra deployment unit for every operator).

### D6. Batched delete statement

Per batch, with the cutoff `now.UTC().AddDate(0, 0, -days)`:

- SQLite: `DELETE FROM <t> WHERE id IN (SELECT id FROM <t> WHERE ts < ? LIMIT ?)`
- PostgreSQL: `DELETE FROM <t> WHERE id = ANY(ARRAY(SELECT id FROM <t> WHERE ts < ? LIMIT ? FOR UPDATE SKIP LOCKED))`.

The inner select has no `ORDER BY`: any rows older than the cutoff may go first. With `ORDER BY id`, SQLite's plan was `SCAN <t>` in rowid order, so the final, empty statement of every pass walked every retained row and could exceed `DB_TIMEOUT` on a large file. Without it, `EXPLAIN QUERY PLAN` on SQLite shows `SEARCH <t> USING COVERING INDEX idx_audit_logs_ts (ts<?)` and `... idx_admin_audit_logs_ts_id (ts<?)`, and the outer delete as `SEARCH <t> USING INTEGER PRIMARY KEY (rowid=?)`; `TestPruneStatementPlanUsesTSIndex` pins this.

On PostgreSQL 16 (200000 rows per table, ids rising with `ts`), `EXPLAIN` of the `IN (subquery)` form showed a hash semi join over a sequential scan of the whole table for every batch; the `ANY(ARRAY(...))` form runs the subquery once as an InitPlan and deletes through `<t>_pkey`. The inner select uses `idx_audit_logs_ts` / `idx_admin_audit_logs_ts_id` when the cutoff is selective, including the final empty statement, and also in the forced generic plan of a prepared statement. When most rows are older than the cutoff it uses a sequential scan that stops once the batch is full. These plans were checked by hand, not by a test.

`SKIP LOCKED` means two replicas never wait on each other's row locks, so concurrent pruners cannot deadlock and simply split the old rows between them. SQLite serialises writers (`_busy_timeout=5000`), and each statement is atomic. The loop ends when a statement deletes `0` rows, not when it deletes fewer than the batch, because a concurrent pruner can take part of a batch while old rows remain. Each statement gets its own `context.WithTimeout(ctx, dbTimeout)`. The cutoff is passed in UTC because SQLite compares `ts` as text, as the existing filters and cursors already do. Days are clamped internally to 100000 so the cutoff arithmetic cannot overflow.

### D7. Pagination under pruning

Keyset cursors carry `(ts, id)` of the last row returned and the next page selects `(ts, id) < cursor`. Deleting rows older than a cutoff can only remove rows from later pages, never move a row across the cursor, so a page after a prune returns the remaining older rows with no repeats and no error, including when the cursor's own row was deleted. No code change is needed; tests pin it on both backends.

## Risks / Trade-offs

- [Docker port publishing rewrites the source address to the bridge gateway for connections from the host] → README warns to list the `derper` container's own address, not the bridge subnet, which would also admit anything reaching the published port through the host.
- [An operator sets `VERIFY_ALLOWED_CIDRS` and forgets a `derper`] → that `derper` gets `403`, which with fail-open off rejects its clients. The warn log names the peer IP and the counter rises; the startup info line shows the list size.
- [Retention deletes `upgrade.run` and system `device.revoke` rows that the upgrade section tells operators to read] → README says so; the upgrade marker lives in `policy_state`, so the upgrade never re-runs.
- [A first prune on a large, long-unpruned table holds the writer lock on SQLite for many short statements] → batches of 1000 keep each statement short; SQLite is for tests and running from source only.
- [Every replica prunes] → `SKIP LOCKED` keeps this to wasted work at most; at an hourly interval it is negligible.

## Migration Plan

No schema change. Deploy as usual; with the new settings unset nothing changes. To enable: set the allowlists to the `derper` and scraper addresses, and the retention days; restart. To roll back: unset them, or deploy the previous version (which ignores the new settings). Rows already pruned are gone; take a backup first if they matter.
