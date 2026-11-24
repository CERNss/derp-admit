Paths are relative to `internel/app/derp_admit/` unless they start at the repository root. Every group leaves `go build ./... && go vet ./... && go test -race -count=1 ./...` passing on the local toolchain and with `GOTOOLCHAIN=go1.24.0`. Groups 1 to 4 are owned by this change's implementer; group 5 is owned by other people working on the same release and is listed here so the release is tracked in one place.

## 1. Configuration

- [x] 1.1 In `config/config.go`, add `VERIFY_ALLOWED_CIDRS` / `verify_allowed_cidrs` and `METRICS_ALLOWED_CIDRS` / `metrics_allowed_cidrs`, parsed to `[]netip.Prefix` per design D3 (empty value does not override a lower layer), and `VERIFY_AUDIT_RETENTION_DAYS` / `verify_audit_retention_days` and `ADMIN_AUDIT_RETENTION_DAYS` / `admin_audit_retention_days` (integers, default `0`, negative fails `validate`). Verify with `TestLoadFromEnv_AllowedCIDRs` (lists, bare IPs, IPv6, whitespace, mapped items, invalid and empty items naming the setting and item, env over `.env` over YAML, empty env value) and `TestLoadFromEnv_AuditRetentionDays` (valid, zero, negative, non-integer, layering) in `config/config_ops_test.go`.
- [x] 1.2 Add the four settings, commented, to `.env.example` and `config/config.yaml` in their existing style; verify by reading both files and by `TestShippedConfigFilesLoad` (the shipped `config/config.yaml` loads and leaves the new settings at their defaults).

## 2. Caller allowlists

- [x] 2.1 Add `CallerRejected(endpoint)` to `metrics.Recorder`, `metrics.Nop` and `metrics.Prometheus` as `derp_admit_caller_rejected_total{endpoint}`, pre-initialised for `verify` and `metrics`; update test fakes. Verify with `TestPrometheusCallerRejectedAndAuditPruned` in `metrics/prometheus_test.go`.
- [x] 2.2 Add the allowlist middleware (design D1, D2, D4) in `server/allowlist.go`, attach it to `POST /verify`, `POST /verify/*relay` and `GET /metrics` ahead of the handlers, and log one startup info line per list in both states (entry count when set; "any peer may call /verify" or "any peer may read /metrics", the latter only with metrics enabled, when unset). Verify with `TestBuildLogsAllowlistState` in `app/retention_test.go` (both states of both lists, metrics disabled) and `server/allowlist_test.go`: `TestVerifyAllowlistAllowsAndRejects` (both paths), `TestMetricsAllowlistAllowsAndRejects`, `TestAllowlistUnsetAllowsEveryone`, `TestAllowlistIgnoresForwardedHeaders`, `TestAllowlistIPv4MappedPeer`, `TestAllowlistUnparsablePeerRejected`, `TestAllowlistRejectedCallerNotAuditedAndKeepsLimiter` (burst 1, near-zero refill, many rejections then one allowed call succeeds; no audit row; decision counter unchanged; rejection counter counts), `TestAllowlistDoesNotAffectOtherEndpoints`.
- [x] 2.3 README: settings table rows, a "Restricting callers" paragraph in the verify section with the Docker bridge gateway warning, the check-order list, the trust statement, the verify audit "Not recorded" list, the `## Metrics` sentence about authentication, and the new counter in the metrics table. Verify by reading the rendered sections.

## 3. Audit retention

- [x] 3.1 Confirm nothing reads old audit rows as state (upgrade marker, bootstrap reconciliation, guards); verify by grepping every read of `AuditLog` / `AdminAuditLog` and recording the result in design.md Context.
- [x] 3.2 Add `AuditPruned(table, n)` to the recorder as `derp_admit_audit_pruned_total{table}`, pre-initialised for `verify` and `admin`. Verify with `TestPrometheusCallerRejectedAndAuditPruned`.
- [x] 3.3 Implement `service.AuditPruner` per design D5 and D6, start it in `app.Build` and stop it in `App.Close`. Verify with `service/retention_test.go`: `TestPruneDeletesOnlyRowsOlderThanCutoff`, `TestPruneUsesMultipleBatches`, `TestPruneLeavesOtherTableAlone`, `TestPruneRetentionZeroDeletesNothing`, `TestPruneConcurrentPrunersAreHarmless`, `TestPruneCountsMetricsAndLogs`, `TestPruneDoesNotTouchPolicyOrAdminAudit`, `TestPruneFailureIsLoggedAndRetried`, `TestPrunerStopsOnShutdown`, `TestPruneCutoffClampsHugeRetention`, `TestPruneStatementPlanUsesTSIndex` (SQLite `EXPLAIN QUERY PLAN` uses the `ts` index on both tables), and in `app/retention_test.go` `TestBuildStartsAndStopsAuditPruner`, `TestBuildSchedulesAuditPruning` (old rows disappear without the test calling `PruneOnce`) and `TestCloseWaitsForPruneInFlight` (`Close` blocks while a prune statement is held open). Mutation check: removing `pruner.Start` fails the last two; removing `AuditPruner.Wait` from `Close` fails `TestCloseWaitsForPruneInFlight`.
- [x] 3.4 Verify keyset pagination under pruning with `TestAuditPaginationSurvivesPrune` (sqlite), `TestPostgresAuditPaginationSurvivesPrune` and `TestPostgresConcurrentAuditPrune` (gated on `TEST_POSTGRES_URL` through `createFreshPostgresDB`, as in `server/postgres_e2e_test.go`) and `TestPostgresPruneSkipsLockedRows` (a pass with some old rows held `FOR UPDATE` by another transaction returns promptly without error, deletes only the unlocked rows, and a later pass deletes the rest; it fails, by waiting for the statement timeout, when `FOR UPDATE SKIP LOCKED` is removed) in `server/retention_pagination_test.go`, run against PostgreSQL 16 with `TEST_POSTGRES_URL` on both toolchains. Plans checked by hand with `EXPLAIN` on PostgreSQL 16 (200000 rows per table): the outer delete uses the primary key on both tables; the inner select uses `idx_audit_logs_ts` / `idx_admin_audit_logs_ts_id` for a selective cutoff (including the final empty statement and the generic prepared plan) and a sequential scan stopping at the batch limit when most rows are old. On SQLite the plan is pinned by `TestPruneStatementPlanUsesTSIndex`.
- [x] 3.5 README: settings table rows, the `### Retention` section (behaviour, every replica, batches, logs and metric, `upgrade.run` rows pruned too), the trust statement's "nothing prunes", and the new counter in the metrics table. Verify by reading the rendered sections.

## 4. Verification

- [x] 4.1 Mutation check by hand: remove the allowlist check from the middleware and confirm the allowlist tests fail; change the prune comparison to delete newer rows and confirm the retention tests fail; restore both and confirm the files match their saved copies and the full suite passes.
- [x] 4.2 `openspec validate add-caller-allowlists-and-audit-retention --json` and `--strict` pass.

## 5. Release work owned by other people

- [x] 5.1 CI workflow
- [x] 5.2 image release workflow
- [x] 5.3 production compose file
- [x] 5.4 enrollment script
- [x] 5.5 onboarding document
- [x] 5.6 README pointers to deploy/ and docs/

## Workflow follow-up

- Archive the change after review; the deltas are merged into `openspec/specs/` at archive time by the person archiving.
