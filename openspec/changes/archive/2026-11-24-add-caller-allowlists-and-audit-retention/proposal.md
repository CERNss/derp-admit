## Why

`POST /verify`, `POST /verify/:relay` and `GET /metrics` answer anyone who can reach the service port. An outsider can learn whether a node key is registered, can drain the single global verify rate limit (with `--verify-client-url-fail-open=false` every `derper` then rejects every client), and writes one verify audit row per call. Neither audit table is ever pruned, so both grow without bound. Operators asked for a way to restrict these callers without a reverse proxy, and for automatic audit retention, before the production deployment work that runs alongside this change.

## What Changes

- New settings `VERIFY_ALLOWED_CIDRS` / `verify_allowed_cidrs` and `METRICS_ALLOWED_CIDRS` / `metrics_allowed_cidrs`: comma-separated CIDRs or single IP addresses. Unset or empty means no restriction, which is today's behaviour and stays the default.
- When `VERIFY_ALLOWED_CIDRS` is set, a `/verify` or `/verify/:relay` caller whose TCP peer address is outside the list gets HTTP `403` before the rate limit and before any other check: no audit row, no rate-limit token, no verify decision counted. Forwarded headers are never consulted.
- When `METRICS_ALLOWED_CIDRS` is set, a `/metrics` caller outside the list gets HTTP `403`.
- New counter `derp_admit_caller_rejected_total{endpoint}` (`verify`, `metrics`).
- New settings `VERIFY_AUDIT_RETENTION_DAYS` / `verify_audit_retention_days` (table `audit_logs`) and `ADMIN_AUDIT_RETENTION_DAYS` / `admin_audit_retention_days` (table `admin_audit_logs`): non-negative integers, `0` (the default) keeps rows forever.
- Each instance runs a background pruner, shortly after startup and then hourly, that deletes rows older than the retention period in bounded batches. It is safe when several replicas run it at once, does not touch policy state or the verify cache, writes no admin audit row, and is counted in `derp_admit_audit_pruned_total{table}` (`verify`, `admin`).
- Invalid list items, and negative or non-integer retention values, are configuration errors at load time.

No breaking change: with the new settings unset the service behaves exactly as before.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `derp-client-verification`: verify callers can be restricted to a list of peer addresses; a rejected caller gets `403` before the rate limit.
- `service-metrics`: `/metrics` can be restricted to a list of peer addresses; new counters for caller rejections and pruned audit rows.
- `verify-audit-logging`: a caller rejected by the allowlist is not audited; verify audit rows are pruned after `VERIFY_AUDIT_RETENTION_DAYS`.
- `admin-audit-logging`: admin audit rows, including `system` rows, are pruned after `ADMIN_AUDIT_RETENTION_DAYS`.
- `layered-config-loading`: the four new settings follow the existing layering and fail loading when invalid.

## Impact

- Code: `config/config.go`; `server/router.go`, `server/verify_handler.go` and a new caller allowlist middleware; a new pruner in `service/`; `app/app.go` (start and stop of the pruner); `metrics/` (two counters).
- Configuration and docs: `.env.example`, `config/config.yaml`, `README.md`.
- Database: no schema change. The pruner relies on the existing `audit_logs(ts)` and `admin_audit_logs(ts DESC, id DESC)` indexes.
- Callers: none while the new settings stay unset. The dev compose file and the `e2e/` rig leave them unset.
- Other work in the same release, owned by other people and listed in `tasks.md`: CI workflow, image release workflow, production compose file, enrollment script, onboarding document, README pointers to `deploy/` and `docs/`.
