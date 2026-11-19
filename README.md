## derp-verifier

`derp-verifier` is a sidecar service for `derper --verify-client-url`.

### Configuration Model

Configuration is loaded in this order (later overrides earlier):

1. `config/config.yaml`
2. `.env` (or `ENV_FILE` path)
3. real process environment variables

### Required Values

- `DATABASE_URL` (PostgreSQL DSN, or `sqlite://...` for local tests)
- `TOKEN_PEPPER` (secret used by token hash: `hex(sha256(token + ":" + TOKEN_PEPPER))`)

### Optional Environment Variables

- `ADDR` (default `:8080`)
- `ADMIN_API_KEY` (enables the `/admin` API when set; must be ≥ 16 chars)
- `ADMIN_RATE_LIMIT_RPS` (default `10`, throttles the `/admin` API, including key guessing)
- `ADMIN_RATE_LIMIT_BURST` (default `20`)
- `LOG_LEVEL` (default `info`)
- `ENABLE_CASBIN` (default `true`)
- `OTEL_ENABLED` (default `false`)
- `OTEL_SERVICE_NAME` (default `derp-admit`)
- `OTEL_EXPORTER_OTLP_ENDPOINT` (for SigNoz/OTLP collector, for example `otel-collector:4318`)
- `OTEL_EXPORTER_OTLP_INSECURE` (default `true`)
- `OTEL_TRACE_SAMPLE_RATIO` (default `1.0`, range `0..1`)
- `DB_TIMEOUT` (default `2s`)
- `VERIFY_RATE_LIMIT_RPS` (default `100`)
- `VERIFY_RATE_LIMIT_BURST` (default `200`)
- `REGISTER_RATE_LIMIT_RPS` (default `5`, applied per client IP so one abusive client cannot starve other registrations; throttles enroll-token guessing on `/register`)
- `REGISTER_RATE_LIMIT_BURST` (default `10`)
- `VERIFY_CACHE_TTL` (default `0s`, disabled)

### Run

```bash
# optional: cp .env.example .env and edit values
go run ./cmd/derp_admit
```

### Admin API

Set `ADMIN_API_KEY` to enable the authenticated lifecycle API. All routes are
under `/admin` and require `Authorization: Bearer <ADMIN_API_KEY>`. When the key
is unset the admin routes are not mounted (provision via SQL instead).

| Method & path | Purpose |
| --- | --- |
| `POST /admin/users` | Create a user `{ username, email? }` |
| `GET /admin/users` | List users |
| `POST /admin/users/:id/disable` / `.../enable` | Toggle a user (disable also drops cached decisions for their devices) |
| `POST /admin/tokens` | Mint an enroll token `{ userId, expiresAt?, maxDevices?, note? }`; the plaintext token is returned **once**. `maxDevices` defaults to `1` when omitted; `0` means unlimited (explicit opt-in) |
| `GET /admin/tokens` | List tokens (metadata only, never the hash) |
| `POST /admin/tokens/:id/revoke` | Revoke a token |
| `GET /admin/devices` (`?userId=`) | List devices |
| `POST /admin/devices/:id/revoke` / `.../enable` | Toggle a device (invalidates its cached decision) |

Enroll tokens are generated server-side with 256 bits of entropy; only the
peppered hash is stored.

Typical bootstrap:

```bash
KEY="your-admin-api-key"
BASE="http://localhost:8080"

# 1. create a user
uid=$(curl -s -XPOST "$BASE/admin/users" -H "Authorization: Bearer $KEY" \
  -H 'content-type: application/json' -d '{"username":"alice"}' | jq -r .user.id)

# 2. mint an enroll token (capture the one-time plaintext)
tok=$(curl -s -XPOST "$BASE/admin/tokens" -H "Authorization: Bearer $KEY" \
  -H 'content-type: application/json' -d "{\"userId\":\"$uid\",\"maxDevices\":5}" | jq -r .token)

# 3. enroll a device's node key
curl -s -XPOST "$BASE/register" -H 'content-type: application/json' \
  -d "{\"token\":\"$tok\",\"nodeKey\":\"nodekey:<hex>\",\"label\":\"laptop\"}"
```

### Registration

`POST /register` with `{ "token": "...", "nodeKey": "...", "label": "..." }`.

`nodeKey` must be a tailscale node public key in canonical text form
(`nodekey:<64-hex>`); it is normalized to the same representation derper sends
at verify time, so the two always match. A malformed key returns `400`.

### Verify Flow

Derper should be configured with:

- `--verify-client-url=http://verifier:8080/verify`
- `--verify-client-url-fail-open=false`

### SigNoz Readiness

To prepare for SigNoz, set:

- `OTEL_ENABLED=true`
- `OTEL_EXPORTER_OTLP_ENDPOINT=<your-collector-host:4318>`

This enables OpenTelemetry traces while logs stay in structured zap JSON.

With compose, the container reads:

- config file: `/app/config/config.yaml`
- env file: `../../.env` (from compose file location)

### Docker Build (Cross-Platform)

Single platform (for local load, e.g. Linux amd64):

```bash
docker buildx build \
  --platform linux/amd64 \
  -f builder/derp_admit/Dockerfile \
  -t derp-admit:linux-amd64 \
  --load \
  .
```

Multi-platform (for registry push):

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f builder/derp_admit/Dockerfile \
  -t <your-registry>/derp-admit:<tag> \
  --push \
  .
```
