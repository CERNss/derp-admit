## derp-verifier

`derp-verifier` is a sidecar service for `derper --verify-client-url`.

### Required Environment Variables

- `DATABASE_URL` (PostgreSQL DSN, or `sqlite://...` for local tests)
- `TOKEN_PEPPER` (secret used by token hash: `hex(sha256(token + ":" + TOKEN_PEPPER))`)

### Optional Environment Variables

- `ADDR` (default `:8080`)
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
- `VERIFY_CACHE_TTL` (default `0s`, disabled)

### Run

```bash
go run ./cmd/derp_admit
```

### Verify Flow

Derper should be configured with:

- `--verify-client-url=http://verifier:8080/verify`
- `--verify-client-url-fail-open=false`

### SigNoz Readiness

To prepare for SigNoz, set:

- `OTEL_ENABLED=true`
- `OTEL_EXPORTER_OTLP_ENDPOINT=<your-collector-host:4318>`

This enables OpenTelemetry traces while logs stay in structured zap JSON.

### Docker Build (Cross-Platform)

Single platform (for local load, e.g. Linux amd64):

```bash
docker buildx build \
  --platform linux/amd64 \
  -f build/derp_admit/Dockerfile \
  -t derp-admit:linux-amd64 \
  --load \
  .
```

Multi-platform (for registry push):

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f build/derp_admit/Dockerfile \
  -t <your-registry>/derp-admit:<tag> \
  --push \
  .
```
