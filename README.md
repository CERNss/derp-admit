## derp-verifier

`derp-verifier` is a sidecar service for `derper --verify-client-url`.

### Required Environment Variables

- `DATABASE_URL` (PostgreSQL DSN, or `sqlite://...` for local tests)
- `TOKEN_PEPPER` (secret used by token hash: `hex(sha256(token + ":" + TOKEN_PEPPER))`)

### Optional Environment Variables

- `ADDR` (default `:8080`)
- `ENABLE_CASBIN` (default `true`)
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
