## 1. Proposal and Design Alignment

- [x] 1.1 Finalize proposal/design/spec artifacts for zap + OTel integration scope
- [x] 1.2 Confirm telemetry configuration contract and defaults for local/prod environments

## 2. Logging Migration

- [x] 2.1 Replace existing logger wiring with zap in app bootstrap
- [x] 2.2 Refactor router and service layers to use structured zap logs
- [x] 2.3 Ensure sensitive values (token plaintext) are never logged

## 3. OTel Tracing Baseline

- [x] 3.1 Add telemetry initialization package for tracer provider and propagator setup
- [x] 3.2 Add OTLP exporter configuration and graceful shutdown hooks
- [x] 3.3 Integrate gin OTel middleware for `/register` and `/verify`

## 4. Config and Runtime Integration

- [x] 4.1 Add telemetry-related environment variables to config parser
- [x] 4.2 Update README and deployment docs for telemetry settings and SigNoz readiness
- [x] 4.3 Verify build/compose wiring still works after telemetry changes

## 5. Validation

- [x] 5.1 Update and run tests for register/verify behavior regression
- [x] 5.2 Add tests for telemetry initialization behavior (enabled/disabled)
- [x] 5.3 Run full `go test ./...` and capture results
