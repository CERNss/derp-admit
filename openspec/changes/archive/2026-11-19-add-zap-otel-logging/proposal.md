## Why

The verifier currently uses basic logging without standardized structured fields or distributed tracing context, which makes production debugging and cross-service correlation difficult. We need a telemetry baseline now so the service can later integrate with SigNoz using OpenTelemetry-compatible signals.

## What Changes

- Replace current logger wiring with `zap` structured logging across app startup, HTTP handlers, and service logic.
- Add OpenTelemetry initialization for trace export and context propagation.
- Instrument inbound HTTP requests with OTel middleware so trace context is attached to request processing.
- Add configurable telemetry environment variables for endpoint, service name, and export behavior.
- Ensure logs are safe (no token plaintext) while including trace correlation fields where available.

## Capabilities

### New Capabilities
- `structured-logging`: Standardized structured application logs with zap across runtime layers.
- `otel-tracing-baseline`: OpenTelemetry trace setup and HTTP instrumentation compatible with OTLP collectors (future SigNoz ingestion).

### Modified Capabilities
- `derp-client-verification`: Verification request processing requirements are extended to include trace-aware observability and structured operational logging.

## Impact

- Affected code: app bootstrap, router middleware stack, service logging calls, config parsing, and tests.
- Dependencies: add zap and OpenTelemetry SDK/instrumentation packages.
- Operations: introduces telemetry configuration surface and prepares runtime for SigNoz via OTLP endpoint.
