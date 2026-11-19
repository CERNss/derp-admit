## ADDED Requirements

### Requirement: Service SHALL initialize OpenTelemetry tracing
The system MUST initialize an OpenTelemetry tracer provider during startup with configurable service metadata and OTLP exporter settings.

#### Scenario: Telemetry enabled with OTLP endpoint
- **WHEN** telemetry is enabled and an OTLP endpoint is configured
- **THEN** the service initializes trace export and sets global tracer provider and propagator

#### Scenario: Telemetry disabled
- **WHEN** telemetry is disabled by configuration
- **THEN** the service starts normally without external trace export

### Requirement: HTTP requests SHALL be instrumented with OTel middleware
The system MUST instrument inbound gin HTTP routes with OpenTelemetry middleware so request spans are created for API calls.

#### Scenario: Verify request tracing
- **WHEN** `POST /verify` is called
- **THEN** a server span is created and request context carries trace propagation metadata
