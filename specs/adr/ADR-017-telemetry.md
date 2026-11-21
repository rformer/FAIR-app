# ADR-017 Telemetry: OpenTelemetry, off by default, with an attribute allow-list
Status: Accepted (Robert Former, 2026-11-20, with the F-012 design; written by F-012 T-09)
Date: 2026-11-20

## Context
F-012 requires metrics, traces and structured logs (AC-22): request rates, errors and latencies, job queues and backlogs, and the audit trail's forwarding and capacity.

Two constraints shape how:
- **No sensitive data (AC-23).** Telemetry must never carry secrets, tokens, risk data or personal data beyond user ids.
- **No call home (AC-25).** Self-hosted and air-gapped installations must keep telemetry inside the installation.

The SaaS operators need SLO alerts with runbooks (AC-24).

OQ4 (resolved 2026-11-19) chose OpenTelemetry with a Collector. For SaaS, Prometheus-compatible metrics, Grafana, Loki and Tempo run in a separate operations account that holds no customer data. Self-hosted installations get the Collector configuration and a Prometheus endpoint.

The alternatives were:
- **Vendor APM agents:** proprietary, they call home, and they are hard to run air-gapped.
- **Prometheus client libraries alone:** metrics only, with no traces.
- **OpenTelemetry's log signal for the services' logs:** a second log path beside slog, which every service already uses for JSON on stdout.

## Decision
- **SDK.** The OpenTelemetry Go SDK v1.47.0, released 2026-10-02 (the newest at least two weeks old): `otel`, `sdk`, `sdk/metric`, `exporters/otlp/otlptrace/otlptracegrpc` and `exporters/otlp/otlpmetric/otlpmetricgrpc`. It is wrapped in `pkg/telemetry`.
- **Off by default.** Without `FAIR_OTEL_ENDPOINT`, `telemetry.Setup` installs nothing, exports nothing and dials nothing (AC-25). With an endpoint, metrics and traces go over OTLP/gRPC with TLS 1.2 or later, optionally verified against `FAIR_OTEL_CA_FILE`. There is no plaintext option. Traces are sampled by `FAIR_OTEL_SAMPLE_RATIO` (default 0.1, parent-based).
- **Logs stay slog JSON on stdout.** `telemetry.Logs` adds `trace_id` and `span_id` to records written with a context. The Collector (or the cluster's log agent) ships stdout.
- **An allow-list, enforced by the pipeline.** Every attribute passes `telemetry.Allowed`, which names routes, operations, queues and outcomes, never ids, arguments, bodies, tokens or personal data. Enforcement is in three places:
  - the span exporter is wrapped by `telemetry.Filtered`, which drops other attributes, every event and status text, since those can hold error messages with data;
  - the metric provider has `telemetry.AllowedView`;
  - spans are named from route patterns and fixed strings.

  `TestTelemetryRedaction` (T-10) checks the whole path over real API flows.
- **Instrumentation in shared places, so every service gets it:**
  - HTTP in `internal/server`, by route pattern;
  - pgx in `internal/dbconn`, by statement operation only;
  - River through worker middleware `telemetry.River`;
  - NATS publish and consume counts in `internal/natspub`;
  - engine calls through gRPC interceptors on the risk service's engine connection;
  - notification delivery outcomes in `notify.Worker`;
  - the audit trail's forwarding backlog per destination and its capacity, as gauges in the audit service.
- **Readiness covers dependencies (AC-22).**
  - Key files and directories are checked (`server.KeyFiles`).
  - Object storage and the engine are checked at most once a minute (`server.Every`). They are degraded checks: a failure is reported, but the service stays ready, because only some features need them and those fail closed on their own.
- **Where telemetry goes.**
  - In SaaS, a Collector in each instance forwards to the operations account over PrivateLink.
  - Self-hosted installations get `deploy/observability/collector-selfhosted.yaml` (F-012 T-11), and nothing calls the vendor.

## Consequences
- `go.mod` gains the OpenTelemetry SDK and its OTLP exporters (OpenTelemetry was already an indirect dependency through gRPC). They are linked into every service image, are covered by the SBOMs and the scans, and are updated by Dependabot.
- A new attribute key needs a reason in `telemetry.Allowed` and a case in the redaction test.
- Routes are recorded by the pattern the service's outer mux matched. Where an API is mounted under a prefix, that is the prefix, so it is coarser but never carries an id.
