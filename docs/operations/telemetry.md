# Telemetry

FAIR's services emit OpenTelemetry metrics and traces, and log JSON to stdout (ADR-017). Telemetry is **off** until you point it at a Collector. Nothing is sent anywhere else, and no FAIR service calls the vendor.

## Turning it on
Set on every service:

| Variable | Meaning |
|---|---|
| `FAIR_OTEL_ENDPOINT` | `host:port` of your OpenTelemetry Collector's OTLP/gRPC receiver. TLS is always used. |
| `FAIR_OTEL_CA_FILE` | The CA that signed the Collector's certificate (PEM). Leave it unset to use the system roots. |
| `FAIR_OTEL_SAMPLE_RATIO` | The share of traces kept, from 0 to 1 (default 0.1). |

## What is sent
| Signal | Contents |
|---|---|
| `http.server.request.duration` | Per method, route pattern and status. |
| `db.client.operation.duration` | Per statement operation (`SELECT`, `INSERT`, …) and result. |
| `job.duration` | Background jobs, per queue, kind and outcome. |
| `messaging.messages` | NATS messages published and consumed, per subject. |
| `engine.call.duration` | Simulation engine calls, per method and outcome. |
| `notification.deliveries` | Per channel and outcome. |
| `backlog.audit_forwarding_<destination>`, `backlog.audit_capacity_permille` | The audit trail's forwarding backlog and storage use. |
| Traces | One span per request and per statement, named by route pattern and operation. |

Every attribute comes from a fixed allow-list. Telemetry never carries ids from paths, statements or arguments, request or response bodies, tokens, or names, emails or risk data (`pkg/telemetry`, F-012-AC-23). Logs carry `trace_id` and `span_id`, so a log line can be matched with its trace.

## Readiness
`/readyz` on every service reports each dependency:
- **The database and the key files:** if either fails, the service is not ready.
- **The engine and object storage:** if either fails, it is reported as `degraded`, and the service stays ready. Only analysis runs, reports and audit archiving need them, and those requests fail closed on their own.
