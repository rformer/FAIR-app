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

## Collector configurations
`deploy/observability/` (F-012 T-11) holds the OpenTelemetry Collector configurations, for the official contrib distribution (`otel/opentelemetry-collector-contrib`):

| File | Where | What it does |
|---|---|---|
| `collector-selfhosted.yaml` | Self-hosted and air-gapped | Receives OTLP/gRPC over TLS and exposes the metrics at `https://<collector>:8889/metrics` for your Prometheus. Traces are received and dropped. Nothing leaves the installation. |
| `collector-selfhosted-forward.yaml` | Optional, after the file above (`--config A --config B`) | Also sends metrics and traces to your own collector at `FAIR_OTEL_FORWARD_ENDPOINT` (TLS 1.2 or later, your CA). |
| `collector-saas.yaml` | SaaS, one per instance | Receives OTLP, scrapes kube-state-metrics and cert-manager, reads the engine certificates' expiry, and forwards to the operations account (Prometheus remote write, Loki and Tempo over OTLP, mutual TLS). |
| `collector-saas-agent.yaml` | SaaS, one per node | Ships the platform pods' stdout to the instance Collector and counts the audit events the alerts need (`fair_audit_events_total`). |

Credentials and certificates are mounted files; endpoints come from the environment. `scripts/observability-check.sh` validates every configuration with `otelcol-contrib validate`.

When your Prometheus scrapes the self-hosted endpoint, set `honor_labels: true`, so that each series keeps its service as `job`.

## Metric names in Prometheus
The Collector's Prometheus exporters (the scrape endpoint and remote write) turn OpenTelemetry names into Prometheus names:
- dots become underscores;
- the unit is added (`s` becomes `_seconds`);
- counters get `_total`;
- histograms become `_bucket`, `_sum` and `_count`.

Attribute keys become labels in the same way, and the resource's `service.name` becomes `job`.

| OpenTelemetry | Prometheus |
|---|---|
| `http.server.request.duration` (s) | `http_server_request_duration_seconds_bucket`, `_sum`, `_count`; labels `http_request_method`, `http_route`, `http_response_status_code` |
| `db.client.operation.duration` (s) | `db_client_operation_duration_seconds_*`; labels `db_operation_name`, `db_result` |
| `job.duration` (s) | `job_duration_seconds_*`; labels `job_queue`, `job_kind`, `job_outcome` |
| `messaging.messages` | `messaging_messages_total`; labels `messaging_operation`, `messaging_destination` |
| `engine.call.duration` (s) | `engine_call_duration_seconds_*`; labels `engine_method`, `outcome` |
| `notification.deliveries` | `notification_deliveries_total`; labels `channel`, `outcome` |
| `backlog.audit_forwarding_<destination>` | `backlog_audit_forwarding_syslog`, `backlog_audit_forwarding_otlp`; label `backlog` |
| `backlog.audit_capacity_permille` | `backlog_audit_capacity_permille` |

Duration histograms use the buckets in `telemetry.SecondBuckets` (5 ms to 15 minutes).

## Alerts and dashboards
`deploy/observability/alerts/` holds Prometheus rules: multi-window burn-rate alerts on the SLOs (99.9% availability, p95 latency under 1 second per API, 99% of job attempts succeed), plus audit forwarding, audit verification and capacity, certificate and key expiry within 30 days, backup failures and posture drift. Every alert links to its runbook in `docs/operations/runbooks/` (index: [runbooks/README.md](runbooks/README.md)). `TestAlertsHaveRunbooks` checks that every alert has a runbook and every runbook has an alert.

Self-hosted administrators can load the availability, latency, jobs and audit rules into their own Prometheus. The rules for certificates, backups and drift read SaaS exporters (cert-manager, the AWS CloudWatch exporter and the log agent), so they find no series in a self-hosted installation.

`deploy/observability/dashboards/fair-service-overview.json` is a Grafana dashboard. It shows request rates, error ratios, p95 latency by route, job outcomes, dependency latencies, and the audit backlogs.
