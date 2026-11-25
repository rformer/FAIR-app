# ServiceUnavailable

Alert rule: `deploy/observability/alerts/availability.yaml`. Severity: critical (pages). F-012-AC-24.

## Meaning
A Deployment in the `fair-platform` namespace has had no available pod for 5 minutes. A service with no pods sends no telemetry, so the availability alerts cannot see it.

## Impact
Everything that service serves is down. The gateway answers 502 for its routes; the audit service down means producers queue in `audit.intake` until it returns; the posture service down means settings go stale and services fail closed after their timeout.

## Where the signal comes from
kube-state-metrics (`kube_deployment_status_replicas_available`, `kube_deployment_spec_replicas`), scraped by the instance Collector (`collector-saas.yaml`).

## First checks
1. `kubectl -n fair-platform get deploy,pods` and `kubectl -n fair-platform describe pod <pod>`: crash loop, image pull refusal, pending scheduling, failed readiness?
2. Admission refusals (Sigstore policy-controller): an image without a valid signature or provenance is refused on purpose.
3. The pod's last logs (`kubectl logs --previous`): services refuse to start on a missing key file, an unbound setting, an unsafe environment (`CheckInstall`) or a missing database migration.

## Remediation
- Start refusal: correct the configuration it names through the fleet repository (a pull request), never by editing the cluster.
- Image refused by admission: do not bypass the policy; check the release's signatures (`scripts/verify-release.sh`) and the fleet pin.
- Node or capacity problem: check the node group in EKS; scale through `infra/`.

## Escalation
Page the platform on-call; escalate to the platform engineering lead after 15 minutes without recovery. An admission refusal of a released image is a security matter: tell security.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
