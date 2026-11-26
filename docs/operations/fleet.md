# The SaaS fleet: how an instance gets a release

F-012 T-15 (F-012-AC-18, AC-19; design §3.6; ADR-016). Each SaaS instance's cluster runs Flux. Flux reconciles the instance to what the private fleet repository says, and the Sigstore policy-controller admits only the release's signed images. Nothing reaches an instance except through an approved pull request to the fleet repository, or through a release this repository's pipeline has signed.

## What a release publishes for the fleet
`release.yml` renders the platform's manifests with `releasegen fleet` (`internal/fleet`). They are pushed as the OCI artifact `ghcr.io/<owner>/fair-manifests:<version>` (`flux push artifact`) and signed like the images: keylessly by the release workflow, then with the KMS release key by `release-sign.yml`. `fleet.json` in the release names the artifact by digest, and `fair-fleet-<version>.tar.gz` holds the same files.

The artifact has one directory per reconciliation step:

| Directory | What it holds |
|---|---|
| `namespaces/` | Every namespace of the release and each namespace's default-deny policy |
| `secrets/` | The key store's ExternalSecrets, the database passwords and the services' certificates (`deploy/k8s/keys/saas`) |
| `migrate/` | The `iam-migrate` Job, its ServiceAccount and egress |
| `platform/` | Every other object of `deploy/k8s`, with the key mounts of `deploy/k8s/keys/secret-mounts.yaml` as patches |
| `observability/` | The Collector and its log agent (`deploy/observability/k8s-saas.yaml` and the two Collector configurations) |

Images are named by digest in the release repository. Instance values that mean one thing everywhere are Flux variables (`${FAIR_DB_HOST}`, `${FAIR_INSTANCE}`, `${FAIR_DEPLOYMENT_MODE}`, …). The rest (the stores) are set by the SaaS patches in `deploy/fleet/flux/release.yaml`. The emergency break-glass Job is not part of a release; operators run it by hand (`docs/operations/idp-outage-recovery.md`).

## The fleet repository
The fleet repository has the layout of `deploy/fleet`. It starts as a copy of `deploy/fleet`, and template changes made here are copied into it by pull request.

| Path | What it is |
|---|---|
| `release-key/cosign.pub` | The release public key: the fleet's one trust anchor. Copy the release's `cosign.pub` here after checking its fingerprint (`docs/security/verify.md`). |
| `flux/` | Each instance's Flux objects: the release source, the reconciliation steps, notifications |
| `addons/` | Cluster add-ons as HelmReleases: the policy-controller, External Secrets, cert-manager with the AWS Private CA issuer, the AWS Load Balancer Controller. Charts are pinned by exact version and images by digest. |
| `addons-config/` | The add-ons' instance configuration: the cluster issuer `fair-internal`, the External Secrets account, the gateway's TargetGroupBinding, and the RDS CA bundle (`rds-ca.pem`, AWS's public GovCloud bundle) |
| `policy/` | The admission policies |
| `instances/<id>/` | One instance: its release pin (tag and digest), its values (`instance.env`) and its overlay. Its Flux bootstrap reconciles this path. `rollout.yaml` (not a Kubernetes object) holds its ring, maintenance window, health endpoints and previous release for `cmd/fleetctl`. |
| `rings/` | The rollout's rings in order, with their soak times: `vendor` (24 h), `canary` (72 h), `general` |

## Adding an instance
After `infra/instance` has been applied (`docs/operations/onboarding.md`), copy `instances/example/` to `instances/<id>/`. Set the ring, the customer's maintenance window and the health endpoints in `rollout.yaml` (below), and remove `previous` if it was copied. Fill in `instance.env` from the root's outputs:

| Variable | From |
|---|---|
| `FAIR_INSTANCE`, `FAIR_REGION` | the spec's `instance`, `region` |
| `FAIR_DEPLOYMENT_MODE` | `saas` |
| `FAIR_CLUSTER_NAME`, `FAIR_APISERVER_CIDR` | `cluster.name`, the VPC's workload range |
| `FAIR_VPC_ID` | `vpc_id` |
| `FAIR_DB_HOST` | `database.host` |
| `FAIR_AUDIT_STORE_*`, `FAIR_AUDIT_WORM_*`, `FAIR_REPORT_STORE_*` (`_BUCKET`, `_ENDPOINT`, `_REGION`) | `service_environment` |
| `FAIR_ROLE_AUDIT`, `FAIR_ROLE_RISK`, `FAIR_ROLE_EXTERNAL_SECRETS`, `FAIR_ROLE_LOAD_BALANCER_CONTROLLER`, `FAIR_ROLE_PRIVATECA_ISSUER` | `workload_roles` |
| `FAIR_GATEWAY_TARGET_GROUP_ARN` | `gateway_target_group_arn` |
| `FAIR_PRIVATE_CA_ARN` | `private_ca_arn` |
| `FAIR_PLATFORM_HOST`, `FAIR_INGRESS_HOST`, `FAIR_INGRESS_CIDR` | the spec's `domain`, the public subnets' range |
| `FAIR_RELEASE_IMAGES`, `FAIR_MIRROR_IMAGES` | globs of where the instance pulls the release's images and the mirrored third-party images (`ghcr.io/rformer/fair-*` and `ghcr.io/rformer/mirror/*`, or the shared ECR mirror's copies) |
| `FAIR_OPS_*`, `FAIR_KSM_TARGET`, `FAIR_CERT_MANAGER_TARGET` | the operations account's endpoints and the scrape targets |

`internal/fleet`'s tests check that the example sets every variable the release and the templates use. Set the release pin (the tag and the digest from the release's `fleet.json`) and the operations receiver in `kustomization.yaml`, then open a pull request. Bootstrap Flux on the cluster from the pipeline's runner, because the API endpoint is private:
- path `instances/<id>`;
- the controllers by digest;
- the kustomize-controller with `--feature-gates=StrictPostBuildSubstitutions=true`, so a missing value fails a step instead of applying an empty string.

Onboarding also provides two Secrets that `infra/modules/instance` does not yet hold:
- `flux-system/fair-ops-events`, the HMAC token for Flux events;
- `fair-platform/otelcol-ops`, the Collector's client certificate for the operations endpoints.

## Order of reconciliation
Each step applies its directory, waits until every object in it is ready, and only then lets the next step start (`dependsOn`, `wait: true`):

1. `fair-addons`: the add-ons.
2. `fair-policy`: the admission policies. Admission enforces before any platform namespace exists.
3. `fair-namespaces`: the release's namespaces, labelled `policy.sigstore.dev/include=true`, with default-deny policies.
4. `fair-addons-config`: the issuer, the External Secrets account, the TargetGroupBinding, the database CA.
5. `fair-secrets`: keys, database passwords and certificates. Ready means every ExternalSecret has synced and every certificate has been issued.
6. `fair-migrate`: the release's `iam migrate` Job, which must complete. `force: true` replaces the Job when a new release changes it. The Job has no TTL, because Flux owns it and would otherwise run it again after the TTL deleted it. Migrations are recorded by checksum, so a rerun applies nothing twice.
7. `fair-platform`: the services.
8. `fair-observability`: the Collector and its log agent.

If a migration fails, the rollout stops at step 6, and the services keep running the previous release on the schema as it was. Every step's events go to the operations account (`flux/notifications.yaml`) for alerts and for the change-evidence export (T-17).

## What is verified
- **The release artifact.** `OCIRepository/fair-release` verifies the artifact's signature with `flux-system/fair-release-key` before it stores anything. An unsigned artifact, or one signed with another key, is refused, and the instance keeps the release it has.
- **Every image in the release's namespaces.** The policy-controller (`policy/release.yaml`) requires:
  - a signature by the release key;
  - a SLSA provenance attestation signed by that key, whose builder is the SLSA generator's container workflow at a tag and whose source is this repository's `release.yml` at a `v*` tag.

  An image that no policy matches is refused (`no-match-policy: deny`), and the webhooks fail closed.
- **Third-party images** (design §3.6, amended 2026-11-26) run only as the release's mirrored copies. Today that is the OpenTelemetry Collector. Each one is listed in `deploy/third-party-images.json` with its publisher's exact certificate identity and issuer. The release then:
  1. verifies the image against that identity with cosign 2.6.4, which reads the publishers' Sigstore bundles (the policy-controller cannot);
  2. copies it by digest to `<release repository>/mirror/<name>`;
  3. signs the copy with the release key.

  `releasegen fleet` names only the copy, and refuses any image that is neither the release's nor listed. `policy/mirror.yaml` (`fair-mirror`) requires the release key for the copies. The publisher's original, an unsigned copy and a copy signed by another key are refused.

  To add or update a third-party image, change its digest in the manifest and its entry in the list together (`internal/fleet` `TestThirdPartyList`). Take the identity from the publisher's release workflow at that version.

`scripts/admission-e2e.sh` (CI `admission-e2e`) checks all of this on kind against a stand-in release. Flux reconciles the stand-in in order, and an unsigned or other-key artifact is refused. The signed image is admitted; unsigned, other-key, other-source, provenance-less and other-repository images are refused. It also builds the real release's every step with the example instance, with every placeholder filled. `scripts/fleet-check.sh` (CI `fleet`) validates every template and the rendered release with kubeconform.

## Promotion and rollback
F-012 T-16 (F-012-AC-20, AC-21; design §3.6). A release reaches an instance when the pull request changing its release pin is merged. The pin is one line of `instances/<id>/kustomization.yaml`:

```yaml
- { op: replace, path: /spec/ref, value: { tag: v0.2.0, digest: "sha256:…" } }
```

Flux pulls by the digest, which takes precedence over the tag, so a tag pushed again changes nothing. The digest is the fleet artifact's, from the release's `fleet.json`. Keep the line as it is: `cmd/fleetctl` rewrites it. It also reads T-15's tag-only form and replaces it on the first promotion.

### What fleetctl reads
`cmd/fleetctl` (`internal/fleetctl`) runs on the pipeline's runner against a checkout of the fleet repository. It reads the fleet at a git revision (`-base`, default `HEAD`), so what it checks is what its branches start from.

`rings/<ring>.yaml` holds `ring`, `order` and `soak`. Each instance's `instances/<id>/rollout.yaml` holds:

| Key | What it is |
|---|---|
| `ring` | One of `rings/` |
| `maintenance_window` | `timezone` (IANA), `days` (`sun` … `sat`), `start` (`HH:MM`, local time) and `duration` (at most 24h). A window may cross midnight. The vendor instance's window is every day from 00:00 for 24h. |
| `health.kubernetes_api` | The cluster's private API endpoint (the instance root's cluster endpoint) |
| `health.readyz` | The gateway's readiness URLs through the load balancer |
| `previous` | The release before the pinned one. promote writes it, and rollback pins it. |
| `rolled_back_from` | The release a rollback left. promote refuses it for this instance. |

Credentials never go in the fleet repository. Health is read with:
- `-credentials DIR`: `DIR/<id>/token` and `DIR/<id>/ca.crt`, a read-only token for Flux's objects in `flux-system`;
- `-prometheus URL` (https), with `-prometheus-token FILE` and `-prometheus-ca FILE`: the operations account's query endpoint;
- `-readyz-ca FILE`: an optional CA for the readiness URLs.

Every connection uses TLS 1.2 or later. An error from any source fails the gate.

### The gates
An instance passes when every one of these holds:
1. **pin**: it is pinned to the release, tag and digest.
2. **flux**: OCIRepository `fair-release` is Ready with the release's revision. Every fleet step (`fair-addons`, `fair-policy`, `fair-addons-config`) is Ready. Every release step (`fair-namespaces`, `fair-secrets`, `fair-migrate`, `fair-platform`, `fair-observability`) is Ready, applied the release, and has observed its current generation without being suspended. `fair-migrate` Ready on the release means the migration Job succeeded, because the step waits for it.
3. **soak**: the source stored the release's artifact at least the ring's soak time ago. The artifact's `lastUpdateTime` starts the clock, and a re-fetch restarts it, which errs on the side of waiting.
4. **readyz**: every readiness URL answers 200.
5. **slo**: no SLO alert fired for the instance at any time since the soak started. These are the alerts with an `slo` label in `deploy/observability/alerts`: availability, latency and jobs, including `ServiceUnavailable`. fleetctl queries `max_over_time(ALERTS{alertstate="firing",slo!="",fair_instance="<id>"}[…])`. A silenced alert still counts.

### Status
```sh
fleetctl status -repo ../fleet -credentials /run/fleet -prometheus https://prometheus.ops.fair.internal [-json]
```
`status` prints each instance's ring, pinned release, the release `fair-platform` last applied, its health now (the gates without the soak), and its maintenance window.

### Promote
```sh
fleetctl promote -repo ../fleet -release v0.2.0 -fleet-json release/fleet.json [-ring canary] [health flags]
```
Without `-ring`, promote takes the first ring in which some instance is not on the release.
1. It checks every instance of the closest earlier ring that has instances, with that ring's soak time. The first ring has no gates.
2. The first failing instance stops the rollout. fleetctl writes nothing, does not read the instances after the one that failed, and leaves later rings untouched. It exits with status 3, the pipeline job fails, and the failure alerts.
3. Otherwise it creates one local branch per instance of the ring that is not yet on the release: `fleet/promote/<release>/<id>`. Each branch is one commit over the base that changes only the instance's pin and records the old pin as `previous`.

fleetctl never pushes. Its commit message names the instance's next maintenance window (`Fleet-Merge-After`, `Fleet-Merge-Before`). Push the branches and open one pull request per instance. promote refuses:
- a release without its digest;
- a tag older than the pin (that is a rollback);
- the pinned tag with another digest;
- a release the instance was rolled back from;
- a branch that already exists.

Promote one ring at a time. The next ring's gates need this ring's soak.

### Merge
After a human approves an instance's pull request, the bot merges it only when this passes:

```sh
fleetctl merge-check -repo ../fleet -branch fleet/promote/v0.2.0/<id> [-base main] [health flags]
```

merge-check requires exactly one instance's pin to change between base and branch.
- **A promotion** needs the time to be inside that instance's maintenance window, and the earlier ring's gates to pass again on the release. Health may have changed since promote.
- **A rollback** may merge at once.

Exit status 3 means wait: the window is closed, or a gate is failing.

### Roll back
```sh
fleetctl rollback -repo ../fleet -instance <id>[,<id>…]   # or -ring <ring>
```
rollback creates `fleet/rollback/<release>/<id>`, which pins each instance's `previous` release, records `rolled_back_from`, and clears `previous` (a rollback goes back one release). It checks no gates and no window, because the instance is failing. If any named instance has no previous release, rollback writes nothing.

The previous release's services run on the upgraded schema. Migrations follow expand–contract, and T-08's upgrade test checks this (AC-21). There are no down migrations, so nothing is lost. Pinning an older release does not undo its successor's migrations; its own migration Job runs again and applies nothing. To move on, promote a fixed release.

## Updating an add-on
Change the chart version and image digests in `addons/` in this repository, at least two weeks after their release. Run `scripts/fleet-check.sh` and `scripts/admission-e2e.sh`, then copy the change to the fleet repository by pull request. If the image comes through the ECR mirror, mirror it first (`infra/modules/ecr-mirror`).
