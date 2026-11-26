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
| `instances/<id>/` | One instance: its release pin, its values (`instance.env`) and its overlay. Its Flux bootstrap reconciles this path. |
| `rings/` | Rings and soak times (T-16) |

## Adding an instance
After `infra/instance` has been applied (`docs/operations/onboarding.md`), copy `instances/example/` to `instances/<id>/`. Fill in `instance.env` from the root's outputs:

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

`internal/fleet`'s tests check that the example sets every variable the release and the templates use. Set the release pin and the operations receiver in `kustomization.yaml`, then open a pull request. Bootstrap Flux on the cluster from the pipeline's runner, because the API endpoint is private:
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
A release reaches an instance when the pull request changing `instances/<id>/kustomization.yaml`'s release pin (`spec.ref.tag`) is merged. `cmd/fleetctl` (T-16) opens these pull requests ring by ring, after health gates and inside maintenance windows.

To roll back, open a pull request that pins the previous release. The previous release's services run on the upgraded schema: migrations follow expand–contract, and the upgrade test checks this (AC-21). There are no down migrations. Pinning an older release does not undo its successor's migrations, and its own migration Job runs again and applies nothing.

## Updating an add-on
Change the chart version and image digests in `addons/` in this repository, at least two weeks after their release. Run `scripts/fleet-check.sh` and `scripts/admission-e2e.sh`, then copy the change to the fleet repository by pull request. If the image comes through the ECR mirror, mirror it first (`infra/modules/ecr-mirror`).
