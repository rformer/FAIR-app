# ADR-016 SaaS infrastructure and delivery: GovCloud accounts per instance, OpenTofu, Flux, Sigstore admission
Status: Accepted (Robert Former, 2026-11-20, with the F-012 design; written by F-012 T-12)
Date: 2026-11-20

## Context
F-012 runs the SaaS offering from code (R-05, R-06). Each customer instance must be created from infrastructure-as-code with no console step (AC-14) and kept isolated from every other instance: its own data, keys and network, encryption at rest under keys of its own, FIPS-validated endpoints and TLS 1.2 or later (AC-15, ADR-001). Drift must be detected within a day (AC-16). Releases must reach the fleet only signed, in rings, with health gates (AC-18 to AC-21).

The requirements' open questions were resolved on 2026-11-19 as proposed:
- **OQ1:** AWS GovCloud (US) for SaaS v1, for the FedRAMP Moderate boundary, with managed PostgreSQL, S3 Object Lock and KMS with FIPS endpoints. Cloud specifics stay in modules, so Azure Government can follow.
- **OQ2:** OpenTofu, with state in the cloud's encrypted object store with locking, and policy checks on every plan.
- **OQ6:** a release key in the cloud's HSM-backed KMS beside keyless signatures (ADR-018).

The design (2026-11-20, §3.5, §3.6, §8) weighed:
- **Terraform:** its licence (BSL) is a risk for a product shipped to government customers. OpenTofu is a drop-in.
- **Argo CD:** a web console and its RBAC to secure and assess. Flux is pull-only and verifies signed OCI sources with cosign natively.
- **One shared EKS cluster with a namespace per customer:** cheaper, but weaker isolation for FedRAMP and CMMC customers and a shared control plane.
- **Kyverno for admission:** a broader policy engine. The Sigstore policy-controller is narrower and verifies provenance predicates directly.

## Decision
- **Cloud and accounts.** An AWS Organization in GovCloud (US), regions us-gov-west-1 and us-gov-east-1 only:
  - `management`: the organization, the guardrails, the OpenTofu state;
  - `security`: the delegated administrator of CloudTrail, GuardDuty and Config, with the organization trail and the log archive under Object Lock in compliance mode;
  - `shared`: the ECR release mirror, the KMS release key and its sign-only role;
  - `ops`: observability and fleet automation, with the evidence bucket;
  - one account per customer instance under an `instances` OU (T-13, T-14).

  GovCloud accounts are created from the paired commercial management account (`CreateGovCloudAccount`) and join the GovCloud organization by invitation.
- **Guardrails.** Service control policies on the organization root:
  - GovCloud regions only, and TLS on every request;
  - CloudTrail, GuardDuty and Config cannot be stopped or deleted, and only the infrastructure role reconfigures them;
  - no account leaves the organization;
  - S3 uploads cannot ask for anything but KMS, and RDS storage must be encrypted;
  - no public S3: public ACLs are denied, and only the infrastructure role changes public access blocks.

  IAM has no condition key for the endpoint a request used, so an SCP cannot require FIPS endpoints. They are required where the client is ours:
  - every OpenTofu AWS provider sets `use_fips_endpoint` (checked by `scripts/infra-check.sh`);
  - the S3 backend sets it too;
  - the release workflow sets `AWS_USE_FIPS_ENDPOINT`, and `internal/kmssign` uses FIPS endpoints (ADR-018).
- **Infrastructure-as-code.** OpenTofu 1.13.9 (image `ghcr.io/opentofu/opentofu:1.13.9`, pinned by digest) with the `hashicorp/aws` provider 6.72.0 (released 2026-11-04, the newest at least two weeks old on 2026-11-25), pinned exactly, with lock files carrying hashes for linux, darwin and windows.
  - **Layout:** `infra/modules/` holds one module per concern, and `infra/{state,organization,security,shared,ops}` are the roots.
  - **State:** one S3 bucket in the management account under its own KMS key, versioned, with Object Lock (governance mode, with bypass denied to everyone). Locking uses S3 conditional writes (`use_lockfile`), with no DynamoDB table. The backend is configured by partial `*.s3.tfbackend` files with nothing secret.
- **Checks.** CI's `infra` job runs `scripts/infra-check.sh` on every root and module: `tofu fmt -check`, `init -backend=false` against the committed lock files, `validate`, `tofu test` with mock providers, and Checkov 3.4.3 (`bridgecrew/checkov`, pinned by digest).
  - Nothing is planned against a real account or applied from CI on pull requests.
  - Checkov runs every Terraform check, without a platform API key. Its FedRAMP Moderate selection is a Prisma Cloud metadata filter, and the full set contains it.
  - A failed check fails the job. A check that does not apply is suppressed inline with its reason.
- **Release key.** The release key is a KMS key (`ECC_NIST_P256`, `SIGN_VERIFY`, alias `alias/fair-release`) in the shared account.
  - **Key policy:** it allows `kms:Sign` only to the sign-only role, and denies `kms:Sign` to every other principal and grants to everyone. Its administrators (the infrastructure role and a key-admin role) cannot sign.
  - **Who may sign:** the sign-only role is assumed only with a GitHub OIDC token whose `aud` is `sts.amazonaws.com` and whose `sub` matches `repo:rformer/FAIR-app:ref:refs/tags/v*:job_workflow_ref:rformer/FAIR-app/.github/workflows/release-sign.yml@refs/tags/v*`. That is this repository, a `v*` tag, and the signing reusable workflow at a `v*` tag.
  - **Subject template:** the repository's OIDC subject template (`infra/github`) adds `job_workflow_ref` to `sub`. The workflow identity is thereby checked through the one claim STS evaluates in every partition (STS's newer provider-specific claim keys were announced for the commercial regions).
  - **Permissions:** the role may call `kms:Sign`, `kms:GetPublicKey` and `kms:DescribeKey` on that key only. cosign's KMS client reads the key's metadata before signing.
- **Delivery (T-15, T-16).** Flux in each instance's cluster reconciles the release's platform manifests, published as a signed OCI artifact (an `OCIRepository` verified with cosign against the release key) under the instance's overlay. The Sigstore policy-controller admits only images signed by the release key with SLSA provenance from this repository at a `v*` tag. Rings advance by pull requests that `cmd/fleetctl` opens after health gates. The versions of Flux and the policy-controller are chosen and pinned by T-15.

## Consequences
- Every new account or resource is a reviewed change to `infra/`, and its invariants are tested without a cloud. A first apply in a GovCloud sandbox account is a recorded manual step of T-14 (design §10).
- **Account joining.** Accounts join the GovCloud organization by invitation and acceptance, which OpenTofu cannot express. For the core accounts this is a recorded bootstrap step (`infra/README.md`), and the accounts are then imported. OpenTofu's test framework cannot run `import` blocks, so the import is a command. Instance onboarding (T-14) automates the invitation in its pipeline.
- **CloudTrail delivery.** The organization trail made by the delegated administrator belongs to the management account. CloudTrail delivers to the log archive only. Threat findings come from GuardDuty, and long-term search runs over the archive.
- **Release key rotation.** The key is not rotated automatically, since KMS does not rotate asymmetric keys. Rotating it is a new key whose public key ships in a release.
- **Key administrators.** An administrator with `kms:PutKeyPolicy` could rewrite the key policy. Every such call is in the organization trail, the key-admin role is assumable only by the named principals, and the infrastructure role applies only reviewed code.
- **Repository variables.** `FAIR_RELEASE_KMS_KEY`, `FAIR_RELEASE_ROLE_ARN` and `FAIR_RELEASE_REGION` are set from the shared root's `github_variables` output after its first apply.
- **Other clouds.** A cloud other than GovCloud means new modules behind the same root interfaces, plus a new ADR.
