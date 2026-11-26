# infra: the SaaS infrastructure as code (F-012, ADR-016)

OpenTofu for the AWS GovCloud (US) organization that runs the SaaS offering, and the repository's branch protection. Nothing here is applied from CI on pull requests. Every directory is checked by `scripts/infra-check.sh` (CI job `infra`):
- `tofu fmt`, `init -backend=false` against the committed lock files, `validate`;
- `tofu test` with mock providers (no cloud call);
- Checkov over every Terraform check;
- a check that every AWS provider uses FIPS endpoints.

## Layout
| Directory | Account | Holds |
|---|---|---|
| `state/` | management | the OpenTofu state bucket (Object Lock, KMS) and its key |
| `organization/` | management | the organization, OUs `core` and `instances`, the guardrails (SCPs), the core accounts, delegated administrators, the management account's baseline |
| `security/` | security | the log archive (Object Lock, compliance mode), the organization trail, GuardDuty and Config for the organization |
| `shared/` | shared | the KMS release key and its sign-only role (release-sign.yml), the ECR release mirror |
| `ops/` | ops | evidence, Loki and Tempo storage; the ops cluster follows with T-13's cluster module |
| `github/` | — | branch protection and the repository's OIDC subject template (F-012 T-02, T-12) |
| `modules/` | — | `secure-bucket`, `guardrails`, `account-baseline`, `org-security`, `release-signing`, `ecr-mirror`, `observability` |

Customer instances (one account each, under the `instances` OU) come with T-13 (the instance module) and T-14 (`infra/instances/*.tfvars`, onboarding, drift, decommissioning). The `instances` OU exists and is empty until then.

## State
Each root's state is `<root>/terraform.tfstate` in the bucket `fair-tofu-state-<management account id>`:
- encrypted with `alias/fair-tofu-state`;
- locked by S3 conditional writes (`use_lockfile`);
- reached through FIPS endpoints.

The backend configuration is partial: `<root>.s3.tfbackend` (committed, nothing secret) plus the bucket at init:

    tofu init -backend-config=<root>.s3.tfbackend -backend-config="bucket=fair-tofu-state-<id>"

Member-account roots assume `OrganizationAccountAccessRole` (the infrastructure role) in their account. The state stays in the management account.

## Bootstrap (once, recorded as a change)
1. `state/`: apply with a local state, then run `tofu init -migrate-state` with its backend configuration.
2. `organization/`: apply. This creates the organization, the OUs and the guardrails, and creates the core accounts through the paired commercial management account (`create_govcloud`).
3. For each core account, invite its GovCloud account (output `govcloud_account_ids`) into the GovCloud organization. Accept the invitation as the account's `OrganizationAccountAccessRole`. Then list the account in `govcloud_account_ids` and run `tofu import 'aws_organizations_account.member["<name>"]' <id>`. Applying then places the account under `core` and delegates CloudTrail, Config and GuardDuty to the security account.
4. `security/`, then `shared/` and `ops/` (with the security root's `log_archive` output), then `organization/` again with `log_archive` (the management account's Config).
5. Set the repository variables `FAIR_RELEASE_KMS_KEY`, `FAIR_RELEASE_ROLE_ARN` and `FAIR_RELEASE_REGION` from the shared root's `github_variables` output. Apply `github/`, which sets the OIDC subject template the sign-only role's trust expects.

## Changing a provider version
Change the exact version in every `versions.tf`, then run `INFRA_LOCK=1 scripts/infra-check.sh`, which rewrites every lock file with hashes for each platform.
