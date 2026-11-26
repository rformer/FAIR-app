# Onboarding a SaaS instance (F-012 T-14)

F-012-AC-14, AC-16; design §3.5; ADR-016. Every customer instance is a file, `infra/instances/<name>.tfvars`, and a pull request. The pipeline (`.github/workflows/infra-instances.yml`, `scripts/infra-instance.sh`) creates the account and the stack from it after approval. No console step is involved.

## What the pipeline builds

| Root | Account | What it holds | State |
|---|---|---|---|
| `infra/instance-account` | the two management accounts | The account, created through the paired commercial management account with its GovCloud account (`CreateGovCloudAccount`), then imported as a member of the GovCloud organization under the `instances` OU. | `instances/<name>/account.tfstate` |
| `infra/instance` | the instance's account | `modules/account-baseline`, `modules/instance` (T-13), the zone's NS and DS records in the SaaS parent zone, and the read-only role `fair-instance-plan`. | `instances/<name>/terraform.tfstate` |

OpenTofu has no resource for the invitation or its acceptance (ADR-016, "Account joining"). The script makes both calls itself:
1. `InviteAccountToOrganization` from the management account.
2. `AcceptHandshake` inside the new account, as its `OrganizationAccountAccessRole`. That role trusts the management account, and the apply role may assume it only while the account belongs to no organization.

The script then imports the account and moves it under the `instances` OU. That plan may change nothing else.

### Roles

The roles are defined in `infra/modules/instance-pipeline` (composed by `infra/organization`) and `infra/modules/parent-zone` (composed by `infra/shared`). Each pipeline role is assumed only with this repository's GitHub OIDC token for `infra-instances.yml`. The token's subject follows the repository's template (`infra/github/oidc.tf`).

| Role | Trusted by | May |
|---|---|---|
| `fair-instances-plan` (both management accounts) | `repo:rformer/FAIR-app:pull_request:job_workflow_ref:…/infra-instances.yml@refs/pull/*/merge` and `…:ref:refs/heads/main:…@refs/heads/main` (pull requests, main, daily drift) | Read the `instances/` state and the organization. Assume `fair-instance-plan` in accounts of the `instances` OU, and `fair-dns-read`. Write nothing. |
| `fair-instance-plan` (each instance account) | the management account's `fair-instances-plan` only | AWS `ReadOnlyAccess`, minus every data read: objects, secret values, decryption, database and cluster sessions, log contents, parameters, console output. It cannot assume any further role. |
| `fair-instances-apply` (both management accounts) | `repo:rformer/FAIR-app:environment:instances:job_workflow_ref:…/infra-instances.yml@refs/heads/main` only | Write the `instances/` state. Invite, move and tag accounts. Assume `OrganizationAccountAccessRole` in accounts of the `instances` OU, or in a new account outside any organization. Never in the management or a core account, and those accounts can never be moved or tagged. Never close or remove an account. In the commercial account: `CreateGovCloudAccount` only. |
| `fair-dns-read`, `fair-dns-delegate` (shared account) | the plan role and the apply role, respectively | Read the parent zone. The delegate may also change NS and DS records of names under the parent domain, and nothing else. |

Two limits apply to plans of pull requests:
- A pull request's plan runs the pull request's own workflow and script. Anyone who can push a branch to this repository can therefore read any instance's configuration through `fair-instance-plan`, but cannot write, and cannot read data.
- Pull requests from forks receive no OIDC token.

## One-time setup (after the T-12 bootstrap, `infra/README.md`)

1. **Apply `infra/organization`.** This creates the pipeline's roles: output `instances_pipeline`.
2. **Apply `infra/shared`** with `parent_zone = { domain, plan_role_arn, apply_role_arn }`, taking the ARNs from `instances_pipeline`. This creates the parent zone and its two roles.
3. **Delegate the parent domain at its registrar,** once. Use output `parent_zone_registrar`: the NS records, and the DS record for DNSSEC.
4. **Apply `infra/organization` again** with `dns_delegation`, taking `read_role_arn` and `delegate_role_arn` from the shared root's output `dns_delegation`. The pipeline's roles may then assume the parent zone's roles.
5. **Set the repository variable `FAIR_INSTANCES_CONFIG`.** It holds no secret:

   ```json
   {
     "management_account_id": "<12 digits>",
     "commercial_account_id": "<12 digits>",
     "region": "us-gov-west-1",
     "state_bucket": "fair-tofu-state-<management account id>",
     "instances_ou_id": "<instances_pipeline.instances_ou_id>",
     "roles": {
       "plan": "<instances_pipeline.plan>",
       "apply": "<instances_pipeline.apply>",
       "commercial_plan": "<instances_pipeline.commercial_plan>",
       "commercial_apply": "<instances_pipeline.commercial_apply>"
     },
     "log_archive": { "bucket": "<security root log_archive.bucket>", "kms_key_arn": "<log_archive.kms_key_arn>" },
     "dns": "<shared root output dns_delegation>",
     "ops_telemetry": null
   }
   ```

6. **Apply `infra/github`** with `instance_reviewers`, the GitHub ids of one to six people or teams. This creates the protected environment `instances`. Its rules: required reviewers, no self-review, no admin bypass, protected branches only. Until this environment exists, the apply job has nothing to wait for. Apply it before setting `FAIR_INSTANCES_CONFIG`.

Until `FAIR_INSTANCES_CONFIG` is set, the workflow runs only its checks that need no AWS.

## Onboarding a customer

1. **Write the spec.** Copy `infra/instances/examples/example.tfvars` to `infra/instances/<name>.tfvars` and fill it in:
   - `instance`: the file's name, 3 to 21 characters.
   - `account_email`: a distribution list that owns the account.
   - `domain`: `<name>.<parent domain>`.
   - The regions, zones, range and sizes.
   - `audit_worm_retention_days` and `audit_retention_days`: the agreed retention of the audit trail.
   - `status = "active"`.

   A spec may set only the fields in `infra/instance/variables.tf`. The pipeline's own values (`infra/instance/pipeline.tf`: the account, the mode, the roles, the log archive, the parent zone) are refused in a spec.
2. **Open a pull request.** CI checks the spec against every validation (`scripts/infra-check.sh`, mock providers). `infra-instances.yml` then plans read-only and comments the plan on the pull request. For a new instance, only the account's creation can be planned yet. The stack's first plan runs in the apply job, after the account exists, and must only create.
3. **Review and merge.** A code owner approves (branch protection, T-02). On main the plan runs again. The apply job then waits in the environment `instances` until a reviewer approves it. The reviewer sees main's plan (job summary) and cannot be the person who pushed.
4. **Apply.** After approval, `scripts/infra-instance.sh apply` runs these steps for each instance, one instance at a time:
   1. Account: applied only if its plan's digest equals the plan on main.
   2. Invitation and acceptance, import, placement under `instances`.
   3. Stack: applied only if its digest equals the approved plan's. A first apply must be creation only.
   4. Secrets' values: only entries without a value.
      - The key files come from one `iam keys init`, as a whole set, as one JSON object per entry (`deploy/k8s/keys/saas/external-secrets.yaml`). A partial set is refused; add missing directories with `iam keys upgrade` (`docs/install/keys.md`).
      - Each database role gets a 33-byte random password (`{"password": …}`).

      The key set is made on the runner, in memory (`/dev/shm`), and removed when the step ends.
5. **Hand over to the fleet (T-15).** The root's outputs `service_environment`, `workload_roles` and `cluster` feed the instance's overlay. The in-cluster steps that need the private cluster and database belong to T-15's fleet templates:
   - External Secrets, the load balancer controller and cert-manager;
   - `iam keys register` of the DB-context key;
   - `scripts/db-bootstrap.sh` with the role passwords;
   - `iam migrate`.

## Changing an instance

A change is a pull request to its spec, or to `infra/instance`, `infra/instance-account` or `infra/modules`. A change to a root or module plans every instance. Each instance's plan is posted to the pull request. After merge, the apply job applies an instance only if its plan on main, shown to the approver, has the same digest as the plan made at apply time (`cmd/infraplan digest`: every changed address and action). If anything moved in between, the apply refuses; re-run the workflow on main to plan again.

## Drift (F-012-AC-16)

Every day (05:41 UTC) the `drift` job plans every instance's two roots read-only with `tofu plan -detailed-exitcode`. The `report` job then decides with `scripts/infra-drift.sh` and opens or comments on the issue labelled `drift` when:
- an instance's plan would change something: drift, or a change not yet applied;
- an instance could not be planned.

The issue lists each instance's planned changes and what changed outside OpenTofu. Changes outside OpenTofu that touch nothing the code sets are reported in a later drift issue, not alerted on their own.

Handle drift in one of two ways: revert the change made outside the pipeline, or make it a reviewed change to `infra/`. Changes reach the accounts only through approved code. The decision logic has a dry run that needs no AWS (`scripts/infra-drift.sh -dry-run`, CI job `infra-drift`) over recorded plans in `internal/infraplan/testdata/drift`.

## Records

The pull request, its plan comment, main's plan and the environment approval are the change's record (design §3.8). The apply job's log holds the applied plan.
