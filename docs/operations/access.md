# Just-in-time operator access

F-012 T-18 (F-012-AC-27; design §3.9, §6 "E: operators hold standing access to customer data"). Nobody holds standing access to a customer instance's account. An operator asks for access with a pull request to the fleet repository. A second operator approves it. `accessctl` then grants it for at most 8 hours and removes it at the end. Every change is recorded.

Customer data stays out of reach throughout. Neither role reads the stores' objects, secret values or the database. Reading customer data is possible only through the platform's break-glass (F-001 T-34/T-35, `docs/operations/idp-outage-recovery.md`), which needs the customer's recorded consent and is audited in the customer's own trail.

## The two roles
| Role | AWS (IAM Identity Center permission set) | Kubernetes (EKS access entry) |
|---|---|---|
| `read-only` | `FairReadOnly`: AWS's `ViewOnlyAccess` (configuration, never contents), plus reaching the instance's cluster | `AmazonEKSViewPolicy` at cluster scope (no Secrets) |
| `operator` | `FairOperator`: the same, plus scaling the node group, rebooting the database and reading the cluster's control-plane logs | The view policy, plus the group `fair:operator` (`deploy/fleet/addons-config/operator-access.yaml`): delete and evict pods (restart), scale Deployments and StatefulSets, cordon nodes |

Both permission sets explicitly deny every data-plane action (`infra/modules/operator-access`, `denied_actions`):
- reading or writing the stores' objects;
- reading or changing secret values;
- using the keys;
- `rds-db:connect`, the Data API, or changing the database, snapshotting, restoring or exporting it;
- sessions on or commands to nodes, console output, and snapshots of volumes;
- issuing certificates from the private CA;
- changing DNS records;
- changing the cluster's access entries or pod identities;
- any IAM change, passing or assuming a role;
- CloudShell.

In Kubernetes, neither role reads Secrets, execs, attaches, port-forwards or proxies into a pod, or creates or changes a workload. Changes to the platform go through the fleet repository.

Sessions last an hour (`session_duration`). A session started before a removal therefore lasts at most an hour after it. An EKS access entry stops working as soon as it is removed.

## Requesting access
Add `access/requests/<id>.yaml` to the fleet repository in a pull request. The id is lower-case letters, digits and dashes, such as `acme-2026-11-26-incident-42`. The format is `fair.access-request.v1`, and its schema is `access/request.schema.json`:

    format: fair.access-request.v1
    operator: alice          # who gets access (access/operators.yaml)
    approver: bob            # the second operator who approves the pull request
    instance: acme           # access/instances.yaml
    role: operator           # read-only or operator
    reason: Restart the risk service after the engine certificate rotation
    ticket: OPS-42
    start: 2026-11-26T10:00:00Z   # UTC
    duration: 4h             # minutes or hours, at most 8h

The pull request's check (`accessctl check`) refuses a request that:
- breaks the schema or lasts more than 8 hours;
- names the operator as their own approver (by name, GitHub login or user id);
- names someone who is not in `access/operators.yaml`, or an instance that is not in `access/instances.yaml`.

Against the base branch, it also refuses removing or changing a merged request, except by adding `revoked`.

The approver named in the request approves the pull request. The fleet repository's branch protection requires a code owner's approval that is not by the last pusher (as `infra/github` does here).
## What accessctl does
The fleet repository's `.github/workflows/access.yml` (template `deploy/fleet/.github/workflows/access.yml`) runs `accessctl` as `fair-access-controller` in the operations account. Its only credential is the workflow's OIDC token in the environment `access` (main only).

1. **On merge**, it grants each added request whose window has begun:
   - It assigns the role's permission set to the operator in the instance's account (`CreateAccountAssignment`) and waits until the assignment is provisioned.
   - It finds the role Identity Center provisioned there (`AWSReservedSSO_<permission set>_…`).
   - Through `fair-access-eks` in that account (`infra/instance/access.tf`), it creates the role's access entry and associates the view policy. A request whose start is still ahead is refused; run the workflow by hand at the start, or merge it then.
2. **Every 15 minutes**, and after every merge, `accessctl expire` removes every assignment of a FAIR permission set and every FAIR access entry that no active request backs:
   - expired requests;
   - revoked requests;
   - group assignments;
   - assignments made by hand;
   - assignments in an account missing from `access/instances.yaml`.

   It never grants. Access therefore ends at most about 15 minutes after its end time even if a run is missed, plus at most an hour for a session already open.
3. **By hand** (`workflow_dispatch` with `revoke` and `reason`), `accessctl revoke` ends a request at once: the operator's assignment, and the role's access entry once nobody else holds the role there. Then record the revocation in the request by pull request (`revoked: {at, by, reason}`), so it is part of the record.

`accessctl list` shows each current grant and the request that backs it. Grants that no request backs are marked; `expire` removes them.

## Records
- Each change is a JSON line in the job log and in the run's artifact `access-record-<run>` (kept 90 days). The line holds the time, the action (`assignment_created`, `assignment_present`, `assignment_deleted`, `access_entry_created`, `access_entry_deleted`), the request, operator, approver, ticket, instance, account, role, principal, expiry and reason.
- CloudTrail, in the organization trail of the security account's log archive, records every Identity Center and EKS call, and the operator's own actions under their session.
- The requests themselves stay in the fleet repository's history.

## Setting it up (once)
1. Enable IAM Identity Center in the GovCloud management account (console; OpenTofu cannot enable an organization instance). Apply `infra/organization` once the ops account has joined: it registers the ops account as Identity Center's delegated administrator (`sso.amazonaws.com`).
2. Apply `infra/ops` with `operator_access`:
   - `sso_instance_arn`: from the Identity Center console;
   - `fleet_repository`;
   - `instances_ou_path`: the organization root's output.

   The output `operator_access` holds `controller_role_arn` and the values of `access/controller.yaml`.
3. Add `access_controller_role_arn` to the repository variable `FAIR_INSTANCES_CONFIG`, then apply each instance (`infra-instances.yml`). This creates `fair-access-eks` in every instance account.
4. In the fleet repository:
   - fill in `access/controller.yaml`, `access/operators.yaml` (each operator's IAM Identity Center user id and GitHub login) and `access/instances.yaml` (each instance's account, region and cluster);
   - create the environment `access` (deployment branch main);
   - set the variables `FAIR_ACCESS_ROLE_ARN`, `FAIR_PLATFORM_REPOSITORY` and `FAIR_PLATFORM_REF` (a full commit of a release); if the platform repository is private, also set the secret `FAIR_PLATFORM_READ_TOKEN` (read-only);
   - make the operators code owners of `access/`.

When an instance is onboarded (`docs/operations/onboarding.md`), add it to `access/instances.yaml`. When it is decommissioned, remove it; `expire` then removes anything left in its account.
