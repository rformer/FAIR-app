# Decommissioning a SaaS instance (F-012 T-14)

F-012-AC-17; design §3.5. An instance is decommissioned in two pull requests to its spec, `infra/instances/<name>.tfvars`. Each is planned, approved and applied like any change (`docs/operations/onboarding.md`). The pull requests are the decommissioning's record.

What decommissioning keeps:
- the customer's export and the audit trail, for the agreed retention;
- the stores, every key, the logs and the account itself.

No code path removes a retained store:
- The buckets (`modules/secure-bucket`), the instance's keys and its log groups carry `prevent_destroy`. A plan that would remove one fails.
- The audit WORM bucket is under Object Lock in compliance mode, which nobody can shorten.
- The pipeline's roles are denied `CloseAccount` and `RemoveAccountFromOrganization`.

## 1. Retiring

The first pull request sets:

```hcl
status = "retiring"
retirement = {
  change       = "<the change record: ticket or contract reference>"
  requested_on = "YYYY-MM-DD"
  retain_until = "YYYY-MM-DD" # at least audit_worm_retention_days after requested_on
}
```

The instance keeps running. Only the database's and the load balancer's deletion protection is lifted (`modules/instance`, `local.protected`), so the next step can remove them. The database still leaves its final snapshot `fair-<name>-final` and keeps its automated backups.

While the instance is retiring, take the exports:

1. **The customer's export.** The risk data is `GET /api/v1/risk/export?bu=<root BU>` (F-003, `fair.risk.v1`; `X-Fair-Digest` is its SHA-256), plus the reports agreed in the contract (F-010). Hand it to the customer through the agreed channel. Record its SHA-256.
2. **The audit evidence export.** Export the whole trail: `POST /api/v1/audit/exports` (F-002, `audit.export` at the root). The service stores the signed ZIP in the audit store, under Object Lock. Check it with `fair-audit-verify verify-export -keys <the checkpoint public keys>` (`docs/operations/audit-verification.md`). Record its SHA-256.

## 2. Retired

The second pull request sets `status = "retired"` and records both digests:

```hcl
status = "retired"
retirement = {
  change                 = "<the same change record>"
  requested_on           = "YYYY-MM-DD"
  retain_until           = "YYYY-MM-DD"
  customer_export_sha256 = "<64 hex digits>"
  audit_export_sha256    = "<64 hex digits>"
}
```

A spec without both digests is refused (`infra/instance` validation). The apply removes the workloads and keeps the rest:

| Removed | Kept |
|---|---|
| The VPC, subnets, NAT gateways, endpoints and flow log; the EKS cluster, nodes and add-ons; the database instance; the load balancer, WAF and certificate; the public and private zones with their delegation in the parent zone; the Private CA; the Secrets Manager entries (30-day recovery window); the workload (IRSA) roles and the cluster's OIDC provider. | Every bucket and replica: the audit WORM (Object Lock compliance) and audit store (Object Lock), the report store, the access logs. Every KMS key, so the stores, logs, snapshot and backups stay readable. Every log group (flow, cluster, database, DNS, WAF; a year). The replication role. The account baseline (Config) and `fair-instance-plan`, so the daily drift job still checks what is kept. The database's final snapshot and its automated backups (outside OpenTofu's state). |

Output `retained` lists what is kept.

## 3. After the retention

When `retain_until` has passed and Object Lock has released the audit copies, closing the account is a separate change, recorded and approved like this one. The pipeline cannot close it: its roles are denied `CloseAccount`. An operator closes the account through just-in-time access (design §3.9), with a second approval. AWS then removes the account's remaining resources after its post-closure period. Remove the spec and the two state files (`instances/<name>/account.tfstate`, `instances/<name>/terraform.tfstate`) in the same change.

## Checks

`tofu test` asserts the decommissioning rules:
- `infra/modules/instance/tests`, runs `retiring_lifts_only_the_workloads_deletion_protection`, `retired_removes_the_workloads` and `retired_keeps_every_retained_store`;
- `infra/instance/tests`, runs `retired_keeps_the_retained_stores` and `retired_needs_both_exports`;
- `infra/modules/instance-pipeline/tests`: no account is ever closed or removed.

The drift dry run includes a plan that would delete a retained store; the drift job reports it.
