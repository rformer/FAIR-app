# First apply in a GovCloud sandbox account (F-012 T-14)

> **Status: Not yet performed.** This needs a GovCloud sandbox organization (a management account, its paired commercial account and an empty `instances` OU) and an operator with credentials there. T-14 is not Done until the record below is filled in and reviewed.

F-012 design §10: the infrastructure is verified here by `tofu validate`, `tofu test` with mock providers, Checkov and plan review. Nothing has been applied to a real account. This page is the procedure for the first real apply, and its record.

## Procedure

Run it in a sandbox organization, never production. It uses the same pipeline as production (`docs/operations/onboarding.md`). The pipeline runs from a private copy of this repository, a sandbox repository. Its `infra/organization` is applied with `repository = "<owner>/<sandbox repository>"`, so the sandbox roles trust only the copy's `infra-instances.yml`. The copy's `FAIR_INSTANCES_CONFIG` names the sandbox organization, and its `instances` environment has a reviewer.

1. **Bootstrap the sandbox organization** (`infra/README.md`, "Bootstrap"): `state`, `organization` (including `instances_pipeline`), `security`, `shared` with `parent_zone`, then `organization` with `dns_delegation`. Delegate the sandbox parent domain at its registrar.
2. **Write a spec.** In the sandbox repository, open a pull request adding `infra/instances/sandbox.tfvars` from the example. Keep the plan comment: the account's creation.
3. **Apply it.** Merge, then approve the apply job in the `instances` environment. The pipeline creates and joins the account, plans the stack (creation only), applies it and loads the secrets' values.
4. **Check the result:**
   - The next drift run (`workflow_dispatch`) reports no changes in either root, and `report` exits 0.
   - The audit WORM bucket's Object Lock is compliance mode (`aws s3api get-object-lock-configuration`).
   - The parameter group has `rds.force_ssl = 1`, and a `psql` connection without TLS is refused.
   - The EKS endpoint is private only.
   - The parent zone delegates the instance's zone, and DNSSEC validates (`dig +dnssec`).
   - Every Secrets Manager entry has a value. `fair-instance-plan` cannot read one (`GetSecretValue` denied).
   - `fair-instance-plan` cannot write (any `Create*` call is denied).
5. **Confirm the open items noted in the code:**
   - the interface endpoint list (`modules/instance` `interface_endpoints`);
   - WAF SQL-injection rules in count mode against risk documents' free text;
   - `aws:ResourceOrgPaths` and `aws:ResourceOrgID` on `sts:AssumeRole` in GovCloud (`modules/instance-pipeline`);
   - the Route 53 record-name and record-type condition keys in GovCloud (`modules/parent-zone`);
   - the permissions `CreateGovCloudAccount` needs (`iam:CreateServiceLinkedRole`);
   - Route 53 query logging to a log group in the home region;
   - whether replicated automated backups stay after replication stops (decommissioning).
6. **Decommission it** through `retiring` and `retired` (`docs/operations/decommissioning.md`). Check that:
   - every bucket, key and log group in output `retained` still exists;
   - the final snapshot exists.

   Leave the account for its retention, or close it as the runbook's step 3 says.

## Record (to be filled in by the operator)

| Field | Value |
|---|---|
| Date and operator | *not yet performed* |
| Sandbox management account | *redacted form, e.g. `1111…1111`* |
| Instance account | *redacted form* |
| Sandbox repository and runs | *the copy; links to the plan, apply and drift runs* |
| Commit applied | *full SHA (and this repository's commit it copies)* |
| OpenTofu and provider | 1.13.9, hashicorp/aws 6.72.0 (or as applied) |
| Account plan summary | *counts to create / update / delete; digest* |
| Stack plan summary | *counts to create (creation only); digest* |
| Apply output summary | *resources created per root; duration; any retries* |
| Secrets loaded | *number of entries with a value / 25* |
| Drift run after the apply | *exit codes of both roots; the report's decision* |
| Checks of step 4 | *each: pass or fail, with a note* |
| Open items of step 5 | *each: confirmed, or the change made* |
| Decommissioning checks of step 6 | *retained resources present; snapshot present* |
| Findings and follow-up changes | *links to issues or pull requests* |
| Reviewed by | *a second engineer* |
