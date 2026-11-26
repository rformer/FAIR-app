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
| `organization/` | management | the organization, OUs `core` and `instances`, the guardrails (SCPs), the core accounts, delegated administrators, the management account's baseline, the instance pipeline's roles in both management accounts (`modules/instance-pipeline`, T-14) |
| `security/` | security | the log archive (Object Lock, compliance mode), the organization trail, GuardDuty and Config for the organization |
| `shared/` | shared | the KMS release key and its sign-only role (release-sign.yml), the ECR release mirror, the SaaS parent zone and its delegation roles (`modules/parent-zone`, T-14) |
| `instance-account/` | both management accounts | one instance's account: created through the commercial pair, joined, placed under `instances` (T-14; state `instances/<name>/account.tfstate`) |
| `instance/` | the instance's | one instance's stack: `account-baseline`, `instance`, its zone's delegation, the read-only `fair-instance-plan` (T-14; state `instances/<name>/terraform.tfstate`), `fair-access-eks` for accessctl's access entries (T-18) |
| `instances/` | — | the instances' specs, `<name>.tfvars` (one per customer; `examples/` is never applied) |
| `ops/` | ops | evidence, Loki and Tempo storage; just-in-time operator access (`modules/operator-access`, T-18: the FairReadOnly and FairOperator permission sets and accessctl's role); the ops cluster is still to come (T-13 built the instance module only) |
| `github/` | — | branch protection and the repository's OIDC subject template (F-012 T-02, T-12) |
| `modules/` | — | `secure-bucket`, `guardrails`, `account-baseline`, `org-security`, `release-signing`, `ecr-mirror`, `observability`, `instance`, `instance-pipeline`, `parent-zone`, `operator-access` |

Customer instances (one account each, under the `instances` OU) are built by `modules/instance` (T-13) through the roots `instance-account` and `instance`, from `infra/instances/<name>.tfvars` pull requests: planned in the pull request, applied after approval in the protected environment `instances`, checked for drift daily (`.github/workflows/infra-instances.yml`, `scripts/infra-instance.sh`, `scripts/infra-drift.sh`; T-14). Runbooks: `docs/operations/onboarding.md`, `docs/operations/decommissioning.md`; the first sandbox apply: `docs/operations/sandbox-apply.md` (not yet performed).

`scripts/infra-check.sh` also plans every spec in `infra/instances/` (and the example) against the instance root's validations with mock providers (`infra/instance/spec-tests`), and refuses a spec that sets a field outside `infra/instance/variables.tf`.

## The instance module (`modules/instance`, F-012 T-13)
One customer instance in its own account (design §3.5, ADR-016). It needs two AWS providers: `aws` (the home region) and `aws.replica` (the other GovCloud region), both with `use_fips_endpoint = true` and `allowed_account_ids = [<instance account>]`:

    module "instance" {
      source    = "../modules/instance"
      providers = { aws = aws, aws.replica = aws.replica }
      instance  = "acme"
      account_id = "<instance account>"
      domain    = "acme.<saas domain>"
    }

| What | How |
|---|---|
| Network | VPC (`vpc_cidr`, a /16) over three zones (`availability_zones`): public subnets (the load balancer and a NAT gateway each; no public addresses), workload subnets (/19; their one default route is the zone's NAT gateway), database subnets (no route out). S3 gateway endpoint and interface endpoints (`interface_endpoints`) whose policies admit this account's principals only. Flow logs (all traffic, a year). The default security group allows nothing. |
| Egress | Nodes reach outside the VPC only on `external_egress_ports` (443, 465, 587); which pods may is the platform's NetworkPolicies' (notify and integrate, F-009, F-011). No peering, no transit gateway; the ops account only through the Collector's PrivateLink endpoint (`ops_telemetry`). |
| EKS | Private API endpoint only; Secrets envelope-encrypted (key `eks`); every control-plane log; EKS access entries only (`cluster_admin_role_arns`, this account's roles), no implicit creator admin; one managed node group on `BOTTLEROCKET_x86_64_FIPS` (IMDSv2, hop limit 1, no admin or control container, volumes under key `nodes`); add-ons vpc-cni, kube-proxy, coredns, aws-ebs-csi-driver. |
| Workload roles (IRSA) | `external-secrets` (fair-platform/fair-external-secrets: `fair/<instance>/*` only), `audit` (fair-platform/audit: the audit store and WORM; never deletes WORM objects), `risk` (fair-platform/risk: the report store), `load-balancer-controller`, `privateca-issuer` (cert-manager/aws-privateca-issuer), `ebs-csi`. Output `workload_roles` gives the ARNs for the service accounts' annotations. |
| Database | RDS PostgreSQL 16 (`postgres_version`), Multi-AZ, private, key `database`, parameter group `rds.force_ssl = 1`, `ssl_min_protocol_version = TLSv1.2`, SCRAM, connection and DDL logs; 35 days of point-in-time recovery; deletion protection and a final snapshot; automated backups copied to the second region (key `database` there). The master password is RDS-managed (`rds!…`, outside `fair/<instance>/*`). |
| Object storage | `fair-<instance>-audit-worm-<account>` (Object Lock compliance, `audit_worm_retention_days`), `-audit-store-` (Object Lock, each write sets its retention), `-report-store-` (versioned), each with a `-replica-` bucket in the second region under its own key (replicas age out after `audit_retention_days` / `report_replica_days`, since the sources' deletes do not replicate). Objects are read and written only by the bucket's service role and the replication role; nothing from another account. Output `service_environment` holds the `FAIR_AUDIT_WORM_*`, `FAIR_AUDIT_STORE_*`, `FAIR_REPORT_STORE_*` bucket, endpoint (`s3-fips.<region>.amazonaws.com:443`) and region. |
| Keys | One KMS key per purpose (`alias/fair-<instance>-<purpose>`): database, audit-worm, audit-store, report-store, secrets, eks, nodes, logs; in the second region database, audit-worm, audit-store, report-store, logs; and the DNSSEC signing key. Every key policy denies principals of other accounts. |
| Secrets | Secrets Manager entries, names only: `fair/<instance>/<service>/<dir>` for the 17 entries of the F-001 T-41 layout (`docs/install/keys.md`, read by `deploy/k8s/keys/saas/external-secrets.yaml`) and `fair/<instance>/database/<role>` for the 8 database login roles. Values are loaded at onboarding through files (T-14). Only the External Secrets role may read a value, and for the key files the roles in `secret_reader_role_arns` (the pipeline's key-rotation role; never the database passwords, never operators). |
| DNS, TLS, WAF | Public zone `domain` (DNSSEC, query logs; delegate it with output `dns.name_servers` and `dns.ds_record`), private zone (`private_domain`), an ECDSA ACM certificate, the internet-facing ALB (HTTPS 443 only, `ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04`) forwarding to the gateway's target group (`gateway_target_group_arn`, HTTPS to `gateway_port`, for a TargetGroupBinding), a WAF web ACL (IP reputation, common rules with body size counted, known bad inputs, SQL injection counted, anonymous IPs, a rate limit; logs with `cookie` and `authorization` redacted); an ACM Private CA (`private_ca_arn`) for cert-manager's internal certificates. |

Outputs: `vpc_id`, `subnet_ids`, `cluster`, `workload_roles`, `database`, `buckets`, `service_environment`, `kms_keys`, `secret_names`, `gateway_target_group_arn`, `dns`, `private_ca_arn`, `web_acl_arn`, and `policy_documents` (every policy the module writes, for the isolation tests). In-cluster components (External Secrets, the load balancer controller, cert-manager, the Collector, Flux) are installed by T-15; the account's baseline is `modules/account-baseline`, composed beside this module by the instance root (`infra/instance`, T-14).

`status` (T-14) decommissions the instance: `retiring` lifts the database's and the load balancer's deletion protection only; `retired` removes the workloads and keeps every bucket and replica (the audit WORM under Object Lock), every key, the log groups and the replication role (output `retained`). The module's buckets, keys and log groups carry `prevent_destroy`; nothing in it removes a retained store (`docs/operations/decommissioning.md`).

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
3. For each core account, invite its GovCloud account (output `govcloud_account_ids`) into the GovCloud organization. Accept the invitation as the account's `OrganizationAccountAccessRole`. Then list the account in `govcloud_account_ids` and run `tofu import 'aws_organizations_account.member["<name>"]' <id>`. Applying then places the account under `core` and delegates CloudTrail, Config and GuardDuty to the security account. (Instance accounts need no such step: the instance pipeline invites, accepts, imports and places them, T-14.)
4. `security/`, then `shared/` and `ops/` (with the security root's `log_archive` output), then `organization/` again with `log_archive` (the management account's Config).
5. Set the repository variables `FAIR_RELEASE_KMS_KEY`, `FAIR_RELEASE_ROLE_ARN` and `FAIR_RELEASE_REGION` from the shared root's `github_variables` output. Apply `github/`, which sets the OIDC subject template the sign-only role's trust expects (and, T-14, the environment `instances` with its reviewers).
6. The instance pipeline (T-14): `shared/` with `parent_zone`, the parent domain's delegation at its registrar, `organization/` with `dns_delegation`, then the repository variable `FAIR_INSTANCES_CONFIG` (`docs/operations/onboarding.md`, "One-time setup").

## Changing a provider version
Change the exact version in every `versions.tf`, then run `INFRA_LOCK=1 scripts/infra-check.sh`, which rewrites every lock file with hashes for each platform.
