# F-012 T-13 (F-012-AC-14, AC-15; design §3.5, ADR-016): one customer
# instance, in an account of its own under the instances OU:
#   - network.tf: VPC over three zones; nodes and the database in private
#     subnets with no internet gateway route; egress through NAT (ports
#     limited; only notify and integrate pods may use it, by the platform's
#     NetworkPolicies) or VPC endpoints; flow logs;
#   - eks.tf: EKS with a private API endpoint only, secrets encrypted with
#     the instance's key, every control-plane log, Bottlerocket FIPS nodes;
#   - irsa.tf: IAM roles for service accounts (External Secrets, audit,
#     risk, the load balancer controller, the Private CA issuer, EBS CSI);
#   - database.tf: RDS PostgreSQL 16, Multi-AZ, encrypted, rds.force_ssl,
#     35 days of point-in-time recovery, backups copied to the second region;
#   - storage.tf: the audit WORM (Object Lock compliance), the audit store
#     (Object Lock, per-write retention) and the report store (versioned),
#     each replicated to the second region;
#   - kms.tf: one key per purpose (and per region for the replicas);
#   - secrets.tf: Secrets Manager entries for the F-001 T-41 key layout and
#     the database roles' passwords (names only, no values);
#   - dns.tf, edge.tf, pca.tf: Route 53 zones (DNSSEC, query logs), the ACM
#     certificate, the public load balancer with its WAF web ACL, and the
#     ACM Private CA for internal TLS (cert-manager).
# The account's baseline (Config, EBS default encryption, account-wide S3
# public access block) is modules/account-baseline, composed beside this
# module by the instance root (T-14).
locals {
  name = "fair-${var.instance}"
  p    = var.partition
  acct = var.account_id

  # Every principal the module names is this account's (AC-15). Role ARNs
  # are built from names, so policies do not wait on the roles.
  account_root = "arn:${local.p}:iam::${local.acct}:root"
  role_arn     = { for r in local.role_names : r => "arn:${local.p}:iam::${local.acct}:role/${local.name}-${r}" }
  role_names   = ["cluster", "nodes", "external-secrets", "audit", "risk", "load-balancer-controller", "privateca-issuer", "ebs-csi", "replication", "rds-monitoring", "flow-logs"]

  private_domain = coalesce(var.private_domain, "${var.instance}.fair.internal")
  cluster_name   = local.name

  # Buckets: fair-<instance>-<purpose>-<account> (replicas: -replica-).
  bucket         = { for b in ["audit-worm", "audit-store", "report-store", "access"] : b => "${local.name}-${b}-${local.acct}" }
  replica_bucket = { for b in ["audit-worm", "audit-store", "report-store", "access"] : b => "${local.name}-${b}-replica-${local.acct}" }

  # The S3 FIPS endpoint the services use (FAIR_*_ENDPOINT is host:port).
  s3_endpoint = "s3-fips.${var.region}.amazonaws.com:443"

  tags = merge(var.tags, { "fair:instance" = var.instance })
}
