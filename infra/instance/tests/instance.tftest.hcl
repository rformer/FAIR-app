# F-012 T-14 (F-012-AC-14, AC-16, AC-17; design §3.5, §6): the instance root,
# with mock providers (no AWS call): the composition (baseline, instance,
# delegation, plan role), the spec's validations, the plan role is read-only,
# applies stay in the instance's account, decommissioning keeps the retained
# stores. The values are infra/instances/examples/example.tfvars' (also
# tested as a file by tests/tfvars.tftest.hcl, scripts/infra-check.sh).
mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:777777777777:key/00000000-0000-0000-0000-000000000100" }
  }
  mock_resource "aws_eks_cluster" {
    defaults = {
      identity              = [{ oidc = [{ issuer = "https://oidc.eks.us-gov-west-1.amazonaws.com/id/0123456789ABCDEF0123456789ABCDEF" }] }]
      certificate_authority = [{ data = "LS0tLS1CRUdJTg==" }]
    }
  }
  mock_resource "aws_db_instance" {
    defaults = {
      arn                = "arn:aws-us-gov:rds:us-gov-west-1:777777777777:db:fair-example"
      master_user_secret = [{ secret_arn = "arn:aws-us-gov:secretsmanager:us-gov-west-1:777777777777:secret:rds!db-0000", kms_key_id = "k", secret_status = "active" }]
    }
  }
  mock_resource "aws_vpc_endpoint" {
    defaults = { dns_entry = [{ dns_name = "vpce-0000.vpce-svc-0000.us-gov-west-1.vpce.amazonaws.com", hosted_zone_id = "Z0000" }] }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws-us-gov:iam::777777777777:role/fair-example-mock" }
  }
  mock_resource "aws_secretsmanager_secret" {
    defaults = { arn = "arn:aws-us-gov:secretsmanager:us-gov-west-1:777777777777:secret:fair/example/mock-AbCdEf" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws-us-gov:logs:us-gov-west-1:777777777777:log-group:mock" }
  }
  mock_resource "aws_lb" {
    defaults = {
      arn      = "arn:aws-us-gov:elasticloadbalancing:us-gov-west-1:777777777777:loadbalancer/app/fair-example/0123456789abcdef"
      dns_name = "fair-example-0123.us-gov-west-1.elb.amazonaws.com"
      zone_id  = "Z0000000000000"
    }
  }
  mock_resource "aws_lb_target_group" {
    defaults = { arn = "arn:aws-us-gov:elasticloadbalancing:us-gov-west-1:777777777777:targetgroup/fair-example-gw/0123456789abcdef" }
  }
  mock_resource "aws_wafv2_web_acl" {
    defaults = { arn = "arn:aws-us-gov:wafv2:us-gov-west-1:777777777777:regional/webacl/fair-example/00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_acmpca_certificate_authority" {
    defaults = { arn = "arn:aws-us-gov:acm-pca:us-gov-west-1:777777777777:certificate-authority/00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_acm_certificate" {
    defaults = { arn = "arn:aws-us-gov:acm:us-gov-west-1:777777777777:certificate/00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_acmpca_certificate" {
    defaults = { arn = "arn:aws-us-gov:acm-pca:us-gov-west-1:777777777777:certificate-authority/00000000-0000-0000-0000-000000000000/certificate/0000" }
  }
  mock_resource "aws_launch_template" {
    defaults = { id = "lt-0123456789abcdef0" }
  }
  mock_resource "aws_iam_openid_connect_provider" {
    defaults = { arn = "arn:aws-us-gov:iam::777777777777:oidc-provider/oidc.eks.us-gov-west-1.amazonaws.com/id/0123456789ABCDEF0123456789ABCDEF" }
  }
  mock_resource "aws_route53_zone" {
    defaults = { zone_id = "Z0EXAMPLE000000", name_servers = ["ns-1.awsdns-01.org", "ns-2.awsdns-02.com"] }
  }
  mock_resource "aws_route53_key_signing_key" {
    defaults = { ds_record = "12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" }
  }
}

mock_provider "aws" {
  alias = "replica"
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-east-1:777777777777:key/00000000-0000-0000-0000-000000000200" }
  }
}

mock_provider "aws" {
  alias = "dns"
}

variables {
  # infra/instances/examples/example.tfvars
  instance                  = "example"
  account_email             = "aws+fair-example@fair-risk.example"
  domain                    = "example.fair-risk.example"
  region                    = "us-gov-west-1"
  replica_region            = "us-gov-east-1"
  availability_zones        = ["us-gov-west-1a", "us-gov-west-1b", "us-gov-west-1c"]
  vpc_cidr                  = "10.40.0.0/16"
  node_instance_types       = ["m6i.xlarge"]
  node_count                = { min = 3, desired = 3, max = 9 }
  db_instance_class         = "db.r6i.large"
  audit_worm_retention_days = 2557
  audit_retention_days      = 2557
  status                    = "active"
  retirement                = null

  # The pipeline's (scripts/infra-instance.sh).
  account_id            = "777777777777"
  management_account_id = "111111111111"
  log_archive = {
    bucket      = "fair-log-archive-444444444444"
    kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:444444444444:key/00000000-0000-0000-0000-000000000001"
  }
  dns = {
    account_id        = "222222222222"
    zone_id           = "Z0PARENT0000000"
    domain            = "fair-risk.example"
    read_role_arn     = "arn:aws-us-gov:iam::222222222222:role/fair-dns-read"
    delegate_role_arn = "arn:aws-us-gov:iam::222222222222:role/fair-dns-delegate"
  }
}

run "the_composition" {
  command = plan

  assert {
    condition     = output.status == "active" && output.account_id == "777777777777" && length(output.secret_names) == 25
    error_message = "the instance in its account, with the key layout's entries to load"
  }
  assert {
    condition = alltrue([
      aws_route53_record.delegation_ns[0].zone_id == "Z0PARENT0000000", aws_route53_record.delegation_ns[0].name == "example.fair-risk.example",
      aws_route53_record.delegation_ns[0].type == "NS", aws_route53_record.delegation_ns[0].records == toset(["ns-1.awsdns-01.org", "ns-2.awsdns-02.com"]),
      aws_route53_record.delegation_ds[0].type == "DS", aws_route53_record.delegation_ds[0].records == toset(["12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"]),
    ])
    error_message = "the zone is delegated in the parent zone (NS from the instance's zone, DS from its signing key): no manual DNS step"
  }
  assert {
    condition     = module.baseline.config_recorder == "fair"
    error_message = "the account baseline (Config to the log archive) is applied beside the instance"
  }
  assert {
    condition     = output.service_environment.FAIR_AUDIT_WORM.FAIR_AUDIT_WORM_BUCKET == "fair-example-audit-worm-777777777777"
    error_message = "the instance's stores are named for it and its account"
  }
}

run "the_plan_role_is_read_only" {
  command = plan

  assert {
    condition     = output.pipeline.plan_role_policies == ["arn:aws-us-gov:iam::aws:policy/ReadOnlyAccess"]
    error_message = "the plan role's one managed policy is AWS ReadOnlyAccess"
  }
  assert {
    condition     = alltrue([for s in jsondecode(output.pipeline.plan_role_denied).Statement : s.Effect == "Deny" && s.Resource == "*"])
    error_message = "its inline policy only denies (it allows nothing)"
  }
  assert {
    condition = length(setsubtract(["s3:GetObject*", "secretsmanager:GetSecretValue", "kms:Decrypt", "kms:GenerateDataKey*", "rds-db:connect", "eks:AccessKubernetesApi", "logs:GetLogEvents", "sts:AssumeRole*"],
    flatten([for s in jsondecode(output.pipeline.plan_role_denied).Statement : s.Action]))) == 0
    error_message = "no object, secret, key, database, cluster or log content reads, and no hop onward"
  }
  assert {
    condition = (jsondecode(output.pipeline.plan_role_trust).Statement[0].Principal.AWS == "arn:aws-us-gov:iam::111111111111:role/fair-instances-plan"
    && length(jsondecode(output.pipeline.plan_role_trust).Statement) == 1 && jsondecode(output.pipeline.plan_role_trust).Statement[0].Action == "sts:AssumeRole")
    error_message = "only the management account's plan role assumes it"
  }
  assert {
    condition     = aws_iam_role.plan.name == "fair-instance-plan" && output.pipeline.current_role_arn == "arn:aws-us-gov:iam::777777777777:role/fair-instance-plan" && output.pipeline.dns_role_arn == "arn:aws-us-gov:iam::222222222222:role/fair-dns-read"
    error_message = "plans run as the read-only roles (the instance's and the parent zone's)"
  }
}

run "applies_stay_in_the_instance_account" {
  command = plan
  variables {
    mode = "apply"
  }

  assert {
    condition     = output.pipeline.current_role_arn == "arn:aws-us-gov:iam::777777777777:role/OrganizationAccountAccessRole" && output.pipeline.dns_role_arn == "arn:aws-us-gov:iam::222222222222:role/fair-dns-delegate"
    error_message = "applies run as the infrastructure role of this instance's account (and the delegation role)"
  }
  assert {
    condition     = alltrue([for k in ["plan_role_arn", "apply_role_arn", "current_role_arn"] : startswith(output.pipeline[k], "arn:aws-us-gov:iam::777777777777:role/")])
    error_message = "every role this root runs as in AWS is in the instance's own account"
  }
}

run "retiring_keeps_running_and_delegated" {
  command = plan
  variables {
    status     = "retiring"
    retirement = { change = "FAIR-CHG-0001", requested_on = "2026-12-01", retain_until = "2033-12-01" }
  }

  assert {
    condition     = length(aws_route53_record.delegation_ns) == 1 && output.cluster != null && output.database != null
    error_message = "a retiring instance still runs and answers (its exports are taken)"
  }
}

run "retired_keeps_the_retained_stores" {
  command = plan
  variables {
    status = "retired"
    retirement = {
      change                 = "FAIR-CHG-0001"
      requested_on           = "2026-12-01"
      retain_until           = "2033-12-01"
      customer_export_sha256 = "0000000000000000000000000000000000000000000000000000000000000001"
      audit_export_sha256    = "0000000000000000000000000000000000000000000000000000000000000002"
    }
  }

  assert {
    condition     = length(aws_route53_record.delegation_ns) == 0 && length(aws_route53_record.delegation_ds) == 0 && output.cluster == null && output.database == null && output.delegation == null
    error_message = "the workloads and the delegation are removed"
  }
  assert {
    condition = output.retained.buckets == {
      audit_worm           = "fair-example-audit-worm-777777777777"
      audit_store          = "fair-example-audit-store-777777777777"
      report_store         = "fair-example-report-store-777777777777"
      access               = "fair-example-access-777777777777"
      audit_worm_replica   = "fair-example-audit-worm-replica-777777777777"
      audit_store_replica  = "fair-example-audit-store-replica-777777777777"
      report_store_replica = "fair-example-report-store-replica-777777777777"
      access_replica       = "fair-example-access-replica-777777777777"
    }
    error_message = "every store and replica is kept (the audit WORM under Object Lock for its retention)"
  }
  assert {
    condition     = length(output.retained.kms_keys) == 13 && length(output.retained.log_groups) == 7 && output.retained.database_snapshot == "fair-example-final"
    error_message = "every key, the log groups and the final snapshot's name are kept"
  }
  assert {
    condition     = aws_iam_role.plan.name == "fair-instance-plan" && module.baseline.config_recorder == "fair"
    error_message = "the plan role and the baseline stay: drift is still detected on what is retained"
  }
  assert {
    condition     = output.retirement.audit_export_sha256 == "0000000000000000000000000000000000000000000000000000000000000002"
    error_message = "the exports' digests are recorded with the change"
  }
}

run "retired_needs_both_exports" {
  command = plan
  variables {
    status     = "retired"
    retirement = { change = "FAIR-CHG-0001", requested_on = "2026-12-01", retain_until = "2033-12-01", customer_export_sha256 = "0000000000000000000000000000000000000000000000000000000000000001" }
  }
  expect_failures = [var.retirement]
}

run "retiring_needs_a_record" {
  command = plan
  variables {
    status = "retiring"
  }
  expect_failures = [var.retirement]
}

run "retention_shorter_than_the_audit_trail_refused" {
  command = plan
  variables {
    status     = "retiring"
    retirement = { change = "FAIR-CHG-0001", requested_on = "2026-12-01", retain_until = "2027-12-01" }
  }
  expect_failures = [var.retirement]
}

run "active_instances_have_no_retirement" {
  command = plan
  variables {
    retirement = { change = "FAIR-CHG-0001", requested_on = "2026-12-01", retain_until = "2033-12-01" }
  }
  expect_failures = [var.retirement]
}

run "a_domain_outside_the_parent_zone_refused" {
  command = plan
  variables {
    domain = "example.other.example"
  }
  expect_failures = [var.domain]
}

run "a_domain_two_labels_down_refused" {
  command = plan
  variables {
    domain = "a.example.fair-risk.example"
  }
  expect_failures = [var.domain]
}

run "the_management_account_is_never_an_instance" {
  command = plan
  variables {
    account_id = "111111111111"
  }
  expect_failures = [var.account_id]
}

run "graviton_nodes_refused" {
  command = plan
  variables {
    node_instance_types = ["m7g.xlarge"]
  }
  expect_failures = [var.node_instance_types]
}

run "a_public_range_refused" {
  command = plan
  variables {
    vpc_cidr = "52.40.0.0/16"
  }
  expect_failures = [var.vpc_cidr]
}

run "an_unknown_mode_refused" {
  command = plan
  variables {
    mode = "admin"
  }
  expect_failures = [var.mode]
}

run "a_bad_email_refused" {
  command = plan
  variables {
    account_email = "not-an-address"
  }
  expect_failures = [var.account_email]
}

# F-012 T-18 (F-012-AC-27; design §3.9, §6 "E: operators hold standing
# access"): fair-access-eks, accessctl's role in the instance account.
run "no_access_role_until_configured" {
  command = plan

  assert {
    condition     = length(aws_iam_role.access_eks) == 0 && output.access == null
    error_message = "no access role before just-in-time access is configured"
  }
}

run "the_access_role_manages_only_operator_entries" {
  command = plan
  variables {
    access_controller_role_arn = "arn:aws-us-gov:iam::555555555555:role/fair-access-controller"
  }

  assert {
    condition = (aws_iam_role.access_eks[0].name == "fair-access-eks" && aws_iam_role.access_eks[0].max_session_duration == 3600
      && length(jsondecode(output.access.trust).Statement) == 1
      && jsondecode(output.access.trust).Statement[0].Principal.AWS == "arn:aws-us-gov:iam::555555555555:role/fair-access-controller"
    && jsondecode(output.access.trust).Statement[0].Action == "sts:AssumeRole")
    error_message = "only accessctl's role in the operations account assumes it"
  }
  assert {
    condition = alltrue([for s in jsondecode(output.access.policy).Statement :
      alltrue([for a in flatten([s.Action]) : contains(["eks:ListAccessEntries", "eks:DescribeAccessEntry", "eks:ListAssociatedAccessPolicies", "eks:CreateAccessEntry", "eks:AssociateAccessPolicy", "eks:DeleteAccessEntry", "iam:ListRoles"], a)])
    if s.Effect == "Allow"])
    error_message = "it allows access-entry calls and listing roles, nothing else (no cluster change, no secret, no data)"
  }
  assert {
    condition = alltrue([for s in jsondecode(output.access.policy).Statement :
      s.Condition.ArnLike["eks:principalArn"] == ["arn:aws-us-gov:iam::777777777777:role/AWSReservedSSO_FairReadOnly_*", "arn:aws-us-gov:iam::777777777777:role/AWSReservedSSO_FairOperator_*"]
    if s.Effect == "Allow" && length(setintersection(flatten([s.Action]), ["eks:CreateAccessEntry", "eks:AssociateAccessPolicy", "eks:DeleteAccessEntry"])) > 0])
    error_message = "entries are created, given a policy or removed only for the FAIR permission sets' roles in this account"
  }
  assert {
    condition = anytrue([for s in jsondecode(output.access.policy).Statement :
      s.Effect == "Allow" && s.Action == "eks:AssociateAccessPolicy"
      && s.Condition.StringEquals["eks:policyArn"] == "arn:aws-us-gov:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
    && s.Condition.StringEquals["eks:accessScope"] == "cluster"])
    error_message = "the one access policy it may associate is the view policy"
  }
  assert {
    condition = anytrue([for s in jsondecode(output.access.policy).Statement :
    s.Effect == "Deny" && s.Action == "eks:AssociateAccessPolicy" && s.Resource == "*" && s.Condition.StringNotEquals["eks:policyArn"] == "arn:aws-us-gov:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"])
    error_message = "any other access policy (cluster admin, admin, edit) is denied"
  }
  assert {
    condition = anytrue([for s in jsondecode(output.access.policy).Statement :
    s.Effect == "Deny" && contains(s.Action, "eks:CreateAccessEntry") && contains(s.Action, "eks:UpdateAccessEntry") && s.Resource == "*" && can(s.Condition.ArnNotLike["eks:principalArn"])])
    error_message = "access entries for any other principal are denied"
  }
  assert {
    condition = anytrue([for s in jsondecode(output.access.policy).Statement :
    s.Action == "eks:CreateAccessEntry" && s.Effect == "Allow" && s.Condition["ForAllValues:StringEquals"]["eks:kubernetesGroups"] == ["fair:operator"]])
    error_message = "the only Kubernetes group an entry may carry is fair:operator (deploy/fleet/addons-config/operator-access.yaml)"
  }
  assert {
    condition = alltrue([for s in jsondecode(output.access.policy).Statement :
      alltrue([for r in flatten([s.Resource]) : r == "*" || startswith(r, "arn:aws-us-gov:eks:us-gov-west-1:777777777777:cluster/fair-example") || startswith(r, "arn:aws-us-gov:eks:us-gov-west-1:777777777777:access-entry/fair-example/")])
    if s.Effect == "Allow"])
    error_message = "only this instance's cluster"
  }
}

run "the_access_controller_is_not_in_the_instance_account" {
  command = plan
  variables {
    access_controller_role_arn = "arn:aws-us-gov:iam::777777777777:role/fair-access-controller"
  }
  expect_failures = [var.access_controller_role_arn]
}
