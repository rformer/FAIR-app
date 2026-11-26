# F-012 T-14 (F-012-AC-14; design §3.5): the SaaS parent zone and its
# delegation roles, with a mock provider.
mock_provider "aws" {
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws-us-gov:logs:us-gov-west-1:222222222222:log-group:/aws/route53/fair-risk.example" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:222222222222:key/00000000-0000-0000-0000-000000000009" }
  }
  mock_resource "aws_route53_zone" {
    defaults = { zone_id = "Z0PARENT0000000" }
  }
}

variables {
  account_id     = "222222222222"
  domain         = "fair-risk.example"
  plan_role_arn  = "arn:aws-us-gov:iam::111111111111:role/fair-instances-plan"
  apply_role_arn = "arn:aws-us-gov:iam::111111111111:role/fair-instances-apply"
}

run "signed_and_logged" {
  command = plan

  assert {
    condition     = aws_route53_hosted_zone_dnssec.parent.signing_status == "SIGNING" && aws_kms_key.dnssec.customer_master_key_spec == "ECC_NIST_P256"
    error_message = "the parent zone is DNSSEC-signed"
  }
  assert {
    condition     = aws_route53_query_log.parent.zone_id == "Z0PARENT0000000" && aws_cloudwatch_log_group.queries.retention_in_days == 365
    error_message = "its queries are logged for a year"
  }
}

run "the_delegate_changes_ns_and_ds_below_the_domain_only" {
  command = plan

  assert {
    condition = alltrue([for s in jsondecode(output.policy_documents["role/delegate"]).Statement :
      s.Resource == "arn:aws-us-gov:route53:::hostedzone/Z0PARENT0000000"
      && s.Condition["ForAllValues:StringEquals"]["route53:ChangeResourceRecordSetsRecordTypes"] == ["NS", "DS"]
      && s.Condition["ForAllValues:StringLike"]["route53:ChangeResourceRecordSetsNormalizedRecordNames"] == ["*.fair-risk.example"]
    if contains(flatten([s.Action]), "route53:ChangeResourceRecordSets")])
    error_message = "record changes: NS and DS only, names below the parent domain only (never its apex)"
  }
  assert {
    condition = length([for s in jsondecode(output.policy_documents["role/delegate"]).Statement : s
    if contains(flatten([s.Action]), "route53:ChangeResourceRecordSets")]) == 1
    error_message = "one statement changes records"
  }
  assert {
    condition = alltrue([for s in jsondecode(output.policy_documents["role/read"]).Statement :
    alltrue([for a in flatten([s.Action]) : can(regex("^route53:(Get|List)[A-Za-z]*$", a))])])
    error_message = "the read role reads only"
  }
  assert {
    condition = (jsondecode(output.policy_documents["trust/delegate"]).Statement[0].Principal.AWS == "arn:aws-us-gov:iam::111111111111:role/fair-instances-apply"
    && jsondecode(output.policy_documents["trust/read"]).Statement[0].Principal.AWS == "arn:aws-us-gov:iam::111111111111:role/fair-instances-plan")
    error_message = "the delegate trusts the pipeline's apply role, the reader its plan role"
  }
}
