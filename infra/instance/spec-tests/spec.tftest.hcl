# F-012 T-14 (F-012-AC-14): an instance's spec file (infra/instances/<name>.tfvars,
# or the example) plans against every validation, with mock providers.
# scripts/infra-check.sh runs it once per file:
#   tofu test -test-directory=spec-tests -var-file=../instances/<name>.tfvars
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


# The pipeline's values: fictional accounts; the parent domain is the
# spec's own domain without its first label (the spec's domain must be one
# label below the SaaS parent domain, which the pipeline gives as
# var.dns.domain).
variables {
  account_id            = "777777777777"
  management_account_id = "111111111111"
  log_archive = {
    bucket      = "fair-log-archive-444444444444"
    kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:444444444444:key/00000000-0000-0000-0000-000000000001"
  }
  dns = {
    account_id        = "222222222222"
    zone_id           = "Z0PARENT0000000"
    domain            = join(".", slice(split(".", var.domain), 1, length(split(".", var.domain))))
    read_role_arn     = "arn:aws-us-gov:iam::222222222222:role/fair-dns-read"
    delegate_role_arn = "arn:aws-us-gov:iam::222222222222:role/fair-dns-delegate"
  }
}

run "the_spec_plans" {
  command = plan

  assert {
    condition     = output.status == var.status
    error_message = "the spec passes every validation and plans"
  }
  assert {
    condition     = var.status == "retired" || length(aws_route53_record.delegation_ns) == 1
    error_message = "a running instance is delegated"
  }
  assert {
    condition     = length(output.retained.buckets) == 8
    error_message = "whatever its status, the retained stores are there"
  }
}
