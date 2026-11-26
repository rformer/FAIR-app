# DNS (design §3.5): the instance's public zone (DNSSEC-signed, queries
# logged; delegated from the parent zone at onboarding, T-14, with the
# name_servers output) and a private zone for internal names.
resource "aws_route53_zone" "public" {
  count         = local.live ? 1 : 0
  name          = var.domain
  comment       = "FAIR ${var.instance}: the public entry"
  force_destroy = false
  tags          = local.tags
}

resource "aws_route53_zone" "private" {
  count         = local.live ? 1 : 0
  name          = local.private_domain
  comment       = "FAIR ${var.instance}: internal names"
  force_destroy = false
  vpc {
    vpc_id = aws_vpc.this[0].id
  }
  tags = local.tags
}

# The gateway's name: the public load balancer.
resource "aws_route53_record" "gateway" {
  count   = local.live ? 1 : 0
  zone_id = aws_route53_zone.public[0].zone_id
  name    = var.domain
  type    = "A"
  alias {
    name                   = aws_lb.public[0].dns_name
    zone_id                = aws_lb.public[0].zone_id
    evaluate_target_health = true
  }
}

# The ops telemetry endpoint's internal name (the Collector's targets).
resource "aws_route53_record" "telemetry" {
  count   = var.ops_telemetry == null || !local.live ? 0 : 1
  zone_id = aws_route53_zone.private[0].zone_id
  name    = "telemetry.${local.private_domain}"
  type    = "CNAME"
  ttl     = 300
  records = [aws_vpc_endpoint.telemetry[0].dns_entry[0].dns_name]
}

# DNSSEC: the key-signing key is an asymmetric KMS key (ECC_NIST_P256,
# SIGN_VERIFY) only Route 53's DNSSEC service may sign with, for this
# account's zones.
resource "aws_kms_key" "dnssec" {
  #checkov:skip=CKV_AWS_7:Asymmetric signing keys cannot rotate in KMS; the key-signing key is rotated by a new key and a DS record change (T-14 runbook).
  count                    = local.live ? 1 : 0
  description              = "FAIR ${var.instance}: DNSSEC key-signing key"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  multi_region             = false
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(local.key_admin_statements, [
      {
        Sid       = "Route53DNSSEC"
        Effect    = "Allow"
        Principal = { Service = "dnssec-route53.amazonaws.com" }
        Action    = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"]
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.acct }
          ArnLike      = { "aws:SourceArn" = "arn:${local.p}:route53:::hostedzone/*" }
        }
      },
      {
        Sid       = "Route53DNSSECGrants"
        Effect    = "Allow"
        Principal = { Service = "dnssec-route53.amazonaws.com" }
        Action    = "kms:CreateGrant"
        Resource  = "*"
        Condition = { Bool = { "kms:GrantIsForAWSResource" = "true" } }
      },
    ])
  })
  tags = merge(local.tags, { "fair:purpose" = "dnssec" })
}

resource "aws_route53_key_signing_key" "public" {
  count                      = local.live ? 1 : 0
  name                       = "${replace(var.instance, "-", "")}ksk"
  hosted_zone_id             = aws_route53_zone.public[0].zone_id
  key_management_service_arn = aws_kms_key.dnssec[0].arn
  status                     = "ACTIVE"
}

resource "aws_route53_hosted_zone_dnssec" "public" {
  count          = local.live ? 1 : 0
  hosted_zone_id = aws_route53_key_signing_key.public[0].hosted_zone_id
  signing_status = "SIGNING"
}

# Public query logs, a year, under the logs key.
resource "aws_cloudwatch_log_group" "dns" {
  name              = "/aws/route53/${var.domain}"
  kms_key_id        = aws_kms_key.home["logs"].arn
  retention_in_days = 365
  tags              = local.tags

  # Retained on decommissioning (var.status).
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_log_resource_policy" "dns" {
  count       = local.live ? 1 : 0
  policy_name = "${local.name}-route53-query-logs"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "Route53QueryLogs"
      Effect    = "Allow"
      Principal = { Service = "route53.amazonaws.com" }
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource  = "${aws_cloudwatch_log_group.dns.arn}:*"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.acct }
        ArnLike      = { "aws:SourceArn" = "arn:${local.p}:route53:::hostedzone/*" }
      }
    }]
  })
}

resource "aws_route53_query_log" "public" {
  count                    = local.live ? 1 : 0
  zone_id                  = aws_route53_zone.public[0].zone_id
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.dns.arn
  depends_on               = [aws_cloudwatch_log_resource_policy.dns]
}
