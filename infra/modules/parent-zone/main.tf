# F-012 T-14 (F-012-AC-14; design §3.5): the SaaS parent zone (the domain
# every instance's public name sits under) and the two roles the instance
# pipeline uses to delegate an instance's zone (infra/instance writes its NS
# and DS records here, so onboarding has no manual DNS step):
#   - fair-dns-delegate (trusted by the management account's
#     fair-instances-apply): changes only NS and DS records of names under
#     the domain, never the apex or any other type;
#   - fair-dns-read (trusted by fair-instances-plan): reads the zone.
# The zone is DNSSEC-signed (its DS record goes to the registrar once, at
# bootstrap) and its queries are logged.
locals {
  p        = var.partition
  zone_arn = "arn:${local.p}:route53:::hostedzone/${aws_route53_zone.parent.zone_id}"

  key_admin = {
    Sid       = "AccountAdministration"
    Effect    = "Allow"
    Principal = { AWS = "arn:${local.p}:iam::${var.account_id}:root" }
    Action    = "kms:*"
    Resource  = "*"
  }

  read_statements = [
    {
      Sid      = "ReadTheParentZone"
      Effect   = "Allow"
      Action   = ["route53:GetHostedZone", "route53:ListResourceRecordSets", "route53:ListTagsForResource", "route53:GetDNSSEC"]
      Resource = local.zone_arn
    },
    {
      Sid      = "ReadChanges"
      Effect   = "Allow"
      Action   = "route53:GetChange"
      Resource = "arn:${local.p}:route53:::change/*"
    },
  ]

  policy = {
    read = jsonencode({ Version = "2012-10-17", Statement = local.read_statements })
    delegate = jsonencode({
      Version = "2012-10-17"
      Statement = concat(local.read_statements, [{
        Sid      = "DelegateInstanceZones"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = local.zone_arn
        Condition = {
          "ForAllValues:StringEquals" = { "route53:ChangeResourceRecordSetsRecordTypes" = ["NS", "DS"] }
          "ForAllValues:StringLike"   = { "route53:ChangeResourceRecordSetsNormalizedRecordNames" = ["*.${var.domain}"] }
        }
      }])
    })
  }

  trust = {
    read = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Sid       = "InstancePlans"
        Effect    = "Allow"
        Principal = { AWS = var.plan_role_arn }
        Action    = "sts:AssumeRole"
      }]
    })
    delegate = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Sid       = "ApprovedInstanceApplies"
        Effect    = "Allow"
        Principal = { AWS = var.apply_role_arn }
        Action    = "sts:AssumeRole"
      }]
    })
  }
}

resource "aws_route53_zone" "parent" {
  name          = var.domain
  comment       = "FAIR SaaS: the instances' parent zone"
  force_destroy = false
  tags          = var.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_key" "dnssec" {
  #checkov:skip=CKV_AWS_7:Asymmetric signing keys cannot rotate in KMS; the key-signing key is rotated by a new key and a DS record change at the registrar.
  description              = "FAIR SaaS parent zone: DNSSEC key-signing key"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  multi_region             = false
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      local.key_admin,
      {
        Sid       = "Route53DNSSEC"
        Effect    = "Allow"
        Principal = { Service = "dnssec-route53.amazonaws.com" }
        Action    = ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"]
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.account_id }
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
    ]
  })
  tags = var.tags
}

resource "aws_route53_key_signing_key" "parent" {
  name                       = "fairparentksk"
  hosted_zone_id             = aws_route53_zone.parent.zone_id
  key_management_service_arn = aws_kms_key.dnssec.arn
  status                     = "ACTIVE"
}

resource "aws_route53_hosted_zone_dnssec" "parent" {
  hosted_zone_id = aws_route53_key_signing_key.parent.hosted_zone_id
  signing_status = "SIGNING"
}

resource "aws_kms_key" "logs" {
  description             = "FAIR SaaS parent zone: query logs"
  key_usage               = "ENCRYPT_DECRYPT"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      local.key_admin,
      {
        Sid       = "CloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:DescribeKey"]
        Resource  = "*"
        Condition = { ArnLike = { "kms:EncryptionContext:aws:logs:arn" = "arn:${local.p}:logs:${var.region}:${var.account_id}:log-group:*" } }
      },
    ]
  })
  tags = var.tags
}

resource "aws_cloudwatch_log_group" "queries" {
  name              = "/aws/route53/${var.domain}"
  kms_key_id        = aws_kms_key.logs.arn
  retention_in_days = 365
  tags              = var.tags
}

resource "aws_cloudwatch_log_resource_policy" "queries" {
  policy_name = "fair-parent-zone-query-logs"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "Route53QueryLogs"
      Effect    = "Allow"
      Principal = { Service = "route53.amazonaws.com" }
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource  = "${aws_cloudwatch_log_group.queries.arn}:*"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:${local.p}:route53:::hostedzone/*" }
      }
    }]
  })
}

resource "aws_route53_query_log" "parent" {
  zone_id                  = aws_route53_zone.parent.zone_id
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.queries.arn
  depends_on               = [aws_cloudwatch_log_resource_policy.queries]
}

resource "aws_iam_role" "read" {
  name                 = var.read_role_name
  description          = "Reads the SaaS parent zone (instance plans and drift, F-012 T-14)"
  assume_role_policy   = local.trust.read
  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role_policy" "read" {
  name   = "parent-zone-read"
  role   = aws_iam_role.read.id
  policy = local.policy.read
}

resource "aws_iam_role" "delegate" {
  name                 = var.delegate_role_name
  description          = "Delegates instance zones in the SaaS parent zone: NS and DS records only (F-012 T-14)"
  assume_role_policy   = local.trust.delegate
  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role_policy" "delegate" {
  name   = "parent-zone-delegate"
  role   = aws_iam_role.delegate.id
  policy = local.policy.delegate
}
