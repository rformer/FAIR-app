# F-012 T-12 (F-012-AC-15, AC-19; design §3.5, §3.6): the release mirror in
# the shared-services account. Every platform image and every mirrored
# third-party image (Flux, the policy-controller, External Secrets,
# cert-manager, the Collector) has a repository with immutable tags, a scan
# on push and KMS encryption under the mirror's own key. Instance accounts
# pull (organization members under the instances OU path only); only the
# named publisher roles push. Images are never expired: releases are kept
# 24 months (design §3.4), and pruning older ones is a reviewed change.
locals {
  key_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # The account delegates the key's use to IAM; ECR uses it for its
        # repositories through grants it creates.
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:${var.partition}:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
    ]
  })

  pull_statement = {
    Sid       = "InstancesPull"
    Effect    = "Allow"
    Principal = { AWS = "*" }
    Action    = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    Condition = {
      StringEquals             = { "aws:PrincipalOrgID" = var.organization_id }
      "ForAnyValue:StringLike" = { "aws:PrincipalOrgPaths" = var.pull_org_paths }
    }
  }

  push_statement = {
    Sid       = "PublishersPush"
    Effect    = "Allow"
    Principal = { AWS = var.publisher_role_arns }
    Action = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
  }

  repository_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = concat([local.pull_statement], length(var.publisher_role_arns) > 0 ? [local.push_statement] : [])
  })
}

resource "aws_kms_key" "mirror" {
  description             = "FAIR release mirror (ECR) encryption"
  key_usage               = "ENCRYPT_DECRYPT"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy                  = local.key_policy
  tags                    = var.tags
}

resource "aws_kms_alias" "mirror" {
  name          = "alias/fair-mirror"
  target_key_id = aws_kms_key.mirror.key_id
}

resource "aws_ecr_repository" "this" {
  for_each             = toset(var.repositories)
  name                 = "${var.prefix}/${each.key}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.mirror.arn
  }

  tags = var.tags
}

resource "aws_ecr_repository_policy" "this" {
  for_each   = aws_ecr_repository.this
  repository = each.value.name
  policy     = local.repository_policy
}
