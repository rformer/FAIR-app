# The instance's IAM roles. Service roles are assumed by AWS services of
# this account; workload roles (IRSA) by one Kubernetes service account
# each, through the cluster's own OIDC provider. Every permission names this
# instance's resources (the External Secrets role: fair/<instance>/* only).
locals {
  managed = "arn:${local.p}:iam::aws:policy"

  service_principals = {
    cluster          = "eks.amazonaws.com"
    nodes            = "ec2.amazonaws.com"
    replication      = "s3.amazonaws.com"
    "rds-monitoring" = "monitoring.rds.amazonaws.com"
    "flow-logs"      = "vpc-flow-logs.amazonaws.com"
  }
  # Services that act for one account carry it as aws:SourceAccount.
  service_source_account = ["replication", "flow-logs"]

  # Kubernetes service accounts (namespace, name) of the workload roles.
  # The platform's: fair-platform/fair-external-secrets (the SecretStore of
  # deploy/k8s/keys/saas), fair-platform/audit, fair-platform/risk; the
  # cluster add-ons Flux installs (T-15): the load balancer controller (for
  # the gateway's TargetGroupBinding), cert-manager's AWS Private CA issuer,
  # the EBS CSI driver.
  irsa = {
    "external-secrets"         = { namespace = "fair-platform", service_account = "fair-external-secrets" }
    audit                      = { namespace = "fair-platform", service_account = "audit" }
    risk                       = { namespace = "fair-platform", service_account = "risk" }
    "load-balancer-controller" = { namespace = "kube-system", service_account = "aws-load-balancer-controller" }
    "privateca-issuer"         = { namespace = "cert-manager", service_account = "aws-privateca-issuer" }
    "ebs-csi"                  = { namespace = "kube-system", service_account = "ebs-csi-controller-sa" }
  }

  oidc_host = trimprefix(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://")

  secrets_arn_prefix = "arn:${local.p}:secretsmanager:${var.region}:${local.acct}:secret:fair/${var.instance}/"
  s3_arn             = { for k, v in local.bucket : k => "arn:${local.p}:s3:::${v}" }
  s3_replica_arn     = { for k, v in local.replica_bucket : k => "arn:${local.p}:s3:::${v}" }
  key                = { for k, _ in local.home_key_purposes : k => aws_kms_key.home[k].arn }
  replica_key        = { for k, _ in local.replica_key_purposes : k => aws_kms_key.replica[k].arn }

  replicated = ["audit-worm", "audit-store", "report-store"]

  bucket_read = ["s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketLocation"]

  policies = {
    cluster = [{
      Sid      = "SecretsEnvelope"
      Effect   = "Allow"
      Action   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey", "kms:CreateGrant"]
      Resource = local.key["eks"]
    }]

    replication = [
      {
        Sid      = "ReadSources"
        Effect   = "Allow"
        Action   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
        Resource = [for b in local.replicated : local.s3_arn[b]]
      },
      {
        Sid      = "ReadSourceVersions"
        Effect   = "Allow"
        Action   = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging", "s3:GetObjectRetention", "s3:GetObjectLegalHold"]
        Resource = [for b in local.replicated : "${local.s3_arn[b]}/*"]
      },
      {
        Sid      = "WriteReplicas"
        Effect   = "Allow"
        Action   = ["s3:ReplicateObject", "s3:ReplicateTags"]
        Resource = [for b in local.replicated : "${local.s3_replica_arn[b]}/*"]
      },
      {
        Sid       = "DecryptSources"
        Effect    = "Allow"
        Action    = "kms:Decrypt"
        Resource  = [for b in local.replicated : local.key[b]]
        Condition = { StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" } }
      },
      {
        Sid       = "EncryptReplicas"
        Effect    = "Allow"
        Action    = ["kms:Encrypt", "kms:GenerateDataKey"]
        Resource  = [for b in local.replicated : local.replica_key[b]]
        Condition = { StringEquals = { "kms:ViaService" = "s3.${var.replica_region}.amazonaws.com" } }
      },
    ]

    "flow-logs" = [{
      Sid      = "DeliverFlowLogs"
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = [aws_cloudwatch_log_group.flow.arn, "${aws_cloudwatch_log_group.flow.arn}:*"]
    }]

    # The instance's secrets, nothing else: the key layout and the database
    # passwords under fair/<instance>/.
    "external-secrets" = [
      {
        Sid      = "ReadInstanceSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = "${local.secrets_arn_prefix}*"
      },
      {
        Sid       = "DecryptInstanceSecrets"
        Effect    = "Allow"
        Action    = "kms:Decrypt"
        Resource  = local.key["secrets"]
        Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" } }
      },
    ]

    # The audit service: exports and archives in the audit store (it
    # destroys records past retention), checkpoint copies in the WORM
    # bucket (written, never deleted); legal holds on both (F-002).
    audit = [
      {
        Sid      = "Buckets"
        Effect   = "Allow"
        Action   = local.bucket_read
        Resource = [local.s3_arn["audit-store"], local.s3_arn["audit-worm"]]
      },
      {
        Sid      = "AuditStoreObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:PutObjectRetention", "s3:GetObjectRetention", "s3:PutObjectLegalHold", "s3:GetObjectLegalHold", "s3:DeleteObjectVersion"]
        Resource = "${local.s3_arn["audit-store"]}/*"
      },
      {
        Sid      = "AuditWORMObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:PutObjectRetention", "s3:GetObjectRetention", "s3:PutObjectLegalHold", "s3:GetObjectLegalHold"]
        Resource = "${local.s3_arn["audit-worm"]}/*"
      },
      {
        Sid      = "AuditKeys"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [local.key["audit-store"], local.key["audit-worm"]]
      },
    ]

    # The risk service: the report store (written, read, purged; F-010).
    risk = [
      {
        Sid      = "Bucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketVersioning", "s3:GetBucketLocation"]
        Resource = local.s3_arn["report-store"]
      },
      {
        Sid      = "ReportObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource = "${local.s3_arn["report-store"]}/*"
      },
      {
        Sid      = "ReportKey"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = local.key["report-store"]
      },
    ]

    # Registers the gateway pods in the load balancer's target group
    # (TargetGroupBinding); the load balancer itself is this module's.
    "load-balancer-controller" = [
      {
        Sid      = "GatewayTargets"
        Effect   = "Allow"
        Action   = ["elasticloadbalancing:RegisterTargets", "elasticloadbalancing:DeregisterTargets"]
        Resource = aws_lb_target_group.gateway.arn
      },
      {
        # Describe calls take no resource (IAM's service authorization).
        Sid    = "Describe"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeListeners", "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetGroupAttributes", "elasticloadbalancing:DescribeTargetHealth", "elasticloadbalancing:DescribeTags",
          "ec2:DescribeInstances", "ec2:DescribeNetworkInterfaces", "ec2:DescribeSecurityGroups", "ec2:DescribeSubnets", "ec2:DescribeVpcs", "ec2:DescribeAvailabilityZones",
        ]
        Resource = "*"
      },
    ]

    # cert-manager's issuer: certificates from the instance's Private CA.
    "privateca-issuer" = [{
      Sid      = "IssueInternalCertificates"
      Effect   = "Allow"
      Action   = ["acm-pca:DescribeCertificateAuthority", "acm-pca:GetCertificate", "acm-pca:IssueCertificate"]
      Resource = aws_acmpca_certificate_authority.internal.arn
    }]

    # Volumes under the nodes key (AmazonEBSCSIDriverPolicy for the rest).
    "ebs-csi" = [
      {
        Sid      = "VolumeKey"
        Effect   = "Allow"
        Action   = local.key_use_actions
        Resource = local.key["nodes"]
      },
      {
        Sid       = "VolumeKeyGrants"
        Effect    = "Allow"
        Action    = ["kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"]
        Resource  = local.key["nodes"]
        Condition = { Bool = { "kms:GrantIsForAWSResource" = "true" } }
      },
    ]
  }

  managed_attachments = {
    "cluster/eks"       = { role = "cluster", arn = "${local.managed}/AmazonEKSClusterPolicy" }
    "nodes/worker"      = { role = "nodes", arn = "${local.managed}/AmazonEKSWorkerNodePolicy" }
    "nodes/ecr"         = { role = "nodes", arn = "${local.managed}/AmazonEC2ContainerRegistryPullOnly" }
    "nodes/cni"         = { role = "nodes", arn = "${local.managed}/AmazonEKS_CNI_Policy" }
    "rds-monitoring/em" = { role = "rds-monitoring", arn = "${local.managed}/service-role/AmazonRDSEnhancedMonitoringRole" }
    "ebs-csi/driver"    = { role = "ebs-csi", arn = "${local.managed}/service-role/AmazonEBSCSIDriverPolicy" }
  }
}

resource "aws_iam_role" "service" {
  for_each = local.service_principals
  name     = "${local.name}-${each.key}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [merge({
      Effect    = "Allow"
      Principal = { Service = each.value }
      Action    = each.key == "cluster" ? ["sts:AssumeRole", "sts:TagSession"] : ["sts:AssumeRole"]
      }, { for c in(contains(local.service_source_account, each.key) ? [local.acct] : []) :
      "Condition" => { StringEquals = { "aws:SourceAccount" = c } }
    })]
  })
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_openid_connect_provider" "cluster" {
  url            = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list = ["sts.amazonaws.com"]
  tags           = local.tags
}

resource "aws_iam_role" "irsa" {
  for_each = local.irsa
  name     = "${local.name}-${each.key}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.cluster.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.oidc_host}:sub" = "system:serviceaccount:${each.value.namespace}:${each.value.service_account}"
          "${local.oidc_host}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })
  max_session_duration = 3600
  tags                 = local.tags
}

# Service and workload roles' policies are separate resources: the
# cluster needs its role's policies first, and the workload roles need the
# cluster's OIDC issuer.
resource "aws_iam_role_policy" "service" {
  for_each = { for k, v in local.policies : k => v if contains(keys(local.service_principals), k) }
  name     = "${local.name}-${each.key}"
  role     = aws_iam_role.service[each.key].name
  policy   = jsonencode({ Version = "2012-10-17", Statement = each.value })
}

resource "aws_iam_role_policy" "irsa" {
  for_each = { for k, v in local.policies : k => v if contains(keys(local.irsa), k) }
  name     = "${local.name}-${each.key}"
  role     = aws_iam_role.irsa[each.key].name
  policy   = jsonencode({ Version = "2012-10-17", Statement = each.value })
}

resource "aws_iam_role_policy_attachment" "service" {
  for_each   = { for k, v in local.managed_attachments : k => v if contains(keys(local.service_principals), v.role) }
  role       = aws_iam_role.service[each.value.role].name
  policy_arn = each.value.arn
}

resource "aws_iam_role_policy_attachment" "irsa" {
  for_each   = { for k, v in local.managed_attachments : k => v if contains(keys(local.irsa), v.role) }
  role       = aws_iam_role.irsa[each.value.role].name
  policy_arn = each.value.arn
}

locals {
  trust_policy = merge({ for k, v in aws_iam_role.service : k => v.assume_role_policy }, { for k, v in aws_iam_role.irsa : k => v.assume_role_policy })
  role_policy  = merge(aws_iam_role_policy.service, aws_iam_role_policy.irsa)
}
