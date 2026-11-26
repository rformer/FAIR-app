# The instance's Kubernetes cluster (design §3.5):
#   - the API endpoint is private only (reached from the VPC: the nodes,
#     and the pipeline's runner for Flux's bootstrap, T-14/T-15);
#   - Kubernetes Secrets are envelope-encrypted with the instance's eks key;
#   - every control-plane log type goes to CloudWatch Logs (logs key);
#   - access by EKS access entries only (no aws-auth ConfigMap), and the
#     creator gets no implicit administration;
#   - one managed node group on Bottlerocket's FIPS variant
#     (BOTTLEROCKET_x86_64_FIPS): its kernel and userspace run in FIPS mode
#     with FIPS-validated crypto modules, the host is immutable with a
#     read-only root and SELinux enforcing, and no SSH or admin container.
#     This is the AMI the design names; AL2023's FIPS mode would be enabled
#     in user data on a general-purpose distribution instead.
resource "aws_cloudwatch_log_group" "cluster" {
  # EKS writes here (the name is fixed by EKS); created first so it is
  # under the logs key with a year's retention.
  name              = "/aws/eks/${local.cluster_name}/cluster"
  kms_key_id        = aws_kms_key.home["logs"].arn
  retention_in_days = 365
  tags              = local.tags
}

resource "aws_eks_cluster" "this" {
  name                      = local.cluster_name
  role_arn                  = aws_iam_role.service["cluster"].arn
  version                   = var.kubernetes_version
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  vpc_config {
    subnet_ids              = [for z, _ in local.zones : aws_subnet.workload[z].id]
    security_group_ids      = [aws_security_group.cluster.id]
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.home["eks"].arn
    }
  }

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  kubernetes_network_config {
    ip_family         = "ipv4"
    service_ipv4_cidr = "172.20.0.0/16"
  }

  upgrade_policy {
    support_type = "STANDARD"
  }

  tags = local.tags

  depends_on = [
    aws_cloudwatch_log_group.cluster,
    aws_iam_role_policy_attachment.service["cluster/eks"],
    aws_iam_role_policy.service["cluster"],
  ]
}

resource "aws_eks_access_entry" "admin" {
  for_each      = toset(var.cluster_admin_role_arns)
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.key
  type          = "STANDARD"
  tags          = local.tags
}

resource "aws_eks_access_policy_association" "admin" {
  for_each      = toset(var.cluster_admin_role_arns)
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.key
  policy_arn    = "arn:${local.p}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope {
    type = "cluster"
  }
  depends_on = [aws_eks_access_entry.admin]
}

# Bottlerocket settings (TOML, merged by EKS with the cluster's): no admin
# or control host container (no shell, no SSM agent), kernel lockdown.
locals {
  bottlerocket_settings = <<-EOT
    [settings.host-containers.admin]
    enabled = false

    [settings.host-containers.control]
    enabled = false

    [settings.kernel]
    lockdown = "integrity"
  EOT
}

resource "aws_launch_template" "nodes" {
  name                   = "${local.name}-nodes"
  description            = "FAIR ${var.instance} nodes: Bottlerocket FIPS, IMDSv2 only, encrypted volumes"
  update_default_version = true
  vpc_security_group_ids = [aws_security_group.nodes.id]
  user_data              = base64encode(local.bottlerocket_settings)

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  # Bottlerocket's OS volume and its data volume, both under the nodes key.
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 4
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = aws_kms_key.home["nodes"].arn
      delete_on_termination = true
    }
  }
  block_device_mappings {
    device_name = "/dev/xvdb"
    ebs {
      volume_size           = var.node_data_volume_gib
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = aws_kms_key.home["nodes"].arn
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.tags, { Name = "${local.name}-node" })
  }
  tag_specifications {
    resource_type = "volume"
    tags          = local.tags
  }

  tags = local.tags
}

resource "aws_eks_node_group" "this" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "fair"
  node_role_arn   = aws_iam_role.service["nodes"].arn
  subnet_ids      = [for z, _ in local.zones : aws_subnet.workload[z].id]
  ami_type        = "BOTTLEROCKET_x86_64_FIPS"
  capacity_type   = "ON_DEMAND"
  instance_types  = var.node_instance_types

  scaling_config {
    min_size     = var.node_count.min
    desired_size = var.node_count.desired
    max_size     = var.node_count.max
  }

  update_config {
    max_unavailable = 1
  }

  launch_template {
    id      = aws_launch_template.nodes.id
    version = aws_launch_template.nodes.latest_version
  }

  tags = local.tags

  depends_on = [
    aws_iam_role_policy_attachment.service["nodes/worker"],
    aws_iam_role_policy_attachment.service["nodes/ecr"],
    aws_iam_role_policy_attachment.service["nodes/cni"],
  ]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }
}

# Add-ons EKS manages: networking, DNS, the EBS CSI driver (under its own
# workload role).
resource "aws_eks_addon" "this" {
  for_each                    = toset(["vpc-cni", "kube-proxy", "coredns", "aws-ebs-csi-driver"])
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = each.key
  service_account_role_arn    = each.key == "aws-ebs-csi-driver" ? aws_iam_role.irsa["ebs-csi"].arn : null
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  tags                        = local.tags
  depends_on                  = [aws_eks_node_group.this]
}
