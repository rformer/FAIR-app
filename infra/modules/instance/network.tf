# The instance's network (design §3.5): three zones, each with
#   - a public subnet: only the public load balancer and a NAT gateway (no
#     instance gets a public address);
#   - a workload subnet (/19): the nodes, the interface endpoints; its only
#     default route is the zone's NAT gateway, never the internet gateway;
#   - a database subnet: no route out of the VPC at all.
# No peering and no transit gateway: the ops account is reached only by
# the Collector's PrivateLink endpoint (outbound) and Flux's pull (AC-15).
locals {
  zones = { for i, z in var.availability_zones : z => i }

  # Subnet ranges: workload /19 at 0, 32, 64; database /24 at 96 to 98;
  # public /24 at 100 to 102 (third octet).
  workload_cidr = { for z, i in local.zones : z => cidrsubnet(var.vpc_cidr, 3, i) }
  database_cidr = { for z, i in local.zones : z => cidrsubnet(var.vpc_cidr, 8, 96 + i) }
  public_cidr   = { for z, i in local.zones : z => cidrsubnet(var.vpc_cidr, 8, 100 + i) }

  # Interface endpoints whose services take an endpoint policy: requests
  # through them must come from this account's principals.
  endpoint_policy_services = ["sts", "secretsmanager", "kms", "kms-fips", "ecr.api", "ecr.dkr", "logs", "ec2", "elasticloadbalancing"]
  endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OnlyThisInstance"
      Effect    = "Allow"
      Principal = "*"
      Action    = "*"
      Resource  = "*"
      Condition = { StringEquals = { "aws:PrincipalAccount" = local.acct } }
    }]
  })
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = local.name })
}

# The default security group allows nothing (no rules): every interface
# names one of the groups below.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${local.name}-default-unused" })
}

resource "aws_subnet" "public" {
  for_each                = local.zones
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = local.public_cidr[each.key]
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${local.name}-public-${each.key}", "fair:tier" = "public" })
}

resource "aws_subnet" "workload" {
  for_each                = local.zones
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = local.workload_cidr[each.key]
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${local.name}-workload-${each.key}", "fair:tier" = "workload" })
}

resource "aws_subnet" "database" {
  for_each                = local.zones
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = local.database_cidr[each.key]
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${local.name}-database-${each.key}", "fair:tier" = "database" })
}

# The internet gateway serves the public subnets only (the load balancer
# and the NAT gateways).
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = local.name })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${local.name}-public", "fair:tier" = "public" })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  for_each       = local.zones
  subnet_id      = aws_subnet.public[each.key].id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  for_each = local.zones
  domain   = "vpc"
  tags     = merge(local.tags, { Name = "${local.name}-nat-${each.key}" })
}

resource "aws_nat_gateway" "this" {
  for_each      = local.zones
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.public[each.key].id
  tags          = merge(local.tags, { Name = "${local.name}-${each.key}" })
  depends_on    = [aws_internet_gateway.this]
}

resource "aws_route_table" "workload" {
  for_each = local.zones
  vpc_id   = aws_vpc.this.id
  tags     = merge(local.tags, { Name = "${local.name}-workload-${each.key}", "fair:tier" = "workload" })
}

# The workload subnets' one way out: the zone's NAT gateway (node security
# group egress limited to var.external_egress_ports).
resource "aws_route" "workload_egress" {
  for_each               = local.zones
  route_table_id         = aws_route_table.workload[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[each.key].id
}

resource "aws_route_table_association" "workload" {
  for_each       = local.zones
  subnet_id      = aws_subnet.workload[each.key].id
  route_table_id = aws_route_table.workload[each.key].id
}

# The database subnets: the VPC's local route only.
resource "aws_route_table" "database" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${local.name}-database", "fair:tier" = "database" })
}

resource "aws_route_table_association" "database" {
  for_each       = local.zones
  subnet_id      = aws_subnet.database[each.key].id
  route_table_id = aws_route_table.database.id
}

# S3 through a gateway endpoint (the stores, ECR's layers), from the
# workload subnets.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [for z, _ in local.zones : aws_route_table.workload[z].id]
  policy            = local.endpoint_policy
  tags              = merge(local.tags, { Name = "${local.name}-s3" })
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(var.interface_endpoints)
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [for z, _ in local.zones : aws_subnet.workload[z].id]
  security_group_ids  = [aws_security_group.endpoints.id]
  policy              = contains(local.endpoint_policy_services, each.key) ? local.endpoint_policy : null
  tags                = merge(local.tags, { Name = "${local.name}-${each.key}" })
}

# The Collector's way to the ops account (PrivateLink, outbound only).
resource "aws_vpc_endpoint" "telemetry" {
  count               = var.ops_telemetry == null ? 0 : 1
  vpc_id              = aws_vpc.this.id
  service_name        = var.ops_telemetry.service_name
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = false
  subnet_ids          = [for z, _ in local.zones : aws_subnet.workload[z].id]
  security_group_ids  = [aws_security_group.telemetry[0].id]
  tags                = merge(local.tags, { Name = "${local.name}-telemetry" })
}

# Flow logs: every accepted and rejected flow, to CloudWatch Logs under
# the logs key, kept a year.
resource "aws_cloudwatch_log_group" "flow" {
  name              = "/fair/${var.instance}/vpc-flow"
  kms_key_id        = aws_kms_key.home["logs"].arn
  retention_in_days = 365
  tags              = local.tags
}

resource "aws_flow_log" "this" {
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow.arn
  iam_role_arn             = aws_iam_role.service["flow-logs"].arn
  max_aggregation_interval = 60
  tags                     = local.tags
}

# Security groups. Rules are one map so the tests can read every rule:
# the only ingress from anywhere is HTTPS to the public load balancer. The
# nodes carry only their own group (not EKS's cluster security group,
# whose egress is open), so their egress is exactly these rules.
resource "aws_security_group" "alb" {
  name        = "${local.name}-alb"
  description = "The public load balancer: HTTPS in, the gateway pods out"
  vpc_id      = aws_vpc.this.id
  tags        = merge(local.tags, { Name = "${local.name}-alb" })
}

resource "aws_security_group" "nodes" {
  name        = "${local.name}-nodes"
  description = "The EKS nodes and pods"
  vpc_id      = aws_vpc.this.id
  tags        = merge(local.tags, { Name = "${local.name}-nodes" })
}

resource "aws_security_group" "cluster" {
  name        = "${local.name}-cluster"
  description = "The EKS API endpoint (private): HTTPS from the nodes"
  vpc_id      = aws_vpc.this.id
  tags        = merge(local.tags, { Name = "${local.name}-cluster" })
}

resource "aws_security_group" "database" {
  name        = "${local.name}-database"
  description = "PostgreSQL: from the nodes only"
  vpc_id      = aws_vpc.this.id
  tags        = merge(local.tags, { Name = "${local.name}-database" })
}

resource "aws_security_group" "endpoints" {
  name        = "${local.name}-endpoints"
  description = "Interface VPC endpoints: HTTPS from the VPC"
  vpc_id      = aws_vpc.this.id
  tags        = merge(local.tags, { Name = "${local.name}-endpoints" })
}

resource "aws_security_group" "telemetry" {
  count       = var.ops_telemetry == null ? 0 : 1
  name        = "${local.name}-telemetry"
  description = "The ops telemetry endpoint: from the nodes (the Collector)"
  vpc_id      = aws_vpc.this.id
  tags        = merge(local.tags, { Name = "${local.name}-telemetry" })
}

locals {
  sg = {
    alb       = aws_security_group.alb.id
    nodes     = aws_security_group.nodes.id
    cluster   = aws_security_group.cluster.id
    database  = aws_security_group.database.id
    endpoints = aws_security_group.endpoints.id
  }

  # group, type, protocol, from, to, and cidr or peer group (or self).
  sg_rules = merge(
    {
      alb_https_in       = { group = "alb", type = "ingress", protocol = "tcp", from = 443, to = 443, cidr = ["0.0.0.0/0"], peer = null, self = false, description = "HTTPS from the internet to the public entry (TLS 1.2+, FIPS policy; WAF)" }
      alb_to_gateway     = { group = "alb", type = "egress", protocol = "tcp", from = var.gateway_port, to = var.gateway_port, cidr = null, peer = "nodes", self = false, description = "To the gateway pods (HTTPS)" }
      nodes_from_alb     = { group = "nodes", type = "ingress", protocol = "tcp", from = var.gateway_port, to = var.gateway_port, cidr = null, peer = "alb", self = false, description = "The load balancer to the gateway pods" }
      nodes_self_in      = { group = "nodes", type = "ingress", protocol = "-1", from = 0, to = 0, cidr = null, peer = null, self = true, description = "Pod to pod and node to node (NetworkPolicies narrow it)" }
      nodes_self_out     = { group = "nodes", type = "egress", protocol = "-1", from = 0, to = 0, cidr = null, peer = null, self = true, description = "Pod to pod and node to node (NetworkPolicies narrow it)" }
      nodes_to_api       = { group = "nodes", type = "egress", protocol = "tcp", from = 443, to = 443, cidr = null, peer = "cluster", self = false, description = "To the private Kubernetes API" }
      nodes_to_database  = { group = "nodes", type = "egress", protocol = "tcp", from = 5432, to = 5432, cidr = null, peer = "database", self = false, description = "To PostgreSQL (TLS, verify-full)" }
      nodes_to_endpoints = { group = "nodes", type = "egress", protocol = "tcp", from = 443, to = 443, cidr = null, peer = "endpoints", self = false, description = "To the interface VPC endpoints" }
      nodes_dns_udp      = { group = "nodes", type = "egress", protocol = "udp", from = 53, to = 53, cidr = [var.vpc_cidr], peer = null, self = false, description = "To the VPC resolver" }
      nodes_dns_tcp      = { group = "nodes", type = "egress", protocol = "tcp", from = 53, to = 53, cidr = [var.vpc_cidr], peer = null, self = false, description = "To the VPC resolver" }
      cluster_from_nodes = { group = "cluster", type = "ingress", protocol = "tcp", from = 443, to = 443, cidr = null, peer = "nodes", self = false, description = "The nodes and pods to the Kubernetes API" }
      cluster_to_nodes   = { group = "cluster", type = "egress", protocol = "tcp", from = 1025, to = 65535, cidr = null, peer = "nodes", self = false, description = "The control plane to the kubelets and admission webhooks" }
      cluster_to_https   = { group = "cluster", type = "egress", protocol = "tcp", from = 443, to = 443, cidr = null, peer = "nodes", self = false, description = "The control plane to admission webhooks on 443" }
      nodes_from_api     = { group = "nodes", type = "ingress", protocol = "tcp", from = 1025, to = 65535, cidr = null, peer = "cluster", self = false, description = "The control plane to the kubelets and admission webhooks" }
      nodes_from_api_443 = { group = "nodes", type = "ingress", protocol = "tcp", from = 443, to = 443, cidr = null, peer = "cluster", self = false, description = "The control plane to admission webhooks on 443" }
      database_in        = { group = "database", type = "ingress", protocol = "tcp", from = 5432, to = 5432, cidr = null, peer = "nodes", self = false, description = "The services to PostgreSQL" }
      endpoints_in       = { group = "endpoints", type = "ingress", protocol = "tcp", from = 443, to = 443, cidr = [var.vpc_cidr], peer = null, self = false, description = "HTTPS from the VPC to the AWS service endpoints" }
    },
    { for port in var.external_egress_ports : "nodes_external_${port}" => {
      group       = "nodes", type = "egress", protocol = "tcp", from = port, to = port, cidr = ["0.0.0.0/0"], peer = null, self = false
      description = "Out through the NAT gateways (webhooks, connectors, SMTP; only notify and integrate pods by NetworkPolicy)"
    } },
    var.ops_telemetry == null ? {} : merge(
      { for port in var.ops_telemetry.ports : "nodes_to_telemetry_${port}" => {
        group = "nodes", type = "egress", protocol = "tcp", from = port, to = port, cidr = null, peer = "telemetry", self = false, description = "The Collector to the ops telemetry endpoint"
      } },
      { for port in var.ops_telemetry.ports : "telemetry_in_${port}" => {
        group = "telemetry", type = "ingress", protocol = "tcp", from = port, to = port, cidr = null, peer = "nodes", self = false, description = "The Collector to the ops telemetry endpoint"
      } },
    ),
  )
  sg_all = merge(local.sg, var.ops_telemetry == null ? {} : { telemetry = aws_security_group.telemetry[0].id })
}

resource "aws_security_group_rule" "rule" {
  for_each                 = local.sg_rules
  security_group_id        = local.sg_all[each.value.group]
  type                     = each.value.type
  protocol                 = each.value.protocol
  from_port                = each.value.from
  to_port                  = each.value.to
  cidr_blocks              = each.value.cidr
  source_security_group_id = each.value.peer == null ? null : local.sg_all[each.value.peer]
  self                     = each.value.self ? true : null
  description              = each.value.description
}
