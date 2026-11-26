# F-012 T-13 (F-012-AC-14, AC-15; design §3.5, §6 "I: one customer's
# instance reaches another's data"): the instance module's invariants, with
# mock providers (no AWS call): encryption under distinct per-purpose keys,
# Object Lock compliance, rds.force_ssl, a private and secrets-encrypted
# EKS, no public routes from private subnets, isolation, replication to the
# second region.
mock_provider "aws" {
  mock_resource "aws_eks_cluster" {
    defaults = {
      identity              = [{ oidc = [{ issuer = "https://oidc.eks.us-gov-west-1.amazonaws.com/id/0123456789ABCDEF0123456789ABCDEF" }] }]
      certificate_authority = [{ data = "LS0tLS1CRUdJTg==" }]
    }
  }
  mock_resource "aws_db_instance" {
    defaults = {
      master_user_secret = [{ secret_arn = "arn:aws-us-gov:secretsmanager:us-gov-west-1:777777777777:secret:rds!db-0000", kms_key_id = "k", secret_status = "active" }]
    }
  }
  mock_resource "aws_vpc_endpoint" {
    defaults = {
      dns_entry = [{ dns_name = "vpce-0000.vpce-svc-0000.us-gov-west-1.vpce.amazonaws.com", hosted_zone_id = "Z0000" }]
    }
  }
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws-us-gov:iam::777777777777:role/fair-acme-mock"
    }
  }
  mock_resource "aws_secretsmanager_secret" {
    defaults = {
      arn = "arn:aws-us-gov:secretsmanager:us-gov-west-1:777777777777:secret:fair/acme/mock-AbCdEf"
    }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws-us-gov:logs:us-gov-west-1:777777777777:log-group:mock"
    }
  }
  mock_resource "aws_lb" {
    defaults = {
      arn      = "arn:aws-us-gov:elasticloadbalancing:us-gov-west-1:777777777777:loadbalancer/app/fair-acme/0123456789abcdef"
      dns_name = "fair-acme-0123.us-gov-west-1.elb.amazonaws.com"
      zone_id  = "Z0000000000000"
    }
  }
  mock_resource "aws_lb_target_group" {
    defaults = {
      arn = "arn:aws-us-gov:elasticloadbalancing:us-gov-west-1:777777777777:targetgroup/fair-acme-gw/0123456789abcdef"
    }
  }
  mock_resource "aws_wafv2_web_acl" {
    defaults = {
      arn = "arn:aws-us-gov:wafv2:us-gov-west-1:777777777777:regional/webacl/fair-acme/00000000-0000-0000-0000-000000000000"
    }
  }
  mock_resource "aws_acmpca_certificate_authority" {
    defaults = {
      arn = "arn:aws-us-gov:acm-pca:us-gov-west-1:777777777777:certificate-authority/00000000-0000-0000-0000-000000000000"
    }
  }
  mock_resource "aws_acm_certificate" {
    defaults = {
      arn = "arn:aws-us-gov:acm:us-gov-west-1:777777777777:certificate/00000000-0000-0000-0000-000000000000"
    }
  }
  mock_resource "aws_acmpca_certificate" {
    defaults = {
      arn = "arn:aws-us-gov:acm-pca:us-gov-west-1:777777777777:certificate-authority/00000000-0000-0000-0000-000000000000/certificate/0000"
    }
  }
  mock_resource "aws_launch_template" {
    defaults = {
      id = "lt-0123456789abcdef0"
    }
  }
  mock_resource "aws_iam_openid_connect_provider" {
    defaults = {
      arn = "arn:aws-us-gov:iam::777777777777:oidc-provider/oidc.eks.us-gov-west-1.amazonaws.com/id/0123456789ABCDEF0123456789ABCDEF"
    }
  }
}

mock_provider "aws" {
  alias = "replica"
}

override_resource {
  target = aws_kms_key.home["database"]
  values = { arn = "arn:aws-us-gov:kms:us-gov-west-1:777777777777:key/00000000-0000-0000-0000-000000000100" }
}

override_resource {
  target = aws_kms_key.home["audit-worm"]
  values = { arn = "arn:aws-us-gov:kms:us-gov-west-1:777777777777:key/00000000-0000-0000-0000-000000000101" }
}

override_resource {
  target = aws_kms_key.home["audit-store"]
  values = { arn = "arn:aws-us-gov:kms:us-gov-west-1:777777777777:key/00000000-0000-0000-0000-000000000102" }
}

override_resource {
  target = aws_kms_key.home["report-store"]
  values = { arn = "arn:aws-us-gov:kms:us-gov-west-1:777777777777:key/00000000-0000-0000-0000-000000000103" }
}

override_resource {
  target = aws_kms_key.home["secrets"]
  values = { arn = "arn:aws-us-gov:kms:us-gov-west-1:777777777777:key/00000000-0000-0000-0000-000000000104" }
}

override_resource {
  target = aws_kms_key.home["eks"]
  values = { arn = "arn:aws-us-gov:kms:us-gov-west-1:777777777777:key/00000000-0000-0000-0000-000000000105" }
}

override_resource {
  target = aws_kms_key.home["nodes"]
  values = { arn = "arn:aws-us-gov:kms:us-gov-west-1:777777777777:key/00000000-0000-0000-0000-000000000106" }
}

override_resource {
  target = aws_kms_key.home["logs"]
  values = { arn = "arn:aws-us-gov:kms:us-gov-west-1:777777777777:key/00000000-0000-0000-0000-000000000107" }
}

override_resource {
  target = aws_kms_key.replica["database"]
  values = { arn = "arn:aws-us-gov:kms:us-gov-east-1:777777777777:key/00000000-0000-0000-0000-000000000200" }
}

override_resource {
  target = aws_kms_key.replica["audit-worm"]
  values = { arn = "arn:aws-us-gov:kms:us-gov-east-1:777777777777:key/00000000-0000-0000-0000-000000000201" }
}

override_resource {
  target = aws_kms_key.replica["audit-store"]
  values = { arn = "arn:aws-us-gov:kms:us-gov-east-1:777777777777:key/00000000-0000-0000-0000-000000000202" }
}

override_resource {
  target = aws_kms_key.replica["report-store"]
  values = { arn = "arn:aws-us-gov:kms:us-gov-east-1:777777777777:key/00000000-0000-0000-0000-000000000203" }
}

override_resource {
  target = aws_kms_key.replica["logs"]
  values = { arn = "arn:aws-us-gov:kms:us-gov-east-1:777777777777:key/00000000-0000-0000-0000-000000000204" }
}

override_resource {
  target = aws_kms_key.dnssec
  values = { arn = "arn:aws-us-gov:kms:us-gov-west-1:777777777777:key/00000000-0000-0000-0000-000000000300" }
}

override_resource {
  target = aws_db_instance.this
  values = {
    arn                = "arn:aws-us-gov:rds:us-gov-west-1:777777777777:db:fair-acme"
    address            = "fair-acme.c0000000000.us-gov-west-1.rds.amazonaws.com"
    master_user_secret = [{ secret_arn = "arn:aws-us-gov:secretsmanager:us-gov-west-1:777777777777:secret:rds!db-0000", kms_key_id = "k", secret_status = "active" }]
  }
}

# Distinct ids where the tests compare them (mock ids are per type).
override_resource {
  target = aws_security_group.alb
  values = { id = "sg-0a1b000000000001" }
}

override_resource {
  target = aws_security_group.nodes
  values = { id = "sg-0a1b000000000002" }
}

override_resource {
  target = aws_security_group.cluster
  values = { id = "sg-0a1b000000000003" }
}

override_resource {
  target = aws_security_group.database
  values = { id = "sg-0a1b000000000004" }
}

override_resource {
  target = aws_security_group.endpoints
  values = { id = "sg-0a1b000000000005" }
}

override_resource {
  target = aws_security_group.telemetry
  values = { id = "sg-0a1b000000000006" }
}

override_resource {
  target = aws_route_table.public
  values = { id = "rtb-0a1b000000000001" }
}

override_resource {
  target = aws_route_table.workload
  values = { id = "rtb-0a1b000000000002" }
}

override_resource {
  target = aws_route_table.database
  values = { id = "rtb-0a1b000000000003" }
}

override_resource {
  target = aws_internet_gateway.this
  values = { id = "igw-0a1b000000000001" }
}

override_resource {
  target = aws_nat_gateway.this
  values = { id = "nat-0a1b000000000001" }
}

variables {
  instance   = "acme"
  account_id = "777777777777"
  domain     = "acme.fair-risk.example"
}

run "every_store_is_encrypted_under_its_own_key" {
  command = plan

  assert {
    condition = alltrue([
      module.audit_worm.kms_key_arn == aws_kms_key.home["audit-worm"].arn,
      module.audit_store.kms_key_arn == aws_kms_key.home["audit-store"].arn,
      module.report_store.kms_key_arn == aws_kms_key.home["report-store"].arn,
      module.access.kms_key_arn == aws_kms_key.home["logs"].arn,
      module.audit_worm_replica.kms_key_arn == aws_kms_key.replica["audit-worm"].arn,
      module.audit_store_replica.kms_key_arn == aws_kms_key.replica["audit-store"].arn,
      module.report_store_replica.kms_key_arn == aws_kms_key.replica["report-store"].arn,
      module.access_replica.kms_key_arn == aws_kms_key.replica["logs"].arn,
    ])
    error_message = "each bucket (and replica) under its purpose's key"
  }
  assert {
    condition     = aws_db_instance.this.storage_encrypted && aws_db_instance.this.kms_key_id == aws_kms_key.home["database"].arn && aws_db_instance.this.performance_insights_kms_key_id == aws_kms_key.home["database"].arn
    error_message = "the database's storage and Performance Insights under the database key"
  }
  assert {
    condition     = aws_db_instance.this.master_user_secret_kms_key_id == aws_kms_key.home["secrets"].arn && aws_db_instance_automated_backups_replication.this.kms_key_id == aws_kms_key.replica["database"].arn
    error_message = "the master secret under the secrets key; backup copies under the replica database key"
  }
  assert {
    condition     = aws_eks_cluster.this.encryption_config[0].provider[0].key_arn == aws_kms_key.home["eks"].arn && contains(aws_eks_cluster.this.encryption_config[0].resources, "secrets")
    error_message = "Kubernetes Secrets envelope-encrypted under the eks key"
  }
  assert {
    condition     = alltrue([for s in aws_secretsmanager_secret.this : s.kms_key_id == aws_kms_key.home["secrets"].arn])
    error_message = "every secret under the secrets key"
  }
  assert {
    condition = alltrue([for g in concat([aws_cloudwatch_log_group.flow, aws_cloudwatch_log_group.cluster, aws_cloudwatch_log_group.dns, aws_cloudwatch_log_group.waf], values(aws_cloudwatch_log_group.database)) :
    g.kms_key_id == aws_kms_key.home["logs"].arn && g.retention_in_days >= 365])
    error_message = "every log group under the logs key, kept a year"
  }
  assert {
    condition     = alltrue([for d in aws_launch_template.nodes.block_device_mappings : d.ebs[0].encrypted == "true" && d.ebs[0].kms_key_id == aws_kms_key.home["nodes"].arn])
    error_message = "node volumes under the nodes key"
  }
  assert {
    condition     = length(distinct(concat([for k in aws_kms_key.home : k.arn], [for k in aws_kms_key.replica : k.arn], [aws_kms_key.dnssec.arn]))) == 14 && toset(keys(aws_kms_key.home)) == toset(["database", "audit-worm", "audit-store", "report-store", "secrets", "eks", "nodes", "logs"]) && toset(keys(aws_kms_key.replica)) == toset(["database", "audit-worm", "audit-store", "report-store", "logs"])
    error_message = "one distinct key per purpose and region"
  }
  assert {
    condition     = alltrue([for k in concat(values(aws_kms_key.home), values(aws_kms_key.replica)) : k.enable_key_rotation && !k.multi_region && k.deletion_window_in_days == 30])
    error_message = "keys rotate yearly, single region, the longest deletion window"
  }
}

run "the_audit_worm_bucket_is_object_lock_compliance" {
  command = plan

  assert {
    condition     = module.audit_worm.object_lock.enabled && module.audit_worm.object_lock.mode == "COMPLIANCE" && module.audit_worm.object_lock.days >= 365
    error_message = "the audit WORM bucket under Object Lock in compliance mode (internal/objstore CheckBucket)"
  }
  assert {
    condition     = module.audit_worm_replica.object_lock.mode == "COMPLIANCE" && module.audit_worm_replica.object_lock.days == module.audit_worm.object_lock.days
    error_message = "its replica too"
  }
  assert {
    condition     = module.audit_store.object_lock_enabled && module.audit_store_replica.object_lock_enabled
    error_message = "the audit store has Object Lock (each write locked until its own date; CheckBucket)"
  }
  assert {
    condition     = alltrue([module.report_store.versioned, module.audit_store.versioned, module.audit_worm.versioned])
    error_message = "every store versioned (CheckVersioned)"
  }
  assert {
    condition     = alltrue([for b in [module.audit_worm, module.audit_store, module.report_store, module.access, module.audit_worm_replica, module.audit_store_replica, module.report_store_replica, module.access_replica] : b.public_access_blocked])
    error_message = "no bucket public"
  }
  assert {
    condition     = alltrue([for b in [module.audit_worm, module.audit_store, module.report_store] : b.access_log_bucket == module.access.id])
    error_message = "stores' access logged"
  }
}

run "stores_replicate_to_the_second_region" {
  command = plan

  assert {
    condition = alltrue([
      module.audit_worm.replication.destination_bucket_arn == module.audit_worm_replica.arn && module.audit_worm.replication.replica_kms_key_arn == aws_kms_key.replica["audit-worm"].arn,
      module.audit_store.replication.destination_bucket_arn == module.audit_store_replica.arn && module.audit_store.replication.replica_kms_key_arn == aws_kms_key.replica["audit-store"].arn,
      module.report_store.replication.destination_bucket_arn == module.report_store_replica.arn && module.report_store.replication.replica_kms_key_arn == aws_kms_key.replica["report-store"].arn,
    ])
    error_message = "the audit WORM, audit store and report store replicate to their replicas under the replica keys"
  }
  assert {
    condition     = alltrue([for b in [module.audit_worm, module.audit_store, module.report_store] : b.replication.role_arn == aws_iam_role.service["replication"].arn])
    error_message = "by the replication role"
  }
  assert {
    condition     = module.audit_worm_replica.expiration_days == 2557 && module.audit_store_replica.expiration_days == 2557 && module.report_store_replica.expiration_days == 30
    error_message = "replicas age out with the retention (they do not receive the source's deletes)"
  }
  assert {
    condition     = module.audit_worm.expiration_days == null && module.audit_store.expiration_days == null && module.report_store.expiration_days == null
    error_message = "the sources expire nothing themselves (the services delete by version)"
  }
  assert {
    condition     = aws_db_instance_automated_backups_replication.this.source_db_instance_arn == aws_db_instance.this.arn && aws_db_instance_automated_backups_replication.this.retention_period == 35
    error_message = "the database's automated backups copied to the second region, 35 days"
  }
}

run "replica_region_must_differ" {
  command = plan
  variables {
    replica_region = "us-gov-west-1"
  }
  expect_failures = [var.replica_region]
}

run "the_database_requires_tls" {
  command = plan

  assert {
    condition     = one([for p in aws_db_parameter_group.this.parameter : p.value if p.name == "rds.force_ssl"]) == "1"
    error_message = "rds.force_ssl = 1"
  }
  assert {
    condition     = one([for p in aws_db_parameter_group.this.parameter : p.value if p.name == "ssl_min_protocol_version"]) == "TLSv1.2"
    error_message = "TLS 1.2 or later"
  }
  assert {
    condition     = aws_db_parameter_group.this.family == "postgres16" && aws_db_instance.this.engine == "postgres" && aws_db_instance.this.engine_version == "16" && aws_db_instance.this.parameter_group_name == aws_db_parameter_group.this.name
    error_message = "PostgreSQL 16 with this parameter group"
  }
  assert {
    condition     = one([for p in aws_db_parameter_group.this.parameter : p.value if p.name == "log_statement"]) == "ddl"
    error_message = "no data-bearing statement logged"
  }
  assert {
    condition     = aws_db_instance.this.multi_az && !aws_db_instance.this.publicly_accessible && aws_db_instance.this.deletion_protection && !aws_db_instance.this.skip_final_snapshot
    error_message = "Multi-AZ, private, deletion protection, a final snapshot"
  }
  assert {
    condition     = aws_db_instance.this.backup_retention_period == 35 && aws_db_instance.this.manage_master_user_password
    error_message = "35 days of point-in-time recovery; the master password managed by RDS"
  }
  assert {
    condition     = aws_db_instance.this.vpc_security_group_ids == toset([aws_security_group.database.id]) && aws_db_subnet_group.this.subnet_ids == toset([for s in aws_subnet.database : s.id])
    error_message = "in the database subnets, behind the database group"
  }
}

run "short_backups_refused" {
  command = plan
  variables {
    db_backup_retention_days = 7
  }
  expect_failures = [var.db_backup_retention_days]
}

run "the_cluster_is_private_and_encrypted" {
  command = plan

  assert {
    condition     = aws_eks_cluster.this.vpc_config[0].endpoint_private_access && !aws_eks_cluster.this.vpc_config[0].endpoint_public_access
    error_message = "the API endpoint is private only"
  }
  assert {
    condition     = aws_eks_cluster.this.enabled_cluster_log_types == toset(["api", "audit", "authenticator", "controllerManager", "scheduler"])
    error_message = "every control-plane log"
  }
  assert {
    condition     = aws_eks_cluster.this.access_config[0].authentication_mode == "API" && !aws_eks_cluster.this.access_config[0].bootstrap_cluster_creator_admin_permissions
    error_message = "access entries only; no implicit administrator"
  }
  assert {
    condition     = aws_eks_node_group.this.ami_type == "BOTTLEROCKET_x86_64_FIPS"
    error_message = "nodes on Bottlerocket's FIPS variant"
  }
  assert {
    condition     = aws_launch_template.nodes.metadata_options[0].http_tokens == "required" && aws_launch_template.nodes.metadata_options[0].http_put_response_hop_limit == 1
    error_message = "IMDSv2 only, unreachable from pods"
  }
  assert {
    condition     = aws_launch_template.nodes.vpc_security_group_ids == toset([aws_security_group.nodes.id])
    error_message = "nodes carry only their own group (their egress is exactly its rules)"
  }
  assert {
    condition     = aws_eks_cluster.this.vpc_config[0].subnet_ids == toset([for s in aws_subnet.workload : s.id]) && aws_eks_node_group.this.subnet_ids == toset([for s in aws_subnet.workload : s.id])
    error_message = "control-plane interfaces and nodes in the workload subnets"
  }
}

run "no_public_routes_from_private_subnets" {
  command = plan

  assert {
    condition     = alltrue([for r in aws_route.workload_egress : r.nat_gateway_id != null && r.gateway_id == null])
    error_message = "the workload subnets' default route is a NAT gateway, never the internet gateway"
  }
  assert {
    condition     = aws_route.public_internet.route_table_id == aws_route_table.public.id && aws_route.public_internet.gateway_id == aws_internet_gateway.this.id
    error_message = "only the public route table routes to the internet gateway"
  }
  assert {
    condition     = toset([for a in aws_route_table_association.public : a.subnet_id]) == toset([for s in aws_subnet.public : s.id])
    error_message = "the public route table serves the public subnets only"
  }
  assert {
    condition     = alltrue([for a in aws_route_table_association.workload : a.route_table_id != aws_route_table.public.id]) && alltrue([for a in aws_route_table_association.database : a.route_table_id == aws_route_table.database.id])
    error_message = "workload and database subnets never use the public route table"
  }
  assert {
    condition     = alltrue([for r in aws_route.workload_egress : r.route_table_id != aws_route_table.database.id])
    error_message = "the database subnets have no route out of the VPC"
  }
  assert {
    condition     = alltrue([for s in concat(values(aws_subnet.public), values(aws_subnet.workload), values(aws_subnet.database)) : !s.map_public_ip_on_launch])
    error_message = "no instance gets a public address"
  }
  assert {
    condition     = alltrue([for n in aws_nat_gateway.this : contains([for s in aws_subnet.public : s.id], n.subnet_id)])
    error_message = "NAT gateways in the public subnets"
  }
  assert {
    condition     = aws_flow_log.this.traffic_type == "ALL" && aws_flow_log.this.vpc_id == aws_vpc.this.id
    error_message = "every flow logged"
  }
  assert {
    condition     = length(aws_default_security_group.this.ingress) == 0 && length(aws_default_security_group.this.egress) == 0
    error_message = "the default security group allows nothing"
  }
}

run "only_the_load_balancer_is_open_to_the_internet" {
  command = plan

  assert {
    condition = alltrue([for k, r in aws_security_group_rule.rule :
      k == "alb_https_in" && r.security_group_id == aws_security_group.alb.id && r.from_port == 443 && r.to_port == 443 && r.protocol == "tcp"
    if r.type == "ingress" && contains(coalesce(r.cidr_blocks, []), "0.0.0.0/0")])
    error_message = "the only ingress from anywhere: HTTPS to the public load balancer"
  }
  assert {
    condition = alltrue([for k, r in aws_security_group_rule.rule :
      r.security_group_id == aws_security_group.nodes.id && r.protocol == "tcp" && r.from_port == r.to_port && contains([443, 465, 587], r.from_port)
    if r.type == "egress" && contains(coalesce(r.cidr_blocks, []), "0.0.0.0/0")])
    error_message = "egress to anywhere: the nodes on HTTPS and SMTP submission only"
  }
  assert {
    condition     = alltrue([for k, r in aws_security_group_rule.rule : r.cidr_blocks == null || alltrue([for c in r.cidr_blocks : c == "0.0.0.0/0" || c == var.vpc_cidr || c == "10.40.0.0/16"])])
    error_message = "no rule names another network (no peer, no other instance)"
  }
  assert {
    condition     = alltrue([for k, r in aws_security_group_rule.rule : contains([aws_security_group.alb.id, aws_security_group.nodes.id, aws_security_group.cluster.id, aws_security_group.database.id, aws_security_group.endpoints.id], r.source_security_group_id) if r.cidr_blocks == null && r.self != true])
    error_message = "peer groups are the instance's own"
  }
  assert {
    condition     = alltrue([for k, r in aws_security_group_rule.rule : r.from_port == 5432 if r.security_group_id == aws_security_group.database.id]) && alltrue([for k, r in aws_security_group_rule.rule : r.source_security_group_id == aws_security_group.nodes.id if r.security_group_id == aws_security_group.database.id])
    error_message = "the database only from the nodes"
  }
  assert {
    condition     = aws_lb_listener.https.port == 443 && aws_lb_listener.https.protocol == "HTTPS" && aws_lb_listener.https.ssl_policy == "ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04"
    error_message = "the listener is HTTPS with the FIPS TLS 1.2/1.3 policy"
  }
  assert {
    condition     = aws_lb_target_group.gateway.protocol == "HTTPS" && aws_lb_target_group.gateway.health_check[0].protocol == "HTTPS" && aws_lb.public.drop_invalid_header_fields
    error_message = "HTTPS to the gateway pods too"
  }
}

run "the_public_entry_is_behind_the_waf" {
  command = plan

  assert {
    condition     = aws_wafv2_web_acl_association.public.resource_arn == aws_lb.public.arn && aws_wafv2_web_acl_association.public.web_acl_arn == aws_wafv2_web_acl.public.arn
    error_message = "the web ACL protects the load balancer"
  }
  assert {
    condition = alltrue([for g in ["AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet", "AWSManagedRulesSQLiRuleSet", "AWSManagedRulesAnonymousIpList"] :
    contains([for r in aws_wafv2_web_acl.public.rule : r.name], g)]) && contains([for r in aws_wafv2_web_acl.public.rule : r.name], "RateLimitPerAddress")
    error_message = "managed rule groups and a rate limit"
  }
  assert {
    condition     = toset([for f in aws_wafv2_web_acl_logging_configuration.public.redacted_fields : f.single_header[0].name]) == toset(["authorization", "cookie"])
    error_message = "WAF logs never carry the session cookie or bearer tokens"
  }
  assert {
    condition     = aws_acm_certificate.public.domain_name == var.domain && aws_acm_certificate.public.key_algorithm == "EC_prime256v1" && aws_acm_certificate.public.validation_method == "DNS"
    error_message = "an ECDSA certificate for the instance's name, DNS-validated"
  }
  assert {
    condition     = aws_route53_hosted_zone_dnssec.public.signing_status == "SIGNING" && aws_kms_key.dnssec.customer_master_key_spec == "ECC_NIST_P256"
    error_message = "the public zone is DNSSEC-signed"
  }
  assert {
    condition     = aws_acmpca_certificate_authority.internal.key_storage_security_standard == "FIPS_140_2_LEVEL_3_OR_HIGHER" && aws_acmpca_certificate_authority.internal.usage_mode == "SHORT_LIVED_CERTIFICATE"
    error_message = "internal TLS from the instance's own Private CA, keys in FIPS HSMs"
  }
}

run "isolation" {
  command = plan

  # Every Allow names this account's principals, AWS services, the
  # cluster's own OIDC provider, or "*" bound to this account by condition.
  assert {
    condition = alltrue(flatten([for name, doc in output.policy_documents : [for s in jsondecode(doc).Statement :
      s.Effect != "Allow" || !can(s.Principal) || anytrue([
        can(s.Principal.Service) && !can(s.Principal.AWS) && !can(s.Principal.Federated),
        can(s.Principal.AWS) && alltrue([for a in try(flatten([s.Principal.AWS]), ["*"]) : strcontains(a, ":777777777777:")]),
        try(s.Principal.Federated, "") == aws_iam_openid_connect_provider.cluster.arn,
        try(s.Principal == "*", false) && try(s.Condition.StringEquals["aws:PrincipalAccount"], "") == "777777777777",
    ])]]))
    error_message = "no policy allows another account or an unbound wildcard principal"
  }
  # No ARN in any policy names another account.
  assert {
    condition     = alltrue(flatten([for name, doc in output.policy_documents : [for acct in flatten(regexall("arn:aws-us-gov:[a-z0-9-]+:[a-z0-9-]*:([0-9]{12}):", doc)) : acct == "777777777777"]]))
    error_message = "every account named is the instance's"
  }
  assert {
    condition     = length(output.policy_documents) >= 60
    error_message = "the isolation checks cover every policy the module writes"
  }
  # Keys, buckets and secrets refuse every other account explicitly.
  assert {
    condition = alltrue([for name, doc in output.policy_documents : anytrue([for s in jsondecode(doc).Statement :
      s.Sid == "DenyOutsideTheInstance" && s.Effect == "Deny" && try(s.Condition.StringNotEquals["aws:PrincipalAccount"], "") == "777777777777"
    ]) if startswith(name, "kms") || startswith(name, "s3/") || startswith(name, "secret/")])
    error_message = "every key, bucket and secret denies principals of other accounts"
  }
  # Endpoint policies: only this account's principals use the endpoints.
  assert {
    condition     = alltrue([for name, doc in output.policy_documents : jsondecode(doc).Statement[0].Condition.StringEquals["aws:PrincipalAccount"] == "777777777777" if startswith(name, "endpoint/")]) && contains(keys(output.policy_documents), "endpoint/s3") && contains(keys(output.policy_documents), "endpoint/kms-fips")
    error_message = "the VPC endpoints serve this account only"
  }
}

run "external_secrets_reads_only_this_instance" {
  command = plan

  assert {
    condition = alltrue([for s in jsondecode(output.policy_documents["role/external-secrets"]).Statement :
      s.Resource == "arn:aws-us-gov:secretsmanager:us-gov-west-1:777777777777:secret:fair/acme/*"
    if anytrue([for a in flatten([s.Action]) : startswith(a, "secretsmanager:")])])
    error_message = "the External Secrets role reads fair/acme/* only"
  }
  assert {
    condition = alltrue(flatten([for name, doc in output.policy_documents : [for s in jsondecode(doc).Statement :
      !anytrue([for a in flatten([s.Action]) : startswith(a, "secretsmanager:")])
    if s.Effect == "Allow"] if startswith(name, "role/") && name != "role/external-secrets"]))
    error_message = "no other workload or service role reads secrets"
  }
  assert {
    condition = alltrue([for s in jsondecode(output.policy_documents["role/external-secrets"]).Statement :
      s.Resource == aws_kms_key.home["secrets"].arn && s.Condition.StringEquals["kms:ViaService"] == "secretsmanager.us-gov-west-1.amazonaws.com"
    if anytrue([for a in flatten([s.Action]) : startswith(a, "kms:")])])
    error_message = "it decrypts with the secrets key, through Secrets Manager only"
  }
  assert {
    condition     = jsondecode(aws_iam_role.irsa["external-secrets"].assume_role_policy).Statement[0].Condition.StringEquals["oidc.eks.us-gov-west-1.amazonaws.com/id/0123456789ABCDEF0123456789ABCDEF:sub"] == "system:serviceaccount:fair-platform:fair-external-secrets"
    error_message = "assumed only by the SecretStore's service account (deploy/k8s/keys/saas)"
  }
  assert {
    condition = alltrue([for k, r in aws_iam_role.irsa : length(jsondecode(r.assume_role_policy).Statement) == 1 && jsondecode(r.assume_role_policy).Statement[0].Action == "sts:AssumeRoleWithWebIdentity"
    && length(jsondecode(r.assume_role_policy).Statement[0].Condition.StringEquals) == 2])
    error_message = "each workload role trusts one service account, by sub and aud"
  }
  assert {
    condition = alltrue([for name, doc in output.policy_documents : anytrue([for s in jsondecode(doc).Statement :
      s.Effect == "Deny" && s.Action == "secretsmanager:GetSecretValue" && s.Condition.ArnNotEquals["aws:PrincipalArn"] == ["arn:aws-us-gov:iam::777777777777:role/fair-acme-external-secrets"]
    ]) if startswith(name, "secret/")])
    error_message = "each secret's value is readable by the External Secrets role alone"
  }
}

run "stores_are_touched_only_by_their_service" {
  command = plan

  assert {
    condition     = toset(jsondecode(module.audit_worm.policy).Statement[4].Condition.ArnNotEquals["aws:PrincipalArn"]) == toset(["arn:aws-us-gov:iam::777777777777:role/fair-acme-audit", "arn:aws-us-gov:iam::777777777777:role/fair-acme-replication"])
    error_message = "audit WORM objects: the audit service and replication only"
  }
  assert {
    condition     = toset(jsondecode(module.report_store.policy).Statement[4].Condition.ArnNotEquals["aws:PrincipalArn"]) == toset(["arn:aws-us-gov:iam::777777777777:role/fair-acme-risk", "arn:aws-us-gov:iam::777777777777:role/fair-acme-replication"])
    error_message = "report objects: the risk service and replication only"
  }
  assert {
    condition = alltrue([for s in jsondecode(output.policy_documents["role/audit"]).Statement :
    !contains(flatten([s.Action]), "s3:DeleteObjectVersion") if contains(flatten([s.Resource]), "arn:aws-us-gov:s3:::fair-acme-audit-worm-777777777777/*")])
    error_message = "the audit service never deletes checkpoint copies"
  }
}

run "secrets_follow_the_key_layout" {
  command = plan

  assert {
    condition = output.secret_names == sort(concat(
      [for e in ["gateway/jwt", "gateway/login-ticket", "gateway/secrets", "iam/jwt", "iam/login-ticket", "iam/secrets", "posture/jwt", "audit/jwt", "audit/checkpoint", "risk/jwt", "risk/engine-client", "risk/secrets", "engine-gate/tls", "notify/jwt", "notify/webhook-secrets", "integrate/jwt", "integrate/secrets"] : "fair/acme/${e}"],
      [for r in ["app_migrator", "app_rw", "app_engine", "app_posture", "app_gateway", "app_audit", "app_notify", "app_integrate"] : "fair/acme/database/${r}"],
    ))
    error_message = "one entry per F-001 T-41 store entry (deploy/k8s/keys/saas) and per database login role"
  }
  assert {
    condition     = alltrue([for s in aws_secretsmanager_secret.this : s.recovery_window_in_days == 30])
    error_message = "deleted secrets recoverable for 30 days"
  }
  assert {
    condition     = output.service_environment.FAIR_AUDIT_WORM.FAIR_AUDIT_WORM_ENDPOINT == "s3-fips.us-gov-west-1.amazonaws.com:443" && output.service_environment.FAIR_REPORT_STORE.FAIR_REPORT_STORE_BUCKET == "fair-acme-report-store-777777777777"
    error_message = "the services reach the stores at the S3 FIPS endpoint"
  }
}

run "telemetry_through_privatelink" {
  command = plan
  variables {
    ops_telemetry = { service_name = "com.amazonaws.vpce.us-gov-west-1.vpce-svc-0123456789abcdef0", ports = [4317, 443] }
  }

  assert {
    condition     = aws_vpc_endpoint.telemetry[0].vpc_endpoint_type == "Interface" && aws_vpc_endpoint.telemetry[0].security_group_ids == toset([aws_security_group.telemetry[0].id])
    error_message = "the Collector reaches the ops account through its endpoint"
  }
  assert {
    condition     = alltrue([for k, r in aws_security_group_rule.rule : r.source_security_group_id == aws_security_group.nodes.id if r.security_group_id == aws_security_group.telemetry[0].id])
    error_message = "the endpoint only from the nodes"
  }
}

run "cluster_admins_of_another_account_refused" {
  command = plan
  variables {
    cluster_admin_role_arns = ["arn:aws-us-gov:iam::888888888888:role/somebody"]
  }
  expect_failures = [var.cluster_admin_role_arns]
}

run "plaintext_http_egress_refused" {
  command = plan
  variables {
    external_egress_ports = [443, 80]
  }
  expect_failures = [var.external_egress_ports]
}

run "a_rotation_role_reads_key_files_never_passwords" {
  command = plan
  variables {
    secret_reader_role_arns = ["arn:aws-us-gov:iam::777777777777:role/fair-key-rotation"]
  }

  assert {
    condition = alltrue([for name, doc in output.policy_documents : anytrue([for s in jsondecode(doc).Statement :
      s.Effect == "Deny" && s.Action == "secretsmanager:GetSecretValue" && jsonencode(s.Condition.ArnNotEquals["aws:PrincipalArn"]) == (startswith(name, "secret/database/")
        ? jsonencode(["arn:aws-us-gov:iam::777777777777:role/fair-acme-external-secrets"])
      : jsonencode(["arn:aws-us-gov:iam::777777777777:role/fair-acme-external-secrets", "arn:aws-us-gov:iam::777777777777:role/fair-key-rotation"]))
    ]) if startswith(name, "secret/")])
    error_message = "the rotation role reads the key files; database passwords stay External Secrets' alone"
  }
}

run "secret_readers_of_another_account_refused" {
  command = plan
  variables {
    secret_reader_role_arns = ["arn:aws-us-gov:iam::888888888888:role/somebody"]
  }
  expect_failures = [var.secret_reader_role_arns]
}
