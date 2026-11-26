# The instance's PostgreSQL 16 (design §3.5): Multi-AZ in the database
# subnets, reached only from the nodes, storage and Performance Insights
# under the database key, TLS required (rds.force_ssl, TLS 1.2 or later;
# the services connect with PGSSLMODE=verify-full), point-in-time recovery
# over 35 days, deletion protection, automated backups copied to the
# second region. The master password is managed by RDS in Secrets Manager
# under the secrets key (named rds!..., outside fair/<instance>/*, so the
# External Secrets role cannot read it); the roles' passwords are the
# fair/<instance>/database/* entries (secrets.tf).
resource "aws_db_subnet_group" "this" {
  count       = local.live ? 1 : 0
  name        = local.name
  description = "FAIR ${var.instance}: the database subnets (no route out of the VPC)"
  subnet_ids  = [for z, _ in local.zones : aws_subnet.database[z].id]
  tags        = local.tags
}

resource "aws_db_parameter_group" "this" {
  count       = local.live ? 1 : 0
  name        = "${local.name}-postgres16"
  family      = "postgres16"
  description = "FAIR ${var.instance}: TLS required, connection and DDL logging"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "ssl_min_protocol_version"
    value = "TLSv1.2"
  }
  parameter {
    name  = "password_encryption"
    value = "scram-sha-256"
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
  parameter {
    name  = "log_disconnections"
    value = "1"
  }
  # DDL only: data-bearing statements are never logged (ADR-017's rule for
  # telemetry applies to database logs too).
  parameter {
    name  = "log_statement"
    value = "ddl"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "-1"
  }

  tags = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "database" {
  for_each          = toset(["postgresql", "upgrade", "iam-db-auth-error"])
  name              = "/aws/rds/instance/${local.name}/${each.key}"
  kms_key_id        = aws_kms_key.home["logs"].arn
  retention_in_days = 365
  tags              = local.tags

  # Retained on decommissioning (var.status).
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_db_instance" "this" {
  count          = local.live ? 1 : 0
  identifier     = local.name
  engine         = "postgres"
  engine_version = var.postgres_version
  instance_class = var.db_instance_class
  db_name        = "fair"
  port           = 5432

  username                      = "fair_master"
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.home["secrets"].arn

  allocated_storage     = var.db_allocated_storage_gib
  max_allocated_storage = var.db_max_allocated_storage_gib
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.home["database"].arn

  multi_az               = true
  db_subnet_group_name   = aws_db_subnet_group.this[0].name
  vpc_security_group_ids = [aws_security_group.database[0].id]
  publicly_accessible    = false
  network_type           = "IPV4"
  ca_cert_identifier     = var.db_ca_cert_identifier

  parameter_group_name                = aws_db_parameter_group.this[0].name
  iam_database_authentication_enabled = var.db_iam_authentication

  backup_retention_period   = var.db_backup_retention_days
  backup_window             = "07:00-08:00"
  maintenance_window        = "sun:08:30-sun:09:30"
  copy_tags_to_snapshot     = true
  delete_automated_backups  = false
  deletion_protection       = local.protected
  skip_final_snapshot       = false
  final_snapshot_identifier = "${local.name}-final"

  auto_minor_version_upgrade  = true
  allow_major_version_upgrade = false
  apply_immediately           = false

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.home["database"].arn
  performance_insights_retention_period = 7
  monitoring_interval                   = 60
  monitoring_role_arn                   = aws_iam_role.service["rds-monitoring"].arn
  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade", "iam-db-auth-error"]

  tags       = local.tags
  depends_on = [aws_cloudwatch_log_group.database]
}

# Automated backups (snapshots and transaction logs) copied to the second
# region under its database key, kept as long as the source's.
resource "aws_db_instance_automated_backups_replication" "this" {
  count                  = local.live ? 1 : 0
  provider               = aws.replica
  source_db_instance_arn = aws_db_instance.this[0].arn
  kms_key_id             = aws_kms_key.replica["database"].arn
  retention_period       = var.db_backup_retention_days
}
