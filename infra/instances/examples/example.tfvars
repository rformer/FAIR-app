# F-012 T-14: a fictional instance's spec, the shape of every
# infra/instances/<name>.tfvars (docs/operations/onboarding.md). Onboarding
# a customer is a pull request adding such a file; the pipeline creates the
# account (infra/instance-account) and the stack (infra/instance) after
# approval. This file sits in examples/, which the pipeline never applies;
# scripts/infra-check.sh tests it against every validation.
instance      = "example"
account_email = "aws+fair-example@fair-risk.example"
domain        = "example.fair-risk.example"

region             = "us-gov-west-1"
replica_region     = "us-gov-east-1"
availability_zones = ["us-gov-west-1a", "us-gov-west-1b", "us-gov-west-1c"]
vpc_cidr           = "10.40.0.0/16"

node_instance_types = ["m6i.xlarge"]
node_count          = { min = 3, desired = 3, max = 9 }
db_instance_class   = "db.r6i.large"

# The agreed retention of the audit trail (F-002 audit.retention_total).
audit_worm_retention_days = 2557
audit_retention_days      = 2557

# active, then retiring and retired at decommissioning
# (docs/operations/decommissioning.md), each a pull request.
status     = "active"
retirement = null
