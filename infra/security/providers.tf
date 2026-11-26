# The security account, through its infrastructure role (the pipeline's
# management-account credentials assume it); FIPS endpoints only.
provider "aws" {
  region              = var.region
  use_fips_endpoint   = true
  allowed_account_ids = [var.account_id]
  assume_role {
    role_arn     = "arn:${var.partition}:iam::${var.account_id}:role/${var.infrastructure_role_name}"
    session_name = "fair-infra-security"
  }
  default_tags {
    tags = local.tags
  }
}
