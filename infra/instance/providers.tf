# The pipeline's credentials are the management account's
# (fair-instances-plan or fair-instances-apply, from the workflow's OIDC
# token); every provider assumes the role var.mode names, in this
# instance's account only (or the shared account for the parent zone).
# FIPS endpoints only (ADR-016).
provider "aws" {
  region              = var.region
  use_fips_endpoint   = true
  allowed_account_ids = [var.account_id]
  assume_role {
    role_arn     = local.role_arn[var.mode]
    session_name = "fair-instance-${var.instance}-${var.mode}"
  }
  default_tags {
    tags = local.tags
  }
}

provider "aws" {
  alias               = "replica"
  region              = var.replica_region
  use_fips_endpoint   = true
  allowed_account_ids = [var.account_id]
  assume_role {
    role_arn     = local.role_arn[var.mode]
    session_name = "fair-instance-${var.instance}-${var.mode}"
  }
  default_tags {
    tags = local.tags
  }
}

# The SaaS parent zone (shared account): NS and DS records only.
provider "aws" {
  alias               = "dns"
  region              = var.region
  use_fips_endpoint   = true
  allowed_account_ids = [var.dns.account_id]
  assume_role {
    role_arn     = local.dns_role_arn[var.mode]
    session_name = "fair-instance-${var.instance}-${var.mode}"
  }
}
