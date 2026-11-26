# The management account, with the credentials of the pipeline's role there.
# FIPS endpoints only (ADR-016); no other account can be touched by mistake.
provider "aws" {
  region              = var.region
  use_fips_endpoint   = true
  allowed_account_ids = [var.account_id]
  default_tags {
    tags = local.tags
  }
}
