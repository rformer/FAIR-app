# The GovCloud management account (the organization's), FIPS endpoints only.
provider "aws" {
  region              = var.region
  use_fips_endpoint   = true
  allowed_account_ids = [var.account_id]
  default_tags {
    tags = local.tags
  }
}

# The paired commercial management account: only CreateGovCloudAccount (and
# its billing pair) is called through it.
provider "aws" {
  alias               = "commercial"
  region              = "us-east-1"
  use_fips_endpoint   = true
  allowed_account_ids = [var.commercial_account_id]
}
