# The GovCloud management account: the pipeline's credentials there
# (fair-instances-plan or fair-instances-apply, from the workflow's OIDC
# token: AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE). FIPS endpoints only.
provider "aws" {
  region              = var.region
  use_fips_endpoint   = true
  allowed_account_ids = [var.account_id]
  default_tags {
    tags = local.tags
  }
}

# The paired commercial management account (CreateGovCloudAccount), with
# the same OIDC token and the commercial pipeline role.
provider "aws" {
  alias               = "commercial"
  region              = "us-east-1"
  use_fips_endpoint   = true
  allowed_account_ids = [var.commercial_account_id]
  assume_role_with_web_identity {
    role_arn                = var.commercial_role_arn
    web_identity_token_file = var.web_identity_token_file
    session_name            = "fair-instance-${var.instance}"
  }
}
