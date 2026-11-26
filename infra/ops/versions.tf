terraform {
  required_version = ">= 1.13.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.72.0"
    }
  }

  # Partial configuration (nothing secret is committed):
  #   tofu init -backend-config=state.s3.tfbackend \
  #     -backend-config="bucket=fair-tofu-state-<management account id>"
  backend "s3" {}
}
