terraform {
  required_version = ">= 1.13.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.72.0"
    }
  }

  # Partial configuration (nothing secret is committed); the key is the
  # instance's (scripts/infra-instance.sh):
  #   tofu init -backend-config=instance.s3.tfbackend \
  #     -backend-config="bucket=fair-tofu-state-<management account id>" \
  #     -backend-config="key=instances/<name>/terraform.tfstate"
  backend "s3" {}
}
