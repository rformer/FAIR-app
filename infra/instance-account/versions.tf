terraform {
  required_version = ">= 1.13.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.72.0"
    }
    # decode_tfvars reads the instance's spec (infra/instances/<name>.tfvars).
    terraform = {
      source = "terraform.io/builtin/terraform"
    }
  }

  # Partial configuration (nothing secret is committed); the key is the
  # instance's (scripts/infra-instance.sh):
  #   tofu init -backend-config=instance-account.s3.tfbackend \
  #     -backend-config="bucket=fair-tofu-state-<management account id>" \
  #     -backend-config="key=instances/<name>/account.tfstate"
  backend "s3" {}
}
