terraform {
  required_version = ">= 1.13.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.72.0"
      # aws: the GovCloud management account; aws.commercial: the paired
      # commercial management account.
      configuration_aliases = [aws.commercial]
    }
  }
}
