terraform {
  required_version = ">= 1.13.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.72.0"
      # aws: the instance's home region; aws.replica: the second GovCloud
      # region, holding the replicas and the database's backup copies.
      configuration_aliases = [aws.replica]
    }
  }
}
