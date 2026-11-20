# F-012 T-02 (F-012-AC-01; design §3.1): the repository's branch protection
# as code. Applied with a GitHub token that may administer the repository
# (never from CI on pull requests); tests run with a mock provider.
terraform {
  required_version = ">= 1.13.0"
  required_providers {
    github = {
      source  = "integrations/github"
      version = "6.13.0"
    }
  }
}

provider "github" {
  owner = var.owner
}
