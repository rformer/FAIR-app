# F-012 T-12: the release mirror's invariants, with a mock provider.
mock_provider "aws" {}

variables {
  account_id      = "222222222222"
  organization_id = "o-abcdefghij"
  pull_org_paths  = ["o-abcdefghij/r-ab12/ou-ab12-instances/*"]
}

run "immutable_scanned_encrypted" {
  command = plan

  assert {
    condition     = length(aws_ecr_repository.this) >= 11 && contains(keys(aws_ecr_repository.this), "engine") && contains(keys(aws_ecr_repository.this), "mirror/policy-controller")
    error_message = "every platform image and the mirrored admission controller have a repository"
  }
  assert {
    condition     = alltrue([for r in aws_ecr_repository.this : r.image_tag_mutability == "IMMUTABLE"])
    error_message = "tags are immutable"
  }
  assert {
    condition     = alltrue([for r in aws_ecr_repository.this : one(r.image_scanning_configuration).scan_on_push])
    error_message = "every push is scanned"
  }
  assert {
    condition     = alltrue([for r in aws_ecr_repository.this : one(r.encryption_configuration).encryption_type == "KMS" && one(r.encryption_configuration).kms_key == aws_kms_key.mirror.arn])
    error_message = "encrypted with the mirror's KMS key"
  }
  assert {
    condition     = alltrue([for r in aws_ecr_repository.this : !r.force_delete])
    error_message = "repositories holding images are never force-deleted"
  }
  assert {
    condition     = aws_kms_key.mirror.enable_key_rotation
    error_message = "the mirror key rotates"
  }
}

run "pulls_by_organization_paths_and_no_push_by_default" {
  command = plan

  assert {
    condition     = length(jsondecode(aws_ecr_repository_policy.this["iam"].policy).Statement) == 1
    error_message = "without publishers, nobody pushes through the repository policy"
  }
  assert {
    condition = alltrue([for s in jsondecode(aws_ecr_repository_policy.this["iam"].policy).Statement :
      s.Condition.StringEquals["aws:PrincipalOrgID"] == "o-abcdefghij"
      && s.Condition["ForAnyValue:StringLike"]["aws:PrincipalOrgPaths"] == ["o-abcdefghij/r-ab12/ou-ab12-instances/*"]
      && length(setintersection(s.Action, ["ecr:PutImage", "ecr:*", "ecr:DeleteRepository", "ecr:BatchDeleteImage"])) == 0
    if s.Principal.AWS == "*"])
    error_message = "'*' principals are only organization members under the named OUs, and only pull"
  }
}

run "publishers_push" {
  command = plan
  variables {
    publisher_role_arns = ["arn:aws-us-gov:iam::222222222222:role/fair-release-publisher"]
  }

  assert {
    condition = anytrue([for s in jsondecode(aws_ecr_repository_policy.this["iam"].policy).Statement :
    s.Principal.AWS == ["arn:aws-us-gov:iam::222222222222:role/fair-release-publisher"] && contains(s.Action, "ecr:PutImage") && !contains(s.Action, "ecr:BatchDeleteImage")])
    error_message = "named publishers push, never delete"
  }
}

run "whole_organization_refused" {
  command = plan
  variables {
    pull_org_paths = ["o-abcdefghij/*"]
  }
  expect_failures = [var.pull_org_paths]
}
