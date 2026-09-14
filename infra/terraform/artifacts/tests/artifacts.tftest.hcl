# Mocked AWS only; no run block here can reach AWS. The one provider configuration this root
# declares is replaced by the mock_provider below, the verification gate runs `terraform test`
# with every AWS credential removed and instance metadata disabled, and
# infra/terraform/policy/check.py refuses any test file that leaves a provider configuration
# unmocked. Every run is `command = plan`.

mock_provider "aws" {
  override_during = plan

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111111111111"
      arn        = "arn:aws:iam::111111111111:role/synthetic-operator"
      user_id    = "SYNTHETIC"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "eu-central-1"
      name   = "eu-central-1"
    }
  }

  # The bootstrap root's artifact-publish role, as this root reads it before naming it.
  mock_data "aws_iam_role" {
    defaults = {
      arn                  = "arn:aws:iam::111111111111:role/firmbatch-artifact-publish"
      permissions_boundary = "arn:aws:iam::111111111111:policy/firmbatch-artifact-publish-boundary"
      assume_role_policy   = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"GitHubOidcExactRepositoryAndEnvironment\",\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com\"},\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":{\"StringEquals\":{\"token.actions.githubusercontent.com:aud\":\"sts.amazonaws.com\",\"token.actions.githubusercontent.com:sub\":\"repo:chamsrut/firmbatch:environment:artifact-publish\"}}}]}"
    }
  }

  mock_resource "aws_ecr_repository" {
    defaults = {
      arn            = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane"
      repository_url = "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane"
      registry_id    = "111111111111"
    }
  }
}

# Synthetic values only.
variables {
  expected_account_id           = "111111111111"
  region                        = "eu-central-1"
  repository_name               = "firmbatch/control-plane"
  release_bucket_name           = "synthetic-firmbatch-releases"
  release_record_retention_days = 730
  untagged_image_expiry_days    = 7
  release_kms_key_arn           = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-0000000000e1"
  artifact_publish_role_arn     = "arn:aws:iam::111111111111:role/firmbatch-artifact-publish"
  release_reader_role_arns      = ["arn:aws:iam::111111111111:role/firmbatch-staging-github-plan", "arn:aws:iam::111111111111:role/firmbatch-staging-github-apply"]
  pull_account_ids              = ["111111111111"]
}

run "the_release_repository_is_immutable_encrypted_scanned_and_retained" {
  command = plan

  assert {
    condition     = aws_ecr_repository.release.image_tag_mutability == "IMMUTABLE" && length(aws_ecr_repository.release.image_tag_mutability_exclusion_filter) == 0
    error_message = "Every tag is immutable, with no exclusion filter: no tag is ever overwritten."
  }

  assert {
    condition     = aws_ecr_repository.release.encryption_configuration[0].encryption_type == "KMS" && aws_ecr_repository.release.encryption_configuration[0].kms_key == "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-0000000000e1"
    error_message = "Release images are encrypted under the bootstrap root's release key."
  }

  assert {
    condition     = aws_ecr_repository.release.image_scanning_configuration[0].scan_on_push == true && aws_ecr_repository.release.force_delete == false
    error_message = "Images are scanned on push, and the repository cannot be force-deleted with its images."
  }
}

run "the_lifecycle_policy_expires_untagged_manifests_only" {
  command = plan

  assert {
    condition = length(jsondecode(aws_ecr_lifecycle_policy.release.policy).rules) == 1 && alltrue([
      for rule in jsondecode(aws_ecr_lifecycle_policy.release.policy).rules :
      rule.selection.tagStatus == "untagged" && rule.action.type == "expire" && rule.selection.countNumber == 7
    ])
    error_message = "Only untagged manifests expire; every tagged release -- deployed and rollback digests included -- is retained."
  }
}

run "only_the_artifact_publish_role_pushes_and_nobody_deletes_or_retags" {
  command = plan

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_ecr_repository_policy.release.policy).Statement :
      try(
        statement.Sid == "OnlyTheArtifactPublishRolePushes" && statement.Effect == "Deny" && statement.Principal == "*" &&
        length(setsubtract(["ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload"], statement.Action)) == 0 &&
        statement.Condition.ArnNotEquals["aws:PrincipalArn"] == "arn:aws:iam::111111111111:role/firmbatch-artifact-publish",
        false
      )
    ])
    error_message = "Every principal but artifact-publish is denied every push action."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_ecr_repository_policy.release.policy).Statement :
      try(statement.Sid == "NoImageIsDeletedOrRetagged" && statement.Effect == "Deny" && statement.Principal == "*" && contains(statement.Action, "ecr:BatchDeleteImage") && contains(statement.Action, "ecr:PutImageTagMutability") && !can(statement.Condition), false)
    ])
    error_message = "No principal deletes a release image or changes tag mutability."
  }

  assert {
    condition = !anytrue([
      for statement in jsondecode(aws_ecr_repository_policy.release.policy).Statement :
      statement.Effect == "Allow" && length(setintersection(flatten([statement.Action]), ["ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:BatchDeleteImage"])) > 0
    ])
    error_message = "The repository policy grants no push or deletion to anyone."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_ecr_repository_policy.release.policy).Statement :
      try(statement.Sid == "VerifyByDigestForApprovedReaderRoles" && statement.Principal.AWS == ["arn:aws:iam::111111111111:role/firmbatch-staging-github-plan", "arn:aws:iam::111111111111:role/firmbatch-staging-github-apply"], false)
    ])
    error_message = "The plan and apply roles -- which re-verify the release before planning and before applying -- describe release images by digest."
  }
}

run "this_root_creates_no_identity_or_key_and_names_only_existing_roles" {
  command = plan

  assert {
    condition     = data.aws_iam_role.artifact_publish.arn == "arn:aws:iam::111111111111:role/firmbatch-artifact-publish" && length(data.aws_iam_role.release_readers) == 2
    error_message = "Every role the policies name is read, and so must already exist, before anything names it."
  }
}

run "release_records_are_write_once_retained_and_readable_by_reader_roles_only" {
  command = plan

  assert {
    condition     = aws_s3_bucket.releases.object_lock_enabled == true && aws_s3_bucket.releases.force_destroy == false && aws_s3_bucket_versioning.releases.versioning_configuration[0].status == "Enabled"
    error_message = "The record bucket is versioned, Object-Locked and cannot be force-destroyed."
  }

  assert {
    condition = alltrue([
      for rule in aws_s3_bucket_object_lock_configuration.releases.rule : alltrue([
        for retention in rule.default_retention : retention.mode == "GOVERNANCE" && retention.days == 730
      ])
    ])
    error_message = "Records carry GOVERNANCE retention of release_record_retention_days."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_s3_bucket_policy.releases.policy).Statement :
      try(statement.Sid == "DenyOverwriteOfAReleaseRecord" && statement.Effect == "Deny" && statement.Action == "s3:PutObject" && statement.Condition.Null["s3:if-none-match"] == "true" && length(keys(statement.Condition)) == 1, false)
    ])
    error_message = "Every principal's record write must carry If-None-Match, so no record is ever replaced."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_s3_bucket_policy.releases.policy).Statement :
      try(statement.Sid == "OnlyTheArtifactPublishRoleWritesReleaseRecords" && statement.Condition.ArnNotEquals["aws:PrincipalArn"] == "arn:aws:iam::111111111111:role/firmbatch-artifact-publish", false)
    ])
    error_message = "Only artifact-publish writes records."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_s3_bucket_policy.releases.policy).Statement :
      try(statement.Sid == "ReadReleaseRecordsForApprovedReaderRoles" && statement.Effect == "Allow" && statement.Action == ["s3:GetObject", "s3:GetObjectVersion"] && statement.Principal.AWS == ["arn:aws:iam::111111111111:role/firmbatch-staging-github-plan", "arn:aws:iam::111111111111:role/firmbatch-staging-github-apply"], false)
    ])
    error_message = "Only the named reader roles read records, by current object or exact version."
  }

  assert {
    condition = alltrue([
      for rule in aws_s3_bucket_lifecycle_configuration.releases.rule : length(rule.expiration) == 0 && length(rule.noncurrent_version_expiration) == 0
    ])
    error_message = "No release record ever expires."
  }
}

run "an_artifact_publish_role_without_its_boundary_is_never_named" {
  command = plan

  override_data {
    target = data.aws_iam_role.artifact_publish
    values = {
      arn                  = "arn:aws:iam::111111111111:role/firmbatch-artifact-publish"
      permissions_boundary = ""
      assume_role_policy   = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com\"},\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":{\"StringEquals\":{\"token.actions.githubusercontent.com:aud\":\"sts.amazonaws.com\",\"token.actions.githubusercontent.com:sub\":\"repo:chamsrut/firmbatch:environment:artifact-publish\"}}}]}"
    }
  }

  expect_failures = [data.aws_iam_role.artifact_publish]
}

run "an_artifact_publish_role_with_a_wider_trust_is_never_named" {
  command = plan

  override_data {
    target = data.aws_iam_role.artifact_publish
    values = {
      arn                  = "arn:aws:iam::111111111111:role/firmbatch-artifact-publish"
      permissions_boundary = "arn:aws:iam::111111111111:policy/firmbatch-artifact-publish-boundary"
      assume_role_policy   = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com\"},\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":{\"StringLike\":{\"token.actions.githubusercontent.com:sub\":\"repo:chamsrut/firmbatch:*\"}}}]}"
    }
  }

  expect_failures = [data.aws_iam_role.artifact_publish]
}

run "a_release_key_in_another_region_is_refused" {
  command = plan

  variables {
    release_kms_key_arn = "arn:aws:kms:eu-west-1:111111111111:key/00000000-0000-4000-8000-0000000000e1"
  }

  expect_failures = [var.release_kms_key_arn]
}

run "an_environment_named_release_repository_is_refused" {
  command = plan

  variables {
    repository_name = "firmbatch/staging-control-plane"
  }

  expect_failures = [var.repository_name]
}

run "a_wildcard_release_reader_is_refused" {
  command = plan

  variables {
    release_reader_role_arns = ["arn:aws:iam::111111111111:role/*"]
  }

  expect_failures = [var.release_reader_role_arns]
}

run "a_release_reader_in_another_account_is_refused" {
  command = plan

  variables {
    release_reader_role_arns = ["arn:aws:iam::222222222222:role/firmbatch-staging-github-plan"]
  }

  expect_failures = [var.release_reader_role_arns]
}

run "credentials_for_another_account_are_refused" {
  command = plan

  variables {
    expected_account_id       = "222222222222"
    release_kms_key_arn       = "arn:aws:kms:eu-central-1:222222222222:key/00000000-0000-4000-8000-0000000000e1"
    artifact_publish_role_arn = "arn:aws:iam::222222222222:role/firmbatch-artifact-publish"
    release_reader_role_arns  = ["arn:aws:iam::222222222222:role/firmbatch-staging-github-plan"]
  }

  # The other account's own, well-formed artifact-publish role, so the only refusal is the account.
  override_data {
    target = data.aws_iam_role.artifact_publish
    values = {
      arn                  = "arn:aws:iam::222222222222:role/firmbatch-artifact-publish"
      permissions_boundary = "arn:aws:iam::222222222222:policy/firmbatch-artifact-publish-boundary"
      assume_role_policy   = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"arn:aws:iam::222222222222:oidc-provider/token.actions.githubusercontent.com\"},\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":{\"StringEquals\":{\"token.actions.githubusercontent.com:aud\":\"sts.amazonaws.com\",\"token.actions.githubusercontent.com:sub\":\"repo:chamsrut/firmbatch:environment:artifact-publish\"}}}]}"
    }
  }

  expect_failures = [data.aws_caller_identity.current]
}
