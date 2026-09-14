# The canonical release registry (ADR 0012 decision 13): build once, promote by digest.
#
# HUMAN-APPLIED, and applied SECOND. The bootstrap root has already created the release key and every
# delivery identity -- artifact-publish and the staging plan and apply roles -- so the repository and
# record-bucket policies here name principals that exist; publish_role.tf refuses to plan otherwise.
# The repository, its lifecycle and repository policies and the release-record bucket are trust
# configuration: whoever changes them decides which images can ever reach an environment. So a
# human creates and changes them with short-lived AWS SSO/MFA credentials, and no GitHub workflow
# plans or applies this root.
#
# Each guarantee, and where it lives:
#   * one build per approved commit, tagged git-<full commit>: .github/workflows/artifact-publish.yml;
#   * no tag is ever overwritten: IMMUTABLE tags with no exclusion filter;
#   * only artifact-publish pushes: the repository policy below, and the staging plan and apply
#     roles' own policies and boundary, which deny every push;
#   * no deployed or rollback digest expires: the lifecycle policy expires untagged manifests only,
#     and the repository policy denies image deletion to every principal;
#   * the digest, not the tag, deploys: the release record binds tag to digest, and staging-plan and
#     staging-apply resolve the image by digest only.
#
# Replication is deliberately not configured. A later production account or region receives images
# through explicitly created destination repositories and policies, and deploys only after
# `delivery.py verify-destination-digest` has proven the destination digest equals the record's.

locals {
  account_id = data.aws_caller_identity.current.account_id

  publish_role_arn = var.artifact_publish_role_arn

  repository_arn     = "arn:aws:ecr:${var.region}:${local.account_id}:repository/${var.repository_name}"
  release_bucket_arn = "arn:aws:s3:::${var.release_bucket_name}"

  # Release records live under this prefix only:
  #   releases/<40-hex commit>/release-manifest.json
  #   releases/<40-hex commit>/sbom-<64-hex image configuration digest>.spdx.json
  release_object_prefix = "releases/"

  # The pipeline identities, by name: every environment's GitHub plan and apply roles, and the one
  # publisher. None of them may reconfigure the registry or its records.
  pipeline_role_arn_patterns = [
    "arn:aws:iam::*:role/*-github-plan",
    "arn:aws:iam::*:role/*-github-apply",
    local.publish_role_arn,
  ]
}

# ------------------------------------------------------------------------------ repository

resource "aws_ecr_repository" "release" {
  name                 = var.repository_name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  # No image_tag_mutability_exclusion_filter: every tag, git-<commit> included, is immutable.

  image_scanning_configuration {
    scan_on_push = true
  }

  # ECR takes a grant on the bootstrap root's release key when the repository is created, and
  # encrypts and decrypts every layer under it: neither artifact-publish nor a pulling execution
  # role needs a key permission of its own.
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.release_kms_key_arn
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Untagged manifests only -- the remnants of an interrupted push. Every tagged release image, and
# so every deployed and rollback digest, is retained; pruning an old release is a later, reviewed,
# human operation that first confirms no environment runs or could roll back to it.
resource "aws_ecr_lifecycle_policy" "release" {
  repository = aws_ecr_repository.release.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Expire untagged manifests only; tagged release images never expire."
      selection = {
        tagStatus   = "untagged"
        countType   = "sinceImagePushed"
        countUnit   = "days"
        countNumber = var.untagged_image_expiry_days
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_ecr_repository_policy" "release" {
  repository = aws_ecr_repository.release.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PullForApprovedWorkloadAccounts"
        Effect    = "Allow"
        Principal = { AWS = [for account in var.pull_account_ids : "arn:aws:iam::${account}:root"] }
        Action    = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
      },
      {
        Sid       = "VerifyByDigestForApprovedReaderRoles"
        Effect    = "Allow"
        Principal = { AWS = var.release_reader_role_arns }
        Action    = ["ecr:DescribeImages", "ecr:DescribeImageScanFindings", "ecr:DescribeRepositories"]
      },
      {
        Sid       = "OnlyTheArtifactPublishRolePushes"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage"]
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = local.publish_role_arn } }
      },
      {
        # Nobody deletes or re-tags a release image. Pruning first changes this policy, in a
        # reviewed human apply of this root.
        Sid       = "NoImageIsDeletedOrRetagged"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["ecr:BatchDeleteImage", "ecr:PutImageTagMutability"]
      },
      {
        Sid       = "NoPipelineRoleReconfiguresTheRepository"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "ecr:SetRepositoryPolicy", "ecr:DeleteRepositoryPolicy", "ecr:PutLifecyclePolicy", "ecr:DeleteLifecyclePolicy",
          "ecr:PutImageScanningConfiguration", "ecr:DeleteRepository", "ecr:StartLifecyclePolicyPreview",
        ]
        Condition = { ArnLike = { "aws:PrincipalArn" = local.pipeline_role_arn_patterns } }
      },
    ]
  })

  # The principals named above must already exist (publish_role.tf).
  depends_on = [data.aws_iam_role.artifact_publish, data.aws_iam_role.release_readers]
}
