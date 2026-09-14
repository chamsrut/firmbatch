# The saved-plan bucket (ADR 0011 decisions 9.2 and 9.3). Separate from state in purpose,
# key and access policy: versioned, customer-managed KMS, public access blocked, TLS only,
# S3 Object Lock in GOVERNANCE mode with a short default retention, and lifecycle expiry of
# current versions, noncurrent versions and delete markers -- under plans/ only.
#
# Deleting a current object in a versioned bucket only adds a delete marker; it does not
# remove the plan. Refused or expired plans are left to lifecycle expiry.

resource "aws_s3_bucket" "plans" {
  bucket              = var.plan_bucket_name
  force_destroy       = false
  object_lock_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "plans" {
  bucket = aws_s3_bucket.plans.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "plans" {
  bucket                  = aws_s3_bucket.plans.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "plans" {
  bucket = aws_s3_bucket.plans.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "plans" {
  bucket = aws_s3_bucket.plans.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.plans.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "plans" {
  bucket = aws_s3_bucket.plans.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.plan_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.plans]
}

resource "aws_s3_bucket_lifecycle_configuration" "plans" {
  bucket = aws_s3_bucket.plans.id

  rule {
    id     = "expire-saved-plan-versions"
    status = "Enabled"

    filter {
      prefix = local.plan_object_prefix
    }

    # A current plan version becomes noncurrent after the saved-plan lifetime, and a
    # noncurrent version is removed once its Object Lock retention has also passed.
    expiration {
      days = var.plan_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.plan_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  rule {
    id     = "expire-saved-plan-delete-markers"
    status = "Enabled"

    filter {
      prefix = local.plan_object_prefix
    }

    expiration {
      expired_object_delete_marker = true
    }
  }

  depends_on = [aws_s3_bucket_versioning.plans]
}

resource "aws_s3_bucket_policy" "plans" {
  bucket = aws_s3_bucket.plans.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      local.deny_insecure_transport.plans,
      {
        Sid       = "DenyTlsOlderThan12"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [local.plan_bucket_arn, "${local.plan_bucket_arn}/*"]
        Condition = { NumericLessThan = { "s3:TlsVersion" = "1.2" } }
      },
      {
        Sid       = "DenyPlanBucketDeletion"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:DeleteBucket"
        Resource  = local.plan_bucket_arn
      },
      {
        Sid         = "DenyObjectsOutsidePlanPrefix"
        Effect      = "Deny"
        Principal   = "*"
        Action      = "s3:PutObject"
        NotResource = "${local.plan_bucket_arn}/${local.plan_object_prefix}*"
      },
      {
        Sid       = "DenyObjectsEncryptedUnderAnotherKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${local.plan_bucket_arn}/*"
        Condition = {
          StringNotEqualsIfExists = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.plans.arn
          }
        }
      },
      {
        # Neither pipeline role can shorten, lift or bypass retention, remove a version, change
        # the bucket's rules, or enumerate historical versions.
        Sid       = "DenyRetentionBypassByPipelineRoles"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:BypassGovernanceRetention",
          "s3:PutObjectRetention",
          "s3:PutObjectLegalHold",
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:ListBucketVersions",
          "s3:PutBucketObjectLockConfiguration",
          "s3:PutLifecycleConfiguration",
          "s3:PutBucketVersioning",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketPublicAccessBlock",
        ]
        Resource  = [local.plan_bucket_arn, "${local.plan_bucket_arn}/*"]
        Condition = { ArnLike = { "aws:PrincipalArn" = local.github_role_arn_pattern } }
      },
      {
        # Conditional-write enforcement: a pipeline role's PutObject must carry
        # If-None-Match: *, so it can only create a key that does not already exist and can
        # never lay a new current version over an approved plan.
        Sid       = "DenyOverwriteByPipelineRoles"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${local.plan_bucket_arn}/*"
        Condition = {
          ArnLike = { "aws:PrincipalArn" = local.github_role_arn_pattern }
          Null    = { "s3:if-none-match" = "true" }
        }
      },
      {
        Sid       = "DenyPlanReadsByPlanRole"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:GetObjectAttributes",
          "s3:GetObjectVersionAttributes",
          "s3:GetObjectRetention",
        ]
        Resource  = "${local.plan_bucket_arn}/*"
        Condition = { ArnEquals = { "aws:PrincipalArn" = local.github_plan_role_arn } }
      },
      {
        # Only the exact plan role creates saved plans. Every other principal -- the apply and
        # artifact-publish roles, any other staging role, an operator -- is denied, so an approved
        # plan's bucket holds nothing the plan job did not write.
        Sid       = "OnlyThePlanRoleCreatesSavedPlans"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${local.plan_bucket_arn}/*"
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = local.github_plan_role_arn } }
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.plans]
}
