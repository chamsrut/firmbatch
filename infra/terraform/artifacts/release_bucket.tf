# The release-record bucket (ADR 0012 decision 13). One release record and its SBOM per published
# commit, created once by artifact-publish and never overwritten or deleted: versioned, the bootstrap
# root's release key, public access blocked, TLS only, and S3 Object Lock in GOVERNANCE mode for at
# least a year. No record holds a credential, a Terraform plan or environment configuration.

resource "aws_s3_bucket" "releases" {
  bucket              = var.release_bucket_name
  force_destroy       = false
  object_lock_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "releases" {
  bucket = aws_s3_bucket.releases.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "releases" {
  bucket                  = aws_s3_bucket.releases.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "releases" {
  bucket = aws_s3_bucket.releases.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "releases" {
  bucket = aws_s3_bucket.releases.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.release_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "releases" {
  bucket = aws_s3_bucket.releases.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.release_record_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.releases]
}

# Records never expire. The only lifecycle rule removes incomplete multipart uploads.
resource "aws_s3_bucket_lifecycle_configuration" "releases" {
  bucket = aws_s3_bucket.releases.id

  rule {
    id     = "abort-incomplete-release-record-uploads"
    status = "Enabled"

    filter {
      prefix = local.release_object_prefix
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.releases]
}

resource "aws_s3_bucket_policy" "releases" {
  bucket = aws_s3_bucket.releases.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [local.release_bucket_arn, "${local.release_bucket_arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyTlsOlderThan12"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [local.release_bucket_arn, "${local.release_bucket_arn}/*"]
        Condition = { NumericLessThan = { "s3:TlsVersion" = "1.2" } }
      },
      {
        Sid       = "DenyReleaseBucketDeletion"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:DeleteBucket"
        Resource  = local.release_bucket_arn
      },
      {
        Sid         = "DenyObjectsOutsideReleasePrefix"
        Effect      = "Deny"
        Principal   = "*"
        Action      = "s3:PutObject"
        NotResource = "${local.release_bucket_arn}/${local.release_object_prefix}*"
      },
      {
        Sid       = "DenyObjectsEncryptedUnderAnotherKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${local.release_bucket_arn}/*"
        Condition = {
          StringNotEqualsIfExists = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = var.release_kms_key_arn
          }
        }
      },
      {
        Sid       = "OnlyTheArtifactPublishRoleWritesReleaseRecords"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${local.release_bucket_arn}/*"
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = local.publish_role_arn } }
      },
      {
        # Conditional-write enforcement for every principal: a record is created with
        # If-None-Match: * or not at all, so no release record is ever replaced.
        Sid       = "DenyOverwriteOfAReleaseRecord"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${local.release_bucket_arn}/*"
        Condition = { Null = { "s3:if-none-match" = "true" } }
      },
      {
        Sid       = "DenyRecordDeletionRetentionBypassAndBucketChangesByPipelineRoles"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:BypassGovernanceRetention",
          "s3:PutObjectRetention",
          "s3:PutObjectLegalHold",
          "s3:PutBucketObjectLockConfiguration",
          "s3:PutLifecycleConfiguration",
          "s3:PutBucketVersioning",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketPublicAccessBlock",
        ]
        Resource  = [local.release_bucket_arn, "${local.release_bucket_arn}/*"]
        Condition = { ArnLike = { "aws:PrincipalArn" = local.pipeline_role_arn_patterns } }
      },
      {
        # The plan role reads the current record; the apply role reads the exact record version the
        # approved plan names.
        Sid       = "ReadReleaseRecordsForApprovedReaderRoles"
        Effect    = "Allow"
        Principal = { AWS = var.release_reader_role_arns }
        Action    = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource  = "${local.release_bucket_arn}/${local.release_object_prefix}*"
      },
    ]
  })

  # The principals named above must already exist (publish_role.tf).
  depends_on = [aws_s3_bucket_public_access_block.releases, data.aws_iam_role.artifact_publish, data.aws_iam_role.release_readers]
}
