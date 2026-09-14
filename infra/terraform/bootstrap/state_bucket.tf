# The Terraform state bucket. Versioned, customer-managed KMS, public access blocked, TLS
# only, with the native S3 lockfile (use_lockfile) rather than a DynamoDB table.
#
# It never holds saved plans and no lifecycle rule here expires a current object: superseded
# state versions are kept for state_noncurrent_version_retention_days, and at least the thirty
# newest are kept regardless.

resource "aws_s3_bucket" "state" {
  bucket              = var.state_bucket_name
  force_destroy       = false
  object_lock_enabled = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "retain-superseded-state-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days           = var.state_noncurrent_version_retention_days
      newer_noncurrent_versions = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.state]
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      local.deny_insecure_transport.state,
      {
        Sid       = "DenyTlsOlderThan12"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [local.state_bucket_arn, "${local.state_bucket_arn}/*"]
        Condition = { NumericLessThan = { "s3:TlsVersion" = "1.2" } }
      },
      {
        Sid       = "DenyStateBucketDeletion"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:DeleteBucket"
        Resource  = local.state_bucket_arn
      },
      {
        Sid       = "DenyObjectsEncryptedUnderAnotherKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${local.state_bucket_arn}/*"
        Condition = {
          StringNotEqualsIfExists = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.state.arn
          }
        }
      },
      {
        # The pipeline roles may read and write their own state key (IAM grants that); they may
        # never delete a state version or change how the bucket keeps them.
        Sid       = "DenyStateHistoryTamperingByPipelineRoles"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:DeleteObjectVersion",
          "s3:PutLifecycleConfiguration",
          "s3:PutBucketVersioning",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketPublicAccessBlock",
        ]
        Resource  = [local.state_bucket_arn, "${local.state_bucket_arn}/*"]
        Condition = { ArnLike = { "aws:PrincipalArn" = local.github_role_arn_pattern } }
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.state]
}
