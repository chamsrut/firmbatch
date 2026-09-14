# Secrets Manager CONTAINERS and the KMS keys (ADR 0011 decision 7; topology §7).
#
# No aws_secretsmanager_secret_version exists anywhere in this repository. Terraform creates
# each container with no value; the database URLs are written by the one-off bootstrap task
# (M3.3c) and so never enter Terraform state or a saved plan. Who writes the Cognito client
# secret into its container is M3.3c's to decide -- this module only creates the container.

variable "name_prefix" {
  type     = string
  nullable = false
}

variable "account_id" {
  type     = string
  nullable = false
}

variable "region" {
  type     = string
  nullable = false
}

locals {
  runtime_secrets = {
    application_database_url      = "the application role's database URL (web/API service)"
    authenticator_database_url    = "the authenticator role's database URL (identity broker only)"
    identity_binding_database_url = "the identity-binding login role's database URL (identity-binding task only)"
    migration_database_url        = "the migration (schema-owner) role's database URL (migrate task only)"
    cognito_client_secret         = "the Cognito app client's secret (identity broker only)"
  }
}

# Secrets, the RDS storage and master secret, and the application log groups.
resource "aws_kms_key" "workload" {
  description             = "${var.name_prefix} runtime secrets, RDS storage and application logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministrationThroughIam"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchLogsForThisEnvironmentOnly"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.region}:${var.account_id}:log-group:/ecs/${var.name_prefix}/*"
          }
        }
      },
    ]
  })
}

resource "aws_kms_alias" "workload" {
  name          = "alias/${var.name_prefix}-workload"
  target_key_id = aws_kms_key.workload.key_id
}

# Cognito refresh tokens, encrypted server-side by the identity broker alone, under an
# encryption context naming the session and account (ADR 0011 decision 5). The grant is the
# compute module's broker task-role policy; the key policy names no workload principal.
resource "aws_kms_key" "refresh_token" {
  description             = "${var.name_prefix} Cognito refresh tokens; identity broker only, under an encryption-context condition"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountAdministrationThroughIam"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

resource "aws_kms_alias" "refresh_token" {
  name          = "alias/${var.name_prefix}-refresh-token"
  target_key_id = aws_kms_key.refresh_token.key_id
}

resource "aws_secretsmanager_secret" "runtime" {
  for_each = local.runtime_secrets

  name                    = "${var.name_prefix}/${replace(each.key, "_", "-")}"
  description             = "Container only, for ${each.value}. Its value is never written by Terraform."
  kms_key_id              = aws_kms_key.workload.arn
  recovery_window_in_days = 30
}

output "workload_kms_key_arn" {
  value = aws_kms_key.workload.arn
}

output "refresh_token_kms_key_arn" {
  value = aws_kms_key.refresh_token.arn
}

output "secret_arns" {
  description = "Secret container ARNs keyed application_database_url, authenticator_database_url, identity_binding_database_url, migration_database_url, cognito_client_secret."
  value       = { for key, secret in aws_secretsmanager_secret.runtime : key => secret.arn }
}
