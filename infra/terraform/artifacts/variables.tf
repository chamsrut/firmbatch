# Every value here is a human-owned parameter. None has a default and no valued tfvars file is
# committed; see artifacts.tfvars.example.

variable "expected_account_id" {
  description = "The canonical registry account, exactly as the bootstrap root's artifact_registry output declares it -- never assumed to be the staging account. A later dedicated artifact account changes nothing in the deployment contract, which names images by full reference and digest."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be a twelve-digit AWS account ID."
  }
}

variable "region" {
  description = "The registry region: the bootstrap root's region, where the release key is."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.region))
    error_message = "region must be an AWS region name such as eu-central-1."
  }
}

variable "repository_name" {
  description = "The canonical release repository, for example firmbatch/control-plane: the bootstrap root's release_repository_name. Environment-neutral: staging and, later, production promote the same digests from it."
  type        = string
  nullable    = false

  validation {
    condition     = length(var.repository_name) <= 200 && can(regex("^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$", var.repository_name))
    error_message = "repository_name must be a valid ECR repository name."
  }

  validation {
    condition     = !can(regex("(^|[/_.-])(staging|production|prod|dev|test)($|[/_.-])", var.repository_name))
    error_message = "The release repository is environment-neutral; an environment name in it invites environment-specific builds."
  }
}

variable "release_bucket_name" {
  description = "Globally unique name of the release-record bucket: the bootstrap root's release_bucket_name."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.release_bucket_name))
    error_message = "release_bucket_name must be a valid S3 bucket name of lowercase letters, digits and hyphens."
  }
}

variable "release_record_retention_days" {
  description = "Object Lock GOVERNANCE retention of every release record, in whole days. A record must outlive every deployment that could roll back to its digest."
  type        = number
  nullable    = false

  validation {
    condition     = var.release_record_retention_days >= 365 && var.release_record_retention_days <= 3650 && floor(var.release_record_retention_days) == var.release_record_retention_days
    error_message = "release_record_retention_days must be a whole number of days from 365 to 3650."
  }
}

variable "untagged_image_expiry_days" {
  description = "Days before an untagged manifest -- the remnant of an interrupted push -- expires. Tagged release images never expire."
  type        = number
  nullable    = false

  validation {
    condition     = var.untagged_image_expiry_days >= 1 && var.untagged_image_expiry_days <= 30 && floor(var.untagged_image_expiry_days) == var.untagged_image_expiry_days
    error_message = "untagged_image_expiry_days must be a whole number of days from 1 to 30."
  }
}

variable "release_kms_key_arn" {
  description = "The release key, from the bootstrap root's outputs. It must be in this account and region: S3 encrypts records only under a key in the bucket's region."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}$", var.release_kms_key_arn))
    error_message = "release_kms_key_arn must be a KMS key ARN."
  }

  validation {
    condition     = try(split(":", var.release_kms_key_arn)[3], "") == var.region && try(split(":", var.release_kms_key_arn)[4], "") == var.expected_account_id
    error_message = "The release key must be in the registry account and region."
  }
}

variable "artifact_publish_role_arn" {
  description = "The artifact-publish role, from the bootstrap root's outputs. It must already exist; this root names it and never creates it."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/[a-z][a-z0-9-]*-artifact-publish$", var.artifact_publish_role_arn))
    error_message = "artifact_publish_role_arn must be an exact <prefix>-artifact-publish role ARN, with no wildcard."
  }

  validation {
    condition     = try(split(":", var.artifact_publish_role_arn)[4], "") == var.expected_account_id
    error_message = "artifact-publish must be in the registry account."
  }
}

variable "release_reader_role_arns" {
  description = "The roles that verify a release before promoting or applying it -- the staging plan and apply roles today, from the bootstrap root's outputs. They may describe release images by digest and read release records, and nothing else."
  type        = list(string)
  nullable    = false

  validation {
    condition = length(var.release_reader_role_arns) > 0 && alltrue([
      for arn in var.release_reader_role_arns : can(regex("^arn:aws:iam::[0-9]{12}:role/[a-z][a-z0-9-]*-github-(plan|apply)$", arn))
    ])
    error_message = "release_reader_role_arns must name at least one exact GitHub plan or apply role ARN, with no wildcard."
  }

  validation {
    condition     = alltrue([for arn in var.release_reader_role_arns : try(split(":", arn)[4], "") == var.expected_account_id])
    error_message = "Each release reader must already exist in the registry account; a reader in another account needs a reviewed key-policy and resource-policy change first."
  }
}

variable "pull_account_ids" {
  description = "The workload accounts whose pre-created ECS execution roles pull release images -- the staging account today."
  type        = list(string)
  nullable    = false

  validation {
    condition     = length(var.pull_account_ids) > 0 && alltrue([for id in var.pull_account_ids : can(regex("^[0-9]{12}$", id))])
    error_message = "pull_account_ids must list at least one twelve-digit account ID."
  }
}
