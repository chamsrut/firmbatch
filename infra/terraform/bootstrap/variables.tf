# Every value here is a human-owned deployment parameter (ADR 0011, "Deployment parameters
# requiring human confirmation"). None has a default and no valued tfvars file is committed;
# see bootstrap.tfvars.example.

variable "expected_account_id" {
  description = "The dedicated staging AWS account ID, confirmed by a human before the first plan."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be a twelve-digit AWS account ID."
  }
}

variable "region" {
  description = "The staging workload region, which is also the release registry's. eu-central-1 is recommended and is confirmed immediately before planning."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.region)) && var.region != "us-east-1"
    error_message = "region must be an AWS region name such as eu-central-1; us-east-1 is reserved for the Cognito custom-domain certificate."
  }
}

variable "environment" {
  description = "The environment these buckets and delivery identities serve. Production is a separate root, account and state (environments/production/README.md)."
  type        = string
  nullable    = false

  validation {
    condition     = var.environment == "staging"
    error_message = "This bootstrap root serves the staging environment only."
  }
}

variable "name_prefix" {
  description = "The staging root's name_prefix, for example firmbatch-staging. The delivery identities are named from it, and the staging root must use exactly the same value."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,22}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 4-24 lowercase letters, digits or hyphens, starting with a letter, as the staging root requires."
  }
}

variable "release_name_prefix" {
  description = "Environment-neutral prefix of the release identity and key, for example firmbatch: the artifact-publish role, its boundary and the release key alias."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}[a-z0-9]$", var.release_name_prefix)) && !can(regex("(^|-)(staging|production|prod|dev|test)($|-)", var.release_name_prefix))
    error_message = "release_name_prefix must be 4-32 lowercase letters, digits or hyphens, and name no environment: one registry serves every environment."
  }
}

variable "state_bucket_name" {
  description = "Globally unique name of the Terraform state bucket."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.state_bucket_name))
    error_message = "state_bucket_name must be a valid S3 bucket name of lowercase letters, digits and hyphens."
  }
}

variable "plan_bucket_name" {
  description = "Globally unique name of the saved-plan bucket. Never the state bucket."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.plan_bucket_name))
    error_message = "plan_bucket_name must be a valid S3 bucket name of lowercase letters, digits and hyphens."
  }

  validation {
    condition     = var.plan_bucket_name != var.state_bucket_name
    error_message = "Saved plans and Terraform state must never share a bucket (ADR 0011 decision 8)."
  }
}

variable "plan_retention_days" {
  description = "Object Lock governance retention, and lifecycle expiry, of saved plans, in whole days. It is the saved-plan lifetime, a human-confirmed parameter: one day is recommended."
  type        = number
  nullable    = false

  validation {
    condition     = var.plan_retention_days >= 1 && var.plan_retention_days <= 7 && floor(var.plan_retention_days) == var.plan_retention_days
    error_message = "plan_retention_days must be a whole number of days from 1 to 7; one day is recommended."
  }
}

variable "state_noncurrent_version_retention_days" {
  description = "Days a superseded state version is kept before lifecycle removes it. Current state is never expired."
  type        = number
  nullable    = false

  validation {
    condition     = var.state_noncurrent_version_retention_days >= 30 && var.state_noncurrent_version_retention_days <= 365 && floor(var.state_noncurrent_version_retention_days) == var.state_noncurrent_version_retention_days
    error_message = "state_noncurrent_version_retention_days must be a whole number of days from 30 to 365."
  }
}

# ------------------------------------------------------------------ what the delivery identities may reach

# The canonical artifact registry is DECLARED, never derived from the staging account or region: every
# release ARN these identities name is built from these values, and the artifacts root, the staging
# root's release_registry_* inputs, the workflows' ARTIFACT_REGISTRY_* variables and every release
# record must name the same ones.
variable "artifact_registry_account_id" {
  description = "The account holding the canonical release repository and release-record bucket, declared by a human. It equals expected_account_id only because this root creates the artifact-publish identity and the release key, which must live beside the registry."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.artifact_registry_account_id))
    error_message = "artifact_registry_account_id must be a twelve-digit AWS account ID."
  }

  validation {
    condition     = var.artifact_registry_account_id == var.expected_account_id
    error_message = "This root creates the artifact-publish identity and the release key, which must live in the registry account: a registry declared in another account needs that account's own publisher bootstrap first, a reviewed change to this root."
  }
}

variable "artifact_registry_region" {
  description = "The region of the canonical release repository and release-record bucket, declared by a human. It equals region only because this root creates the release key, which ECR and S3 need in the registry's region."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.artifact_registry_region))
    error_message = "artifact_registry_region must be an AWS region name such as eu-central-1."
  }

  validation {
    condition     = var.artifact_registry_region == var.region
    error_message = "This root creates the release key, which must be in the registry's region: a registry declared in another region needs its own key and a reviewed change to this root and to the apply boundary's region denies."
  }
}

variable "release_repository_name" {
  description = "The canonical release repository the artifacts root creates in the declared artifact registry, for example firmbatch/control-plane. The identities are written against its predictable ARN before it exists."
  type        = string
  nullable    = false

  validation {
    condition     = length(var.release_repository_name) <= 200 && can(regex("^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$", var.release_repository_name))
    error_message = "release_repository_name must be a valid ECR repository name."
  }

  validation {
    condition     = !can(regex("(^|[/_.-])(staging|production|prod|dev|test)($|[/_.-])", var.release_repository_name))
    error_message = "The release repository is environment-neutral; an environment name in it invites environment-specific builds."
  }
}

variable "release_bucket_name" {
  description = "Globally unique name of the release-record bucket the artifacts root creates in this account and region."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.release_bucket_name))
    error_message = "release_bucket_name must be a valid S3 bucket name of lowercase letters, digits and hyphens."
  }

  validation {
    condition     = !contains([var.state_bucket_name, var.plan_bucket_name], var.release_bucket_name)
    error_message = "Release records never share a bucket with state or saved plans."
  }
}

variable "route53_zone_id" {
  description = "The one hosted zone the apply role may change records in; the staging root's route53_zone_id."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^Z[A-Z0-9]{1,32}$", var.route53_zone_id))
    error_message = "route53_zone_id must be a Route 53 hosted zone ID."
  }
}

variable "rds_instance_class" {
  description = "The one reviewed RDS instance class; the apply boundary refuses creating or resizing to any other. The staging root's rds_instance_class."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^db\\.[a-z0-9]+\\.[a-z0-9]+$", var.rds_instance_class))
    error_message = "rds_instance_class must be an RDS instance class such as db.t4g.micro."
  }
}
