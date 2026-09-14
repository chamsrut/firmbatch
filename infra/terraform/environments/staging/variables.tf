# Human-owned deployment parameters (ADR 0011, "Deployment parameters requiring human
# confirmation"). No default stands in for a human decision, and no valued tfvars file is ever
# committed: see staging.tfvars.example. Reviewer CIDRs are supplied at plan time from
# protected configuration outside the repository.

# ------------------------------------------------------------------ account and region

variable "expected_account_id" {
  description = "The dedicated staging AWS account ID."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be a twelve-digit AWS account ID."
  }
}

variable "region" {
  description = "The staging workload region; eu-central-1 is recommended and confirmed immediately before planning."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.region)) && var.region != "us-east-1"
    error_message = "region must be an AWS region name; us-east-1 is reserved for the Cognito custom-domain certificate alias."
  }
}

variable "environment" {
  type     = string
  nullable = false

  validation {
    condition     = var.environment == "staging"
    error_message = "This root is the staging environment only; production is a separate root, account and state."
  }
}

variable "name_prefix" {
  type     = string
  nullable = false

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,22}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 4-24 lowercase letters, digits or hyphens (ALB and target-group names are limited to 32 characters)."
  }
}

# ------------------------------------------------------------------ bootstrap outputs

variable "state_bucket_name" {
  type     = string
  nullable = false
}

variable "state_kms_key_arn" {
  type     = string
  nullable = false

  validation {
    condition     = can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}$", var.state_kms_key_arn))
    error_message = "state_kms_key_arn must be a KMS key ARN."
  }
}

variable "plan_bucket_name" {
  type     = string
  nullable = false

  validation {
    condition     = var.plan_bucket_name != var.state_bucket_name
    error_message = "Saved plans and state never share a bucket."
  }
}

variable "plan_kms_key_arn" {
  type     = string
  nullable = false

  validation {
    condition     = can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}$", var.plan_kms_key_arn))
    error_message = "plan_kms_key_arn must be a KMS key ARN."
  }
}

# ------------------------------------------------------------------ release registry (artifacts root outputs)

variable "release_registry_account_id" {
  description = "The account holding the canonical release repository, as the bootstrap root's artifact_registry output declares it. Never derived from expected_account_id: it equals the staging account only when a human declared the registry there, and a dedicated artifact account needs no change here."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.release_registry_account_id))
    error_message = "release_registry_account_id must be a twelve-digit AWS account ID."
  }
}

variable "release_registry_region" {
  type     = string
  nullable = false

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.release_registry_region))
    error_message = "release_registry_region must be an AWS region name."
  }
}

variable "release_repository_name" {
  description = "The canonical release repository, for example firmbatch/control-plane."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$", var.release_repository_name))
    error_message = "release_repository_name must be a valid ECR repository name."
  }
}

# ------------------------------------------------------------------ domains

variable "route53_zone_id" {
  type     = string
  nullable = false

  validation {
    condition     = can(regex("^Z[A-Z0-9]{1,32}$", var.route53_zone_id))
    error_message = "route53_zone_id must be a Route 53 hosted zone ID."
  }
}

variable "app_hostname" {
  description = "The one customer origin's host (proposed staging.app.firmbatch.com)."
  type        = string
  nullable    = false
}

variable "auth_hostname" {
  description = "The Cognito Managed Login custom domain (proposed auth.staging.app.firmbatch.com)."
  type        = string
  nullable    = false

  validation {
    condition     = var.auth_hostname != var.app_hostname
    error_message = "The authentication host is not the customer origin."
  }
}

# ------------------------------------------------------------------ network

variable "vpc_cidr" {
  type     = string
  nullable = false
}

variable "availability_zones" {
  type     = list(string)
  nullable = false
}

variable "public_subnet_cidrs" {
  type     = list(string)
  nullable = false
}

variable "private_subnet_cidrs" {
  type     = list(string)
  nullable = false
}

variable "database_subnet_cidrs" {
  type     = list(string)
  nullable = false
}

variable "reviewer_cidrs" {
  description = "The human-reviewed reviewer allow-list for ALB ports 443 and 80, also admitted by the Cognito WAF. Validated by the edge module and by infra/terraform/policy/cidr_allowlist.py. Never committed."
  type        = list(string)
  nullable    = false
}

variable "reviewer_address_space_limit" {
  description = "Maximum total address space of reviewer_cidrs: IPv4 addresses and IPv6 /64 networks."
  type = object({
    ipv4_addresses        = number
    ipv6_slash64_networks = number
  })
  nullable = false
}

# ------------------------------------------------------------------ runtime contract

variable "runtime_contract_reviewed" {
  description = "Set true only after M3.3c's broker, bootstrap and identity-binding programs, dependencies and image have passed review. False keeps every task definition and service from planning."
  type        = bool
  nullable    = false
}

variable "release_image" {
  description = "The verified release image, <release repository>@sha256:<64 hex>. In the pipeline it is written from the release record staging-plan verified, never from environment configuration."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$", var.release_image))
    error_message = "release_image must be a full digest-qualified reference, <repository>@sha256:<64 lowercase hex>; any tag is refused."
  }

  validation {
    condition     = startswith(var.release_image, "${var.release_registry_account_id}.dkr.ecr.${var.release_registry_region}.amazonaws.com/${var.release_repository_name}@sha256:")
    error_message = "release_image must come from the canonical release repository named by release_registry_account_id, release_registry_region and release_repository_name."
  }
}

variable "commands" {
  description = "Container command per task. The broker, bootstrap and identity-binding commands are M3.3c's."
  type = object({
    web_api          = list(string)
    identity_broker  = list(string)
    migrate          = list(string)
    bootstrap        = list(string)
    identity_binding = list(string)
  })
  nullable = false
}

variable "task_sizes" {
  type = map(object({
    cpu    = number
    memory = number
  }))
  nullable = false
}

variable "desired_counts" {
  type = object({
    web_api         = number
    identity_broker = number
  })
  nullable = false
}

variable "firmbatch_env" {
  description = "FIRMBATCH_ENV for every container; the staging configuration mode is M3.3c's."
  type        = string
  nullable    = false
}

variable "identity_broker_health_check_path" {
  description = "The broker's health route under /auth/ (M3.3c)."
  type        = string
  nullable    = false
}

# ------------------------------------------------------------------ database

variable "postgres_engine_version" {
  description = "The exact supported PostgreSQL 16 minor, checked immediately before deployment."
  type        = string
  nullable    = false
}

variable "rds_instance_class" {
  type     = string
  nullable = false
}

variable "rds_allocated_storage_gib" {
  type     = number
  nullable = false
}

variable "rds_max_allocated_storage_gib" {
  type     = number
  nullable = false
}

# ------------------------------------------------------------------ identity

variable "cognito_ses_identity_arn" {
  type     = string
  nullable = false
}

variable "cognito_from_email_address" {
  type     = string
  nullable = false
}

# ------------------------------------------------------------------ observability

variable "log_retention_days" {
  type     = number
  nullable = false
}

variable "alert_email" {
  type      = string
  nullable  = false
  sensitive = true
}

variable "budget_limit_usd" {
  description = "Monthly budget alert amount. AWS Budgets alerts; it is not a spending cap."
  type        = string
  nullable    = false
}

variable "budget_alert_threshold_percent" {
  type     = number
  nullable = false
}
