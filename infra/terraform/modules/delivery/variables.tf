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

variable "state_bucket_name" {
  type     = string
  nullable = false
}

variable "state_kms_key_arn" {
  type     = string
  nullable = false
}

variable "plan_bucket_name" {
  type     = string
  nullable = false
}

variable "plan_kms_key_arn" {
  type     = string
  nullable = false
}

variable "cluster_name" {
  type     = string
  nullable = false
}

variable "release_registry_account_id" {
  description = "The account holding the canonical release repository (the artifacts root)."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.release_registry_account_id))
    error_message = "release_registry_account_id must be a twelve-digit account ID."
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
  type     = string
  nullable = false

  validation {
    condition     = can(regex("^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$", var.release_repository_name))
    error_message = "release_repository_name must be a valid ECR repository name."
  }
}
