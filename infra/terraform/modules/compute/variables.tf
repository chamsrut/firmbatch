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

variable "cluster_name" {
  type     = string
  nullable = false
}

variable "service_names" {
  description = "ECS service names keyed web_api and identity_broker."
  type        = map(string)
  nullable    = false
}

variable "runtime_contract_reviewed" {
  description = "True only once M3.3c's broker, bootstrap and identity-binding programs, their dependencies and the image have passed review. Until then no task definition or service can be planned: M3.3b's templates are not operational."
  type        = bool
  nullable    = false
}

variable "approved_image_repository_url" {
  description = "The canonical release repository in the artifacts root, with no tag and no digest. Every image must come from it."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9][a-z0-9._/-]*$", var.approved_image_repository_url))
    error_message = "approved_image_repository_url must be an ECR repository URL with no tag or digest."
  }
}

variable "image" {
  description = "The one verified release image every service and one-off task runs, as <approved repository>@sha256:<64 hex>, from the release record staging-plan verified. A tag, a tag with a digest, or another repository is refused."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9]{12}\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$", var.image))
    error_message = "image must be a full digest-qualified reference, <repository>@sha256:<64 lowercase hex>; any tag is refused."
  }

  validation {
    condition     = startswith(var.image, "${var.approved_image_repository_url}@sha256:")
    error_message = "image must come from the approved release repository."
  }
}

variable "image_repository_arn" {
  description = "ARN of the approved release repository: the one repository the execution roles pull from."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^arn:aws:ecr:[a-z0-9-]+:[0-9]{12}:repository/[a-z0-9][a-z0-9._/-]*$", var.image_repository_arn))
    error_message = "image_repository_arn must be an ECR repository ARN."
  }
}

variable "commands" {
  description = "Container command per task. The web/API and migrate commands name existing entry points; the broker, bootstrap and identity-binding commands are M3.3c's and do not exist yet."
  type = object({
    web_api          = list(string)
    identity_broker  = list(string)
    migrate          = list(string)
    bootstrap        = list(string)
    identity_binding = list(string)
  })
  nullable = false

  validation {
    condition = alltrue([
      for command in values(var.commands) :
      length(command) > 0 && alltrue([for part in command : length(trimspace(part)) > 0])
    ])
    error_message = "Every task needs a non-empty command with no empty argument."
  }
}

variable "task_sizes" {
  description = "Fargate CPU units and memory MiB per task, keyed like commands."
  type = map(object({
    cpu    = number
    memory = number
  }))
  nullable = false

  validation {
    condition = (
      toset(keys(var.task_sizes)) == toset(["web_api", "identity_broker", "migrate", "bootstrap", "identity_binding"]) &&
      alltrue([
        for size in values(var.task_sizes) : contains(lookup({
          "256"  = [512, 1024, 2048]
          "512"  = [1024, 2048, 3072, 4096]
          "1024" = [2048, 3072, 4096, 5120, 6144, 7168, 8192]
          "2048" = [4096, 5120, 6144, 7168, 8192, 9216, 10240, 11264, 12288, 13312, 14336, 15360, 16384]
        }, tostring(size.cpu), []), size.memory)
      ])
    )
    error_message = "task_sizes must size all five tasks with a supported Fargate CPU and memory combination (256 to 2048 CPU units)."
  }
}

variable "desired_counts" {
  description = "Running tasks per service; no autoscaling in M3.3."
  type = object({
    web_api         = number
    identity_broker = number
  })
  nullable = false

  validation {
    condition     = var.desired_counts.web_api >= 1 && var.desired_counts.web_api <= 4 && var.desired_counts.identity_broker >= 1 && var.desired_counts.identity_broker <= 4
    error_message = "Each service runs from 1 to 4 tasks."
  }
}

variable "private_subnet_ids" {
  type     = list(string)
  nullable = false
}

variable "task_security_group_ids" {
  type     = map(string)
  nullable = false
}

variable "target_group_arns" {
  type     = map(string)
  nullable = false
}

variable "application_port" {
  type     = number
  nullable = false
}

variable "log_group_names" {
  type     = map(string)
  nullable = false
}

variable "secret_arns" {
  description = "Secret container ARNs from the secrets module."
  type = object({
    application_database_url      = string
    authenticator_database_url    = string
    identity_binding_database_url = string
    migration_database_url        = string
    cognito_client_secret         = string
  })
  nullable = false
}

variable "rds_master_secret_arn" {
  description = "ARN of the RDS-managed master secret; injected into the bootstrap task and nothing else."
  type        = string
  nullable    = false
}

variable "workload_kms_key_arn" {
  type     = string
  nullable = false
}

variable "refresh_token_kms_key_arn" {
  type     = string
  nullable = false
}

variable "cognito" {
  type = object({
    user_pool_id  = string
    user_pool_arn = string
    client_id     = string
    issuer        = string
  })
  nullable = false
}

variable "app_origin" {
  description = "The one customer origin, https://<app_hostname>."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^https://[a-z0-9.-]+$", var.app_origin))
    error_message = "app_origin must be an https origin with no path."
  }
}

variable "firmbatch_env" {
  description = "FIRMBATCH_ENV for every container. The staging configuration mode is M3.3c's; the test environment is never deployed."
  type        = string
  nullable    = false

  validation {
    condition     = var.firmbatch_env != "test"
    error_message = "The test environment is never deployed."
  }
}

variable "workload_permissions_boundary_arn" {
  description = "The permissions boundary every execution and task role carries, from the delivery module."
  type        = string
  nullable    = false
}
