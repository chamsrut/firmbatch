# The ECS cluster, two long-running services and three one-off task definitions, every one of
# them the same verified release image, by digest (ADR 0011 decision 3; ADR 0012 decision 13;
# topology §3).
#
# Task-definition revisions and service updates are applied by staging-apply from verified saved
# plans, inside the delivery contract (ADR 0012 decision 5): the roles below are created on the
# first, human, apply and only ever passed afterwards, and delivery.py plan-summary checks every
# revision's image, roles, secret references and hardening -- non-root user, read-only root
# filesystem, no privilege, every capability dropped, awsvpc networking, no volume -- before apply.
# Every revision is skip_destroy, so a rollout never deregisters the revision a rollback needs.
#
# THESE ARE RUNTIME CONTRACTS, NOT A DEPLOYABLE ENVIRONMENT. The identity broker, bootstrap
# and identity-binding programs do not exist until M3.3c, and the existing web/API entry point
# still requires an authenticator URL the AWS-mode web/API service will not receive. Every task
# definition and service carries a precondition on runtime_contract_reviewed, so nothing here
# plans until M3.3c's programs, dependencies and image have passed review.
#
# Credential separation, one row per task:
#   web_api           application database URL only
#   identity_broker   authenticator database URL, Cognito client secret, refresh-token KMS key
#   migrate           migration (schema-owner) database URL only
#   bootstrap         the RDS-managed master secret; PutSecretValue on the four database URLs
#   identity_binding  identity-binding database URL; cognito-idp:AdminGetUser on the one pool
# No long-running service holds the schema-owner, migration or master credential, and the
# identity-binding task never receives the authenticator credential. ECS Exec is disabled
# everywhere; enabling it needs a later, explicit architecture decision.

locals {
  # The verified release reference, validated as <approved repository>@sha256:<digest>. Built once
  # by artifact-publish and promoted by digest; nothing here ever names a tag.
  image = var.image

  session_ttl_seconds = "28800"

  tasks = {
    web_api = {
      family  = "web-api"
      service = true
      command = var.commands.web_api
      secrets = tomap({
        FIRMBATCH_DATABASE_URL = var.secret_arns.application_database_url
      })
      environment = tomap({
        FIRMBATCH_ENV                     = var.firmbatch_env
        FIRMBATCH_API_ALLOWED_ORIGINS     = var.app_origin
        FIRMBATCH_API_COOKIE_SECURE       = "true"
        FIRMBATCH_API_SESSION_TTL_SECONDS = local.session_ttl_seconds
      })
    }

    identity_broker = {
      family  = "identity-broker"
      service = true
      command = var.commands.identity_broker
      secrets = tomap({
        FIRMBATCH_AUTHENTICATOR_DATABASE_URL = var.secret_arns.authenticator_database_url
        FIRMBATCH_COGNITO_CLIENT_SECRET      = var.secret_arns.cognito_client_secret
      })
      environment = tomap({
        FIRMBATCH_ENV                       = var.firmbatch_env
        FIRMBATCH_API_ALLOWED_ORIGINS       = var.app_origin
        FIRMBATCH_API_COOKIE_SECURE         = "true"
        FIRMBATCH_API_SESSION_TTL_SECONDS   = local.session_ttl_seconds
        FIRMBATCH_COGNITO_ISSUER            = var.cognito.issuer
        FIRMBATCH_COGNITO_CLIENT_ID         = var.cognito.client_id
        FIRMBATCH_REFRESH_TOKEN_KMS_KEY_ARN = var.refresh_token_kms_key_arn
      })
    }

    migrate = {
      family  = "migrate"
      service = false
      command = var.commands.migrate
      secrets = tomap({
        FIRMBATCH_MIGRATION_DATABASE_URL = var.secret_arns.migration_database_url
      })
      environment = tomap({
        FIRMBATCH_ENV = var.firmbatch_env
      })
    }

    bootstrap = {
      family  = "bootstrap"
      service = false
      command = var.commands.bootstrap
      secrets = tomap({
        FIRMBATCH_RDS_MASTER_SECRET = var.rds_master_secret_arn
      })
      environment = tomap({
        FIRMBATCH_ENV = var.firmbatch_env
        FIRMBATCH_BOOTSTRAP_TARGET_SECRET_ARNS = jsonencode({
          application_database_url      = var.secret_arns.application_database_url
          authenticator_database_url    = var.secret_arns.authenticator_database_url
          identity_binding_database_url = var.secret_arns.identity_binding_database_url
          migration_database_url        = var.secret_arns.migration_database_url
        })
      })
    }

    identity_binding = {
      family  = "identity-binding"
      service = false
      command = var.commands.identity_binding
      secrets = tomap({
        FIRMBATCH_IDENTITY_BINDING_DATABASE_URL = var.secret_arns.identity_binding_database_url
      })
      environment = tomap({
        FIRMBATCH_ENV                  = var.firmbatch_env
        FIRMBATCH_COGNITO_USER_POOL_ID = var.cognito.user_pool_id
        FIRMBATCH_COGNITO_ISSUER       = var.cognito.issuer
      })
    }
  }

  services = { for key, task in local.tasks : key => task if task.service }
}

resource "aws_ecs_cluster" "this" {
  name = var.cluster_name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  # No execute_command_configuration: ECS Exec is not enabled for any service or task.
}

resource "aws_ecs_task_definition" "this" {
  for_each = local.tasks

  # A new image digest is a new revision. Terraform's replacement removes the old revision from
  # state without deregistering it, so every previous revision stays registered for rollback and
  # the apply role holds no ecs:DeregisterTaskDefinition at all.
  skip_destroy = true

  family                   = "${var.name_prefix}-${each.value.family}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.task_sizes[each.key].cpu)
  memory                   = tostring(var.task_sizes[each.key].memory)
  execution_role_arn       = aws_iam_role.execution[each.key].arn
  task_role_arn            = aws_iam_role.task[each.key].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([{
    name                   = each.value.family
    image                  = local.image
    essential              = true
    command                = each.value.command
    user                   = "10001:10001"
    readonlyRootFilesystem = true
    privileged             = false
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    portMappings = each.value.service ? [{ containerPort = var.application_port, protocol = "tcp" }] : []
    environment  = [for name in sort(keys(each.value.environment)) : { name = name, value = each.value.environment[name] }]
    secrets      = [for name in sort(keys(each.value.secrets)) : { name = name, valueFrom = each.value.secrets[name] }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = var.log_group_names[each.key]
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = each.value.family
      }
    }
  }])

  lifecycle {
    precondition {
      condition     = var.runtime_contract_reviewed
      error_message = "Not operational: M3.3c's broker, bootstrap and identity-binding programs, their dependencies and the image have not passed review."
    }
  }
}

resource "aws_ecs_service" "this" {
  for_each = local.services

  name             = var.service_names[each.key]
  cluster          = aws_ecs_cluster.this.id
  task_definition  = aws_ecs_task_definition.this[each.key].arn
  desired_count    = var.desired_counts[each.key]
  launch_type      = "FARGATE"
  platform_version = "1.4.0"

  enable_execute_command            = false
  enable_ecs_managed_tags           = true
  propagate_tags                    = "SERVICE"
  health_check_grace_period_seconds = 60

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.task_security_group_ids[each.key]]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = var.target_group_arns[each.key]
    container_name   = each.value.family
    container_port   = var.application_port
  }

  lifecycle {
    precondition {
      condition     = var.runtime_contract_reviewed
      error_message = "Not operational: M3.3c's programs, dependencies and image have not passed review."
    }
  }
}
