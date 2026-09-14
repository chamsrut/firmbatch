# One execution role and one task role per service and one-off task, each under the workload
# permissions boundary. An execution role reads exactly the secrets its own container
# definition names; a task role carries only the AWS permissions in the topology's table.

locals {
  ecs_tasks_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:ecs:${var.region}:${var.account_id}:*" }
      }
    }]
  })

  runtime_database_url_secret_arns = [
    var.secret_arns.application_database_url,
    var.secret_arns.authenticator_database_url,
    var.secret_arns.identity_binding_database_url,
    var.secret_arns.migration_database_url,
  ]

  # Task-role policies, as JSON, only for the three tasks that need any AWS permission.
  task_role_policies = {
    identity_broker = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Sid      = "RefreshTokenEncryptionBoundToSessionAndAccount"
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt"]
        Resource = var.refresh_token_kms_key_arn
        Condition = {
          "ForAllValues:StringEquals" = {
            "kms:EncryptionContextKeys" = ["firmbatch:session_id", "firmbatch:account_id"]
          }
          Null = {
            "kms:EncryptionContext:firmbatch:session_id" = "false"
            "kms:EncryptionContext:firmbatch:account_id" = "false"
          }
        }
      }]
    })

    bootstrap = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid      = "WriteRuntimeDatabaseUrlsIntoPreCreatedContainers"
          Effect   = "Allow"
          Action   = ["secretsmanager:PutSecretValue", "secretsmanager:DescribeSecret"]
          Resource = local.runtime_database_url_secret_arns
        },
        {
          Sid      = "EncryptThoseValuesThroughSecretsManager"
          Effect   = "Allow"
          Action   = ["kms:GenerateDataKey", "kms:Encrypt"]
          Resource = var.workload_kms_key_arn
          Condition = {
            StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }
          }
        },
      ]
    })

    identity_binding = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Sid      = "ValidateTheSelectedSubjectInTheOnePool"
        Effect   = "Allow"
        Action   = "cognito-idp:AdminGetUser"
        Resource = var.cognito.user_pool_arn
      }]
    })
  }
}

resource "aws_iam_role" "execution" {
  for_each = local.tasks

  name                 = "${var.name_prefix}-${each.value.family}-execution"
  description          = "ECS execution role for ${each.value.family}: image pull, its own log stream, its own secrets"
  assume_role_policy   = local.ecs_tasks_trust
  permissions_boundary = var.workload_permissions_boundary_arn
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "execution" {
  for_each = local.tasks

  name = "execution"
  role = aws_iam_role.execution[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PullFromTheReleaseRepository"
        Effect   = "Allow"
        Action   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
        Resource = var.image_repository_arn
      },
      {
        Sid      = "EcrAuthorizationToken"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Sid      = "WriteItsOwnLogStream"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${var.account_id}:log-group:${var.log_group_names[each.key]}:log-stream:*"
      },
      {
        Sid      = "ReadOnlyTheSecretsItsContainerNames"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = sort(values(each.value.secrets))
      },
      {
        Sid      = "DecryptThoseSecretsThroughSecretsManager"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = var.workload_kms_key_arn
        Condition = {
          StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }
        }
      },
    ]
  })
}

resource "aws_iam_role" "task" {
  for_each = local.tasks

  name                 = "${var.name_prefix}-${each.value.family}-task"
  description          = "ECS task role for ${each.value.family}"
  assume_role_policy   = local.ecs_tasks_trust
  permissions_boundary = var.workload_permissions_boundary_arn
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "task" {
  for_each = local.task_role_policies

  name   = "task"
  role   = aws_iam_role.task[each.key].id
  policy = each.value
}
