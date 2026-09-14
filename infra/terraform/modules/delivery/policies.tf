# The workload permissions boundary and the operator's identity-binding run policy (ADR 0011
# decision 5; ADR 0012 decision 5). The GitHub plan, apply and artifact-publish policies and
# boundaries are the bootstrap root's (infra/terraform/bootstrap/delivery_policies.tf).

# ------------------------------------------------------------------ workload boundary

resource "aws_iam_policy" "workload_boundary" {
  name        = local.workload_boundary_name
  description = "Permissions boundary of every ECS execution and task role: the release repository, this environment's log groups, secrets, keys and user pool only."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EcrAuthorizationToken"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        # Layers are decrypted under ECR's own grant on the release key; a pull needs no key
        # permission of its own.
        Sid      = "PullTheReleaseRepository"
        Effect   = "Allow"
        Action   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
        Resource = local.release_repository_arn
      },
      {
        Sid      = "ThisEnvironmentsLogGroups"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${var.account_id}:log-group:/ecs/${var.name_prefix}/*"
      },
      {
        # This environment's containers and the RDS-managed master secret, whose name RDS chooses.
        Sid    = "ThisEnvironmentsSecrets"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "secretsmanager:PutSecretValue"]
        Resource = [
          "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/*",
          "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:rds!*",
        ]
      },
      {
        Sid       = "KeysInThisAccountAndRegion"
        Effect    = "Allow"
        Action    = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
        Resource  = "arn:aws:kms:${var.region}:${var.account_id}:key/*"
        Condition = { StringEquals = { "aws:ResourceAccount" = var.account_id } }
      },
      {
        Sid      = "ThisAccountsUserPools"
        Effect   = "Allow"
        Action   = "cognito-idp:AdminGetUser"
        Resource = "arn:aws:cognito-idp:${var.region}:${var.account_id}:userpool/*"
      },
      {
        Sid      = "NeverTheBootstrapKeysOrBuckets"
        Effect   = "Deny"
        Action   = ["kms:*", "s3:*"]
        Resource = [var.state_kms_key_arn, var.plan_kms_key_arn, local.state_bucket_arn, "${local.state_bucket_arn}/*", local.plan_bucket_arn, "${local.plan_bucket_arn}/*"]
      },
    ]
  })
}

# ------------------------------------------------------------------ operator binding permission

# Attach to the operator's AWS SSO permission set by name. It can start the identity-binding
# task definition and nothing else, and pass only that task's own two roles, so it can neither
# start the broker nor run the binding task under another task's roles. The task's command is
# assumed overridable (ADR 0011 decision 5). Human-applied, like every IAM resource.
resource "aws_iam_policy" "operator_identity_binding" {
  name        = "${var.name_prefix}-operator-identity-binding"
  description = "Run the identity-binding one-off task and nothing else."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RunOnlyTheIdentityBindingTaskDefinition"
        Effect    = "Allow"
        Action    = "ecs:RunTask"
        Resource  = "arn:aws:ecs:${var.region}:${var.account_id}:task-definition/${local.identity_binding_family}:*"
        Condition = { ArnEquals = { "ecs:cluster" = local.cluster_arn } }
      },
      {
        Sid       = "PassOnlyTheIdentityBindingTasksOwnRoles"
        Effect    = "Allow"
        Action    = "iam:PassRole"
        Resource  = local.identity_binding_role_arns
        Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }
      },
      {
        Sid       = "ObserveTasksInTheCluster"
        Effect    = "Allow"
        Action    = ["ecs:DescribeTasks", "ecs:ListTasks"]
        Resource  = "*"
        Condition = { ArnEquals = { "ecs:cluster" = local.cluster_arn } }
      },
    ]
  })
}
