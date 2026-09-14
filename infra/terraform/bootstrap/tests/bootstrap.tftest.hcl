# Mocked AWS only; no run block here can reach AWS. The one provider configuration this root
# declares is replaced by the mock_provider below, the verification gate runs `terraform test`
# with every AWS credential removed and instance metadata disabled, and
# infra/terraform/policy/check.py refuses any test file that leaves a provider configuration
# unmocked. Every run is `command = plan`: nothing is applied, even to the mock.
#
# The two policy-evaluation runs below evaluate the rendered identity policy and permissions
# boundary against representative requests, statement by statement: Action or NotAction, Resource
# or NotResource, and every condition operator these policies use against the request's context. A
# request is effective only when the identity policy and the boundary both allow it and neither
# denies it. infra/terraform/policy/check.py evaluates the same requests independently.

mock_provider "aws" {
  override_during = plan

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111111111111"
      arn        = "arn:aws:iam::111111111111:role/synthetic-operator"
      user_id    = "SYNTHETIC"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "eu-central-1"
      name   = "eu-central-1"
    }
  }

  mock_resource "aws_kms_key" {
    defaults = {
      arn    = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-000000000000"
      key_id = "00000000-0000-4000-8000-000000000000"
    }
  }

  mock_resource "aws_iam_openid_connect_provider" {
    defaults = {
      arn = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
    }
  }

  mock_resource "aws_iam_policy" {
    defaults = {
      arn = "arn:aws:iam::111111111111:policy/synthetic-boundary"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::111111111111:role/synthetic-role"
      id  = "synthetic-role"
    }
  }
}

# Synthetic values only.
variables {
  expected_account_id                     = "111111111111"
  region                                  = "eu-central-1"
  environment                             = "staging"
  name_prefix                             = "firmbatch-staging"
  release_name_prefix                     = "firmbatch"
  state_bucket_name                       = "synthetic-firmbatch-state"
  plan_bucket_name                        = "synthetic-firmbatch-plans"
  plan_retention_days                     = 1
  state_noncurrent_version_retention_days = 90
  artifact_registry_account_id            = "111111111111"
  artifact_registry_region                = "eu-central-1"
  release_repository_name                 = "firmbatch/control-plane"
  release_bucket_name                     = "synthetic-firmbatch-releases"
  route53_zone_id                         = "Z0SYNTHETIC00000000"
  rds_instance_class                      = "db.t4g.micro"
}

run "state_bucket_is_versioned_encrypted_private_and_never_expires_state" {
  command = plan

  assert {
    condition     = aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled"
    error_message = "The state bucket must be versioned."
  }

  assert {
    condition = alltrue([
      for rule in aws_s3_bucket_server_side_encryption_configuration.state.rule : alltrue([
        for default in rule.apply_server_side_encryption_by_default : default.sse_algorithm == "aws:kms"
      ])
    ])
    error_message = "The state bucket must use customer-managed KMS encryption."
  }

  assert {
    condition = (
      aws_s3_bucket_public_access_block.state.block_public_acls &&
      aws_s3_bucket_public_access_block.state.block_public_policy &&
      aws_s3_bucket_public_access_block.state.ignore_public_acls &&
      aws_s3_bucket_public_access_block.state.restrict_public_buckets
    )
    error_message = "The state bucket must block every form of public access."
  }

  assert {
    condition     = aws_s3_bucket.state.object_lock_enabled == false && aws_s3_bucket.state.force_destroy == false
    error_message = "The state bucket is not the Object-Locked plan bucket and cannot be force-destroyed."
  }

  assert {
    condition = alltrue([
      for rule in aws_s3_bucket_lifecycle_configuration.state.rule :
      length(rule.expiration) == 0 && length(rule.noncurrent_version_expiration) == 1
    ])
    error_message = "No lifecycle rule may expire current state or its delete markers; only superseded versions age out."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_s3_bucket_policy.state.policy).Statement :
      try(statement.Sid == "DenyInsecureTransport" && statement.Effect == "Deny" && statement.Condition.Bool["aws:SecureTransport"] == "false", false)
    ])
    error_message = "The state bucket must refuse non-TLS access."
  }

  assert {
    condition     = aws_kms_key.state.enable_key_rotation && aws_kms_key.plans.enable_key_rotation && aws_kms_key.release.enable_key_rotation
    error_message = "Every bootstrap key rotates."
  }
}

run "plan_bucket_is_object_locked_short_lived_and_separate" {
  command = plan

  assert {
    condition     = aws_s3_bucket.plans.object_lock_enabled == true && aws_s3_bucket.plans.bucket != aws_s3_bucket.state.bucket
    error_message = "The plan bucket is its own bucket with Object Lock enabled."
  }

  assert {
    condition     = aws_s3_bucket_versioning.plans.versioning_configuration[0].status == "Enabled"
    error_message = "The plan bucket must be versioned."
  }

  assert {
    condition = length(aws_s3_bucket_object_lock_configuration.plans.rule) == 1 && alltrue([
      for rule in aws_s3_bucket_object_lock_configuration.plans.rule : alltrue([
        for retention in rule.default_retention : retention.mode == "GOVERNANCE" && retention.days == 1
      ])
    ])
    error_message = "Saved plans carry GOVERNANCE-mode Object Lock retention of plan_retention_days."
  }

  assert {
    condition = alltrue([
      for rule in aws_s3_bucket_lifecycle_configuration.plans.rule : alltrue([
        for filter in rule.filter : filter.prefix == "plans/"
      ])
    ])
    error_message = "Every plan-bucket lifecycle rule is confined to the plans/ prefix."
  }

  assert {
    condition = anytrue([
      for rule in aws_s3_bucket_lifecycle_configuration.plans.rule :
      try(rule.expiration[0].days == 1 && rule.noncurrent_version_expiration[0].noncurrent_days == 1, false)
    ])
    error_message = "Lifecycle expires current and noncurrent plan versions after the retention."
  }

  assert {
    condition = anytrue([
      for rule in aws_s3_bucket_lifecycle_configuration.plans.rule :
      try(rule.expiration[0].expired_object_delete_marker == true, false)
    ])
    error_message = "Lifecycle expires plan delete markers."
  }
}

run "plan_bucket_policy_forbids_overwrite_retention_bypass_history_and_other_writers" {
  command = plan

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_s3_bucket_policy.plans.policy).Statement :
      try(
        statement.Sid == "DenyOverwriteByPipelineRoles" &&
        statement.Effect == "Deny" &&
        statement.Action == "s3:PutObject" &&
        statement.Condition.Null["s3:if-none-match"] == "true" &&
        statement.Condition.ArnLike["aws:PrincipalArn"] == "arn:aws:iam::111111111111:role/firmbatch-staging-github-*",
        false
      )
    ])
    error_message = "Pipeline roles may only create plan objects that do not exist yet."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_s3_bucket_policy.plans.policy).Statement :
      try(
        statement.Sid == "OnlyThePlanRoleCreatesSavedPlans" && statement.Effect == "Deny" && statement.Principal == "*" &&
        statement.Action == "s3:PutObject" && length(keys(statement.Condition)) == 1 &&
        statement.Condition.ArnNotEquals["aws:PrincipalArn"] == "arn:aws:iam::111111111111:role/firmbatch-staging-github-plan",
        false
      )
    ])
    error_message = "Every principal but the exact plan role -- the apply role and any other staging role included -- is denied saved-plan writes."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_s3_bucket_policy.plans.policy).Statement :
      try(
        statement.Sid == "DenyRetentionBypassByPipelineRoles" && statement.Effect == "Deny" &&
        length(setsubtract(
          ["s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:DeleteObjectVersion", "s3:ListBucketVersions", "s3:PutLifecycleConfiguration"],
          statement.Action
        )) == 0,
        false
      )
    ])
    error_message = "Pipeline roles can neither bypass retention, delete a version nor enumerate history."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_s3_bucket_policy.plans.policy).Statement :
      try(
        statement.Sid == "DenyPlanReadsByPlanRole" &&
        contains(statement.Action, "s3:GetObjectVersion") &&
        statement.Condition.ArnEquals["aws:PrincipalArn"] == "arn:aws:iam::111111111111:role/firmbatch-staging-github-plan",
        false
      )
    ])
    error_message = "The plan role can never read a saved plan."
  }
}

run "the_github_oidc_provider_is_the_accounts_one_anchor_with_one_audience" {
  command = plan

  assert {
    condition     = aws_iam_openid_connect_provider.github.url == "https://token.actions.githubusercontent.com" && aws_iam_openid_connect_provider.github.client_id_list == toset(["sts.amazonaws.com"])
    error_message = "One GitHub OIDC provider per account, in the human-applied trust root; its only audience is sts.amazonaws.com."
  }
}

run "every_delivery_identity_is_created_here_trusting_exactly_its_own_environment" {
  command = plan

  assert {
    condition = alltrue([
      for pair in [
        [aws_iam_role.github_plan.assume_role_policy, "staging-plan"],
        [aws_iam_role.github_apply.assume_role_policy, "staging-apply"],
        [aws_iam_role.artifact_publish.assume_role_policy, "artifact-publish"],
      ] :
      length(jsondecode(pair[0]).Statement) == 1 &&
      jsondecode(pair[0]).Statement[0].Action == "sts:AssumeRoleWithWebIdentity" &&
      jsondecode(pair[0]).Statement[0].Principal.Federated == "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com" &&
      length(keys(jsondecode(pair[0]).Statement[0].Condition)) == 1 &&
      jsondecode(pair[0]).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com" &&
      jsondecode(pair[0]).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:chamsrut/firmbatch:environment:${pair[1]}"
    ])
    error_message = "Each delivery identity trusts exactly this repository's own environment, audience sts.amazonaws.com, through this root's OIDC provider."
  }

  assert {
    condition = (
      aws_iam_role.github_plan.name == "firmbatch-staging-github-plan" &&
      aws_iam_role.github_apply.name == "firmbatch-staging-github-apply" &&
      aws_iam_role.artifact_publish.name == "firmbatch-artifact-publish" &&
      aws_iam_role.github_plan.permissions_boundary == aws_iam_policy.plan_boundary.arn &&
      aws_iam_role.github_apply.permissions_boundary == aws_iam_policy.apply_boundary.arn &&
      aws_iam_role.artifact_publish.permissions_boundary == aws_iam_policy.artifact_publish_boundary.arn &&
      aws_iam_policy.plan_boundary.name == "firmbatch-staging-github-plan-boundary" &&
      aws_iam_policy.apply_boundary.name == "firmbatch-staging-github-apply-boundary" &&
      aws_iam_policy.artifact_publish_boundary.name == "firmbatch-artifact-publish-boundary"
    )
    error_message = "Three distinct identities, each under its own boundary, named as the artifacts root and the workflows expect."
  }

  assert {
    condition     = !anytrue([for statement in jsondecode(aws_iam_policy.apply_boundary.policy).Statement : try(statement.Sid == "DenyEveryIamChange", false)])
    error_message = "The former DenyEveryIamChange statement -- a NotAction deny of everything but IAM reads -- denied every non-IAM operation and must not return."
  }

  assert {
    condition = alltrue(flatten([
      for document in [jsondecode(aws_iam_policy.plan_boundary.policy), jsondecode(aws_iam_policy.apply_boundary.policy), jsondecode(aws_iam_policy.artifact_publish_boundary.policy)] : [
        for statement in document.Statement :
        !can(statement.NotAction) || (
          statement.Effect == "Deny" &&
          length(keys(statement.Condition)) == 1 &&
          length(keys(values(statement.Condition)[0])) == 1 &&
          keys(values(statement.Condition)[0])[0] == "aws:RequestedRegion" &&
          contains(["StringEquals", "StringNotEquals"], keys(statement.Condition)[0]) &&
          !anytrue([for region in flatten([values(values(statement.Condition)[0])[0]]) : strcontains(region, "*") || strcontains(region, "?")])
        )
      ]
    ]))
    error_message = "A NotAction statement in a boundary may only deny requests outside exact regions; a broad NotAction deny of everything but a short allow-list is refused."
  }

  assert {
    condition = alltrue(flatten([
      for document in [jsondecode(aws_iam_role_policy.github_plan.policy), jsondecode(aws_iam_role_policy.github_apply.policy), jsondecode(aws_iam_role_policy.artifact_publish.policy), jsondecode(aws_iam_policy.plan_boundary.policy), jsondecode(aws_iam_policy.apply_boundary.policy), jsondecode(aws_iam_policy.artifact_publish_boundary.policy)] : [
        for statement in document.Statement : alltrue([
          for operator in keys(try(statement.Condition, {})) :
          contains(["StringEquals", "StringNotEquals", "StringEqualsIfExists", "StringNotEqualsIfExists", "StringLike", "ArnEquals", "ArnLike", "ArnLikeIfExists", "ArnNotEquals", "ArnNotLike", "Bool", "Null", "ForAnyValue:StringEquals", "ForAllValues:StringNotEquals"], operator)
        ])
      ]
    ]))
    error_message = "Every condition operator in the delivery policies is one the evaluation runs below understand."
  }
}

run "the_apply_boundary_admits_staging_work_and_no_iam_mutation" {
  command = plan

  # Every representative request the apply role must be able to make: state and the exact saved
  # plan, EC2 and VPC, RDS, task-definition registration, both services' rollout, the workload role
  # assignment, observability, the budget, and the release re-verification before apply.
  assert {
    condition = alltrue([
      for r in [
        { action = "s3:GetObject", resource = "arn:aws:s3:::synthetic-firmbatch-state/staging/terraform.tfstate", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "s3:PutObject", resource = "arn:aws:s3:::synthetic-firmbatch-state/staging/terraform.tfstate", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "s3:PutObject", resource = "arn:aws:s3:::synthetic-firmbatch-state/staging/terraform.tfstate.tflock", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "s3:GetObjectVersion", resource = "arn:aws:s3:::synthetic-firmbatch-plans/plans/staging/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.tfplan", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "kms:Decrypt", resource = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-000000000000", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "ec2:CreateVpc", resource = "arn:aws:ec2:eu-central-1:111111111111:vpc/*", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "ec2:AuthorizeSecurityGroupIngress", resource = "arn:aws:ec2:eu-central-1:111111111111:security-group/sg-synthetic", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "rds:CreateDBInstance", resource = "arn:aws:rds:eu-central-1:111111111111:db:firmbatch-staging", context = { "aws:RequestedRegion" = ["eu-central-1"], "rds:DatabaseClass" = ["db.t4g.micro"] } },
        { action = "rds:ModifyDBInstance", resource = "arn:aws:rds:eu-central-1:111111111111:db:firmbatch-staging", context = { "aws:RequestedRegion" = ["eu-central-1"], "rds:DatabaseClass" = ["db.t4g.micro"] } },
        { action = "ecs:RegisterTaskDefinition", resource = "arn:aws:ecs:eu-central-1:111111111111:task-definition/firmbatch-staging-web-api:8", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "ecs:UpdateService", resource = "arn:aws:ecs:eu-central-1:111111111111:service/firmbatch-staging/firmbatch-staging-web-api", context = { "aws:RequestedRegion" = ["eu-central-1"], "ecs:cluster" = ["arn:aws:ecs:eu-central-1:111111111111:cluster/firmbatch-staging"], "ecs:task-definition" = ["arn:aws:ecs:eu-central-1:111111111111:task-definition/firmbatch-staging-web-api:8"], "ecs:enable-execute-command" = ["false"] } },
        { action = "ecs:UpdateService", resource = "arn:aws:ecs:eu-central-1:111111111111:service/firmbatch-staging/firmbatch-staging-identity-broker", context = { "aws:RequestedRegion" = ["eu-central-1"], "ecs:cluster" = ["arn:aws:ecs:eu-central-1:111111111111:cluster/firmbatch-staging"] } },
        { action = "ecs:CreateService", resource = "arn:aws:ecs:eu-central-1:111111111111:service/firmbatch-staging/firmbatch-staging-identity-broker", context = { "aws:RequestedRegion" = ["eu-central-1"], "ecs:cluster" = ["arn:aws:ecs:eu-central-1:111111111111:cluster/firmbatch-staging"], "ecs:task-definition" = ["arn:aws:ecs:eu-central-1:111111111111:task-definition/firmbatch-staging-identity-broker:1"], "ecs:enable-execute-command" = ["false"] } },
        { action = "iam:PassRole", resource = "arn:aws:iam::111111111111:role/firmbatch-staging-web-api-execution", context = { "aws:RequestedRegion" = ["eu-central-1"], "iam:PassedToService" = ["ecs-tasks.amazonaws.com"] } },
        { action = "iam:GetRole", resource = "arn:aws:iam::111111111111:role/firmbatch-staging-web-api-task", context = { "aws:RequestedRegion" = ["us-east-1"] } },
        { action = "logs:CreateLogGroup", resource = "arn:aws:logs:eu-central-1:111111111111:log-group:/ecs/firmbatch-staging/web-api", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "cloudwatch:PutMetricAlarm", resource = "arn:aws:cloudwatch:eu-central-1:111111111111:alarm:firmbatch-staging-web-api-running", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "sns:CreateTopic", resource = "arn:aws:sns:eu-central-1:111111111111:firmbatch-staging-alerts", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "budgets:ModifyBudget", resource = "arn:aws:budgets::111111111111:budget/firmbatch-staging-monthly", context = { "aws:RequestedRegion" = ["us-east-1"] } },
        { action = "ecr:DescribeImages", resource = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "ecr:DescribeImageScanFindings", resource = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "s3:GetObjectVersion", resource = "arn:aws:s3:::synthetic-firmbatch-releases/releases/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/release-manifest.json", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "kms:Decrypt", resource = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-000000000000", context = { "aws:RequestedRegion" = ["eu-central-1"], "kms:ViaService" = ["s3.eu-central-1.amazonaws.com"] } },
      ] :
      alltrue([
        for effects in [[
          for x in concat(
            [for s in jsondecode(aws_iam_role_policy.github_apply.policy).Statement : { w = "identity", s = s }],
            [for s in jsondecode(aws_iam_policy.apply_boundary.policy).Statement : { w = "boundary", s = s }],
          ) : "${x.w}:${x.s.Effect}"
          if(
            (can(x.s.Action) ? anytrue([for p in flatten([x.s.Action]) : can(regex("^${replace(replace(replace(lower(p), ".", "\\."), "*", ".*"), "?", ".")}$", lower(r.action)))]) : !anytrue([for p in flatten([x.s.NotAction]) : can(regex("^${replace(replace(replace(lower(p), ".", "\\."), "*", ".*"), "?", ".")}$", lower(r.action)))])) &&
            (can(x.s.Resource) ? anytrue([for p in flatten([x.s.Resource]) : can(regex("^${replace(replace(replace(p, ".", "\\."), "*", ".*"), "?", ".")}$", r.resource))]) : !anytrue([for p in flatten([x.s.NotResource]) : can(regex("^${replace(replace(replace(p, ".", "\\."), "*", ".*"), "?", ".")}$", r.resource))])) &&
            alltrue([
              for operator, entries in try(x.s.Condition, {}) : alltrue([
                for key, want in entries : alltrue([
                  for b in [{ present = contains(keys(r.context), key), vals = try(r.context[key], []), wants = flatten([want]) }] : alltrue([
                    for m in [{ eq = anytrue([for v in b.vals : contains(b.wants, v)]), like = anytrue([for v in b.vals : anytrue([for w in b.wants : can(regex("^${replace(replace(replace(w, ".", "\\."), "*", ".*"), "?", ".")}$", v))])]) }] :
                    operator == "StringEquals" || operator == "Bool" || operator == "ForAnyValue:StringEquals" ? (b.present && m.eq) :
                    operator == "StringNotEquals" || operator == "ForAllValues:StringNotEquals" ? (!b.present || !m.eq) :
                    operator == "StringEqualsIfExists" ? (!b.present || m.eq) :
                    operator == "StringNotEqualsIfExists" ? (!b.present || !m.eq) :
                    operator == "StringLike" || operator == "ArnEquals" || operator == "ArnLike" ? (b.present && m.like) :
                    operator == "ArnLikeIfExists" ? (!b.present || m.like) :
                    operator == "ArnNotEquals" || operator == "ArnNotLike" ? (!b.present || !m.like) :
                    operator == "Null" ? ((b.wants[0] == "true") != b.present) : false
                  ])
                ])
              ])
            ])
          )
        ]] :
        contains(effects, "identity:Allow") && contains(effects, "boundary:Allow") && !contains(effects, "identity:Deny") && !contains(effects, "boundary:Deny")
      ])
    ])
    error_message = "A representative staging request -- state or the exact saved plan, EC2/VPC, RDS, task-definition registration, a service rollout, the workload role assignment, observability, the budget or release re-verification -- is not allowed by both the apply role and its boundary, or is explicitly denied."
  }

  # Every request the apply role must never be able to make: any IAM mutation of a role, policy,
  # trust policy or boundary; another role or service for PassRole; deregistration; a service
  # running another family or ECS Exec; a one-off task; image publication; a release-record write;
  # a secret value; another region; a budget action.
  assert {
    condition = !anytrue([
      for r in [
        { action = "iam:CreateRole", resource = "arn:aws:iam::111111111111:role/replacement-deployer", context = { "aws:RequestedRegion" = ["us-east-1"] } },
        { action = "iam:PutRolePolicy", resource = "arn:aws:iam::111111111111:role/firmbatch-staging-github-apply", context = { "aws:RequestedRegion" = ["us-east-1"] } },
        { action = "iam:AttachRolePolicy", resource = "arn:aws:iam::111111111111:role/firmbatch-staging-web-api-task", context = { "aws:RequestedRegion" = ["us-east-1"] } },
        { action = "iam:DetachRolePolicy", resource = "arn:aws:iam::111111111111:role/firmbatch-staging-web-api-task", context = { "aws:RequestedRegion" = ["us-east-1"] } },
        { action = "iam:UpdateAssumeRolePolicy", resource = "arn:aws:iam::111111111111:role/firmbatch-staging-github-apply", context = { "aws:RequestedRegion" = ["us-east-1"] } },
        { action = "iam:DeleteRolePermissionsBoundary", resource = "arn:aws:iam::111111111111:role/firmbatch-staging-github-apply", context = { "aws:RequestedRegion" = ["us-east-1"] } },
        { action = "iam:PutRolePermissionsBoundary", resource = "arn:aws:iam::111111111111:role/firmbatch-staging-github-apply", context = { "aws:RequestedRegion" = ["us-east-1"] } },
        { action = "iam:CreatePolicyVersion", resource = "arn:aws:iam::111111111111:policy/firmbatch-staging-github-apply-boundary", context = { "aws:RequestedRegion" = ["us-east-1"] } },
        { action = "iam:DeleteRole", resource = "arn:aws:iam::111111111111:role/firmbatch-staging-github-plan", context = { "aws:RequestedRegion" = ["us-east-1"] } },
        { action = "iam:PassRole", resource = "arn:aws:iam::111111111111:role/administrator", context = { "aws:RequestedRegion" = ["eu-central-1"], "iam:PassedToService" = ["ecs-tasks.amazonaws.com"] } },
        { action = "iam:PassRole", resource = "arn:aws:iam::111111111111:role/firmbatch-staging-web-api-task", context = { "aws:RequestedRegion" = ["eu-central-1"], "iam:PassedToService" = ["lambda.amazonaws.com"] } },
        { action = "ecs:DeregisterTaskDefinition", resource = "arn:aws:ecs:eu-central-1:111111111111:task-definition/firmbatch-staging-web-api:7", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "ecs:UpdateService", resource = "arn:aws:ecs:eu-central-1:111111111111:service/firmbatch-staging/firmbatch-staging-web-api", context = { "aws:RequestedRegion" = ["eu-central-1"], "ecs:cluster" = ["arn:aws:ecs:eu-central-1:111111111111:cluster/firmbatch-staging"], "ecs:task-definition" = ["arn:aws:ecs:eu-central-1:111111111111:task-definition/firmbatch-staging-bootstrap:3"] } },
        { action = "ecs:UpdateService", resource = "arn:aws:ecs:eu-central-1:111111111111:service/firmbatch-staging/firmbatch-staging-identity-broker", context = { "aws:RequestedRegion" = ["eu-central-1"], "ecs:cluster" = ["arn:aws:ecs:eu-central-1:111111111111:cluster/firmbatch-staging"], "ecs:enable-execute-command" = ["true"] } },
        { action = "ecs:RunTask", resource = "arn:aws:ecs:eu-central-1:111111111111:task-definition/firmbatch-staging-bootstrap:3", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "ecr:PutImage", resource = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "s3:PutObject", resource = "arn:aws:s3:::synthetic-firmbatch-releases/releases/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/release-manifest.json", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "secretsmanager:GetSecretValue", resource = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/application-database-url", context = { "aws:RequestedRegion" = ["eu-central-1"] } },
        { action = "ec2:CreateVpc", resource = "arn:aws:ec2:us-west-2:111111111111:vpc/*", context = { "aws:RequestedRegion" = ["us-west-2"] } },
        { action = "budgets:CreateBudgetAction", resource = "arn:aws:budgets::111111111111:budget/firmbatch-staging-monthly/action/*", context = { "aws:RequestedRegion" = ["us-east-1"] } },
      ] :
      anytrue([
        for effects in [[
          for x in concat(
            [for s in jsondecode(aws_iam_role_policy.github_apply.policy).Statement : { w = "identity", s = s }],
            [for s in jsondecode(aws_iam_policy.apply_boundary.policy).Statement : { w = "boundary", s = s }],
          ) : "${x.w}:${x.s.Effect}"
          if(
            (can(x.s.Action) ? anytrue([for p in flatten([x.s.Action]) : can(regex("^${replace(replace(replace(lower(p), ".", "\\."), "*", ".*"), "?", ".")}$", lower(r.action)))]) : !anytrue([for p in flatten([x.s.NotAction]) : can(regex("^${replace(replace(replace(lower(p), ".", "\\."), "*", ".*"), "?", ".")}$", lower(r.action)))])) &&
            (can(x.s.Resource) ? anytrue([for p in flatten([x.s.Resource]) : can(regex("^${replace(replace(replace(p, ".", "\\."), "*", ".*"), "?", ".")}$", r.resource))]) : !anytrue([for p in flatten([x.s.NotResource]) : can(regex("^${replace(replace(replace(p, ".", "\\."), "*", ".*"), "?", ".")}$", r.resource))])) &&
            alltrue([
              for operator, entries in try(x.s.Condition, {}) : alltrue([
                for key, want in entries : alltrue([
                  for b in [{ present = contains(keys(r.context), key), vals = try(r.context[key], []), wants = flatten([want]) }] : alltrue([
                    for m in [{ eq = anytrue([for v in b.vals : contains(b.wants, v)]), like = anytrue([for v in b.vals : anytrue([for w in b.wants : can(regex("^${replace(replace(replace(w, ".", "\\."), "*", ".*"), "?", ".")}$", v))])]) }] :
                    operator == "StringEquals" || operator == "Bool" || operator == "ForAnyValue:StringEquals" ? (b.present && m.eq) :
                    operator == "StringNotEquals" || operator == "ForAllValues:StringNotEquals" ? (!b.present || !m.eq) :
                    operator == "StringEqualsIfExists" ? (!b.present || m.eq) :
                    operator == "StringNotEqualsIfExists" ? (!b.present || !m.eq) :
                    operator == "StringLike" || operator == "ArnEquals" || operator == "ArnLike" ? (b.present && m.like) :
                    operator == "ArnLikeIfExists" ? (!b.present || m.like) :
                    operator == "ArnNotEquals" || operator == "ArnNotLike" ? (!b.present || !m.like) :
                    operator == "Null" ? ((b.wants[0] == "true") != b.present) : false
                  ])
                ])
              ])
            ])
          )
        ]] :
        contains(effects, "identity:Allow") && contains(effects, "boundary:Allow") && !contains(effects, "identity:Deny") && !contains(effects, "boundary:Deny")
      ])
    ])
    error_message = "A prohibited request -- an IAM mutation, another role or service for PassRole, deregistration, a service running another family or ECS Exec, a one-off task, a push, a release-record write, a secret value, another region or a budget action -- is effective for the apply role."
  }

  assert {
    condition = !anytrue([
      for statement in jsondecode(aws_iam_policy.apply_boundary.policy).Statement :
      statement.Effect == "Allow" && anytrue([for action in flatten([try(statement.Action, [])]) : startswith(lower(action), "iam:") && !startswith(action, "iam:Get") && !startswith(action, "iam:List") && action != "iam:PassRole"])
    ])
    error_message = "The apply boundary's ceiling admits no IAM action but exact reads and iam:PassRole."
  }
}

run "the_apply_role_rolls_out_only_inside_the_delivery_contract" {
  command = plan

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_role_policy.github_apply.policy).Statement :
      try(
        statement.Sid == "PassOnlyThePreCreatedWorkloadRoles" && statement.Action == "iam:PassRole" &&
        statement.Condition.StringEquals["iam:PassedToService"] == "ecs-tasks.amazonaws.com" &&
        length(statement.Resource) == 10 && alltrue([
          for arn in statement.Resource : can(regex("^arn:aws:iam::111111111111:role/firmbatch-staging-(web-api|identity-broker|migrate|bootstrap|identity-binding)-(execution|task)$", arn))
        ]),
        false
      )
    ])
    error_message = "The apply role may pass exactly the ten pre-created workload roles, and only to ECS tasks."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_role_policy.github_apply.policy).Statement :
      try(statement.Sid == "RegisterApprovedTaskDefinitionRevisions" && statement.Action == "ecs:RegisterTaskDefinition" && length(statement.Resource) == 5 && alltrue([for arn in statement.Resource : startswith(arn, "arn:aws:ecs:eu-central-1:111111111111:task-definition/firmbatch-staging-")]), false)
    ])
    error_message = "Registration of the five approved families only."
  }

  assert {
    condition = !anytrue(flatten([
      for document in [jsondecode(aws_iam_role_policy.github_plan.policy), jsondecode(aws_iam_role_policy.github_apply.policy)] : [
        for statement in document.Statement :
        statement.Effect == "Allow" && length(setintersection(flatten([statement.Action]), ["ecs:DeregisterTaskDefinition", "ecs:DeleteTaskDefinitions", "ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:BatchDeleteImage", "ecr:PutImageTagMutability", "ecr:GetAuthorizationToken"])) > 0
      ]
    ]))
    error_message = "Neither staging role can deregister a revision a rollback needs, or push, re-tag or delete an image."
  }

  assert {
    condition = alltrue([
      for pair in [["RollOutTheWebApiServiceWithItsOwnFamily", "web-api"], ["RollOutTheIdentityBrokerServiceWithItsOwnFamily", "identity-broker"]] :
      anytrue([
        for statement in jsondecode(aws_iam_role_policy.github_apply.policy).Statement :
        try(
          statement.Sid == pair[0] &&
          statement.Resource == "arn:aws:ecs:eu-central-1:111111111111:service/firmbatch-staging/firmbatch-staging-${pair[1]}" &&
          statement.Condition.ArnEquals["ecs:cluster"] == "arn:aws:ecs:eu-central-1:111111111111:cluster/firmbatch-staging" &&
          statement.Condition.ArnLikeIfExists["ecs:task-definition"] == "arn:aws:ecs:eu-central-1:111111111111:task-definition/firmbatch-staging-${pair[1]}:*" &&
          statement.Condition.StringEqualsIfExists["ecs:enable-execute-command"] == "false",
          false
        )
      ])
    ])
    error_message = "Each service is rolled out only with its own family, in the one cluster, never with ECS Exec."
  }

  assert {
    condition = !anytrue([
      for statement in jsondecode(aws_iam_role_policy.github_apply.policy).Statement :
      statement.Effect == "Allow" && statement.Sid != "PassOnlyThePreCreatedWorkloadRoles" && anytrue([for action in flatten([statement.Action]) : startswith(action, "iam:") && !startswith(action, "iam:Get") && !startswith(action, "iam:List")])
    ])
    error_message = "No other apply statement grants any IAM action beyond reads."
  }

  assert {
    condition = !anytrue([
      for statement in jsondecode(aws_iam_role_policy.github_plan.policy).Statement :
      statement.Effect == "Allow" && length(setintersection(flatten([statement.Action]), ["s3:GetObjectVersion", "s3:ListBucketVersions", "s3:BypassGovernanceRetention", "s3:PutObjectRetention", "iam:PassRole"])) > 0
    ])
    error_message = "The plan role cannot read, enumerate or unlock saved plans, and cannot pass a role."
  }
}

run "artifact_publish_is_publication_only" {
  command = plan

  assert {
    condition = alltrue([
      for r in [
        { action = "ecr:GetAuthorizationToken", resource = "*", context = {} },
        { action = "ecr:PutImage", resource = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane", context = {} },
        { action = "ecr:DescribeImages", resource = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane", context = {} },
        { action = "ecr:BatchGetImage", resource = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane", context = {} },
        { action = "ecr:GetDownloadUrlForLayer", resource = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane", context = {} },
        { action = "s3:PutObject", resource = "arn:aws:s3:::synthetic-firmbatch-releases/releases/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/release-manifest.json", context = {} },
        { action = "s3:GetObject", resource = "arn:aws:s3:::synthetic-firmbatch-releases/releases/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/release-manifest.json", context = {} },
        { action = "kms:GenerateDataKey", resource = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-000000000000", context = { "kms:ViaService" = ["s3.eu-central-1.amazonaws.com"] } },
        { action = "kms:Decrypt", resource = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-000000000000", context = { "kms:ViaService" = ["s3.eu-central-1.amazonaws.com"] } },
        { action = "sts:GetCallerIdentity", resource = "*", context = {} },
      ] :
      alltrue([
        for effects in [[
          for x in concat(
            [for s in jsondecode(aws_iam_role_policy.artifact_publish.policy).Statement : { w = "identity", s = s }],
            [for s in jsondecode(aws_iam_policy.artifact_publish_boundary.policy).Statement : { w = "boundary", s = s }],
          ) : "${x.w}:${x.s.Effect}"
          if(
            (can(x.s.Action) ? anytrue([for p in flatten([x.s.Action]) : can(regex("^${replace(replace(replace(lower(p), ".", "\\."), "*", ".*"), "?", ".")}$", lower(r.action)))]) : !anytrue([for p in flatten([x.s.NotAction]) : can(regex("^${replace(replace(replace(lower(p), ".", "\\."), "*", ".*"), "?", ".")}$", lower(r.action)))])) &&
            (can(x.s.Resource) ? anytrue([for p in flatten([x.s.Resource]) : can(regex("^${replace(replace(replace(p, ".", "\\."), "*", ".*"), "?", ".")}$", r.resource))]) : !anytrue([for p in flatten([x.s.NotResource]) : can(regex("^${replace(replace(replace(p, ".", "\\."), "*", ".*"), "?", ".")}$", r.resource))])) &&
            alltrue([
              for operator, entries in try(x.s.Condition, {}) : alltrue([
                for key, want in entries : alltrue([
                  for b in [{ present = contains(keys(r.context), key), vals = try(r.context[key], []), wants = flatten([want]) }] : alltrue([
                    for m in [{ eq = anytrue([for v in b.vals : contains(b.wants, v)]), like = anytrue([for v in b.vals : anytrue([for w in b.wants : can(regex("^${replace(replace(replace(w, ".", "\\."), "*", ".*"), "?", ".")}$", v))])]) }] :
                    operator == "StringEquals" || operator == "Bool" || operator == "ForAnyValue:StringEquals" ? (b.present && m.eq) :
                    operator == "StringNotEquals" || operator == "ForAllValues:StringNotEquals" ? (!b.present || !m.eq) :
                    operator == "StringEqualsIfExists" ? (!b.present || m.eq) :
                    operator == "StringNotEqualsIfExists" ? (!b.present || !m.eq) :
                    operator == "StringLike" || operator == "ArnEquals" || operator == "ArnLike" ? (b.present && m.like) :
                    operator == "ArnLikeIfExists" ? (!b.present || m.like) :
                    operator == "ArnNotEquals" || operator == "ArnNotLike" ? (!b.present || !m.like) :
                    operator == "Null" ? ((b.wants[0] == "true") != b.present) : false
                  ])
                ])
              ])
            ])
          )
        ]] :
        contains(effects, "identity:Allow") && contains(effects, "boundary:Allow") && !contains(effects, "identity:Deny") && !contains(effects, "boundary:Deny")
      ])
    ])
    error_message = "artifact-publish cannot push to the release repository, read back what it pushed, or create and read back its records through S3."
  }

  assert {
    condition = !anytrue([
      for r in [
        { action = "ecr:BatchDeleteImage", resource = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane", context = {} },
        { action = "ecr:PutImageTagMutability", resource = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane", context = {} },
        { action = "ecr:PutImage", resource = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch-staging", context = {} },
        { action = "s3:PutObject", resource = "arn:aws:s3:::synthetic-firmbatch-plans/plans/staging/x.tfplan", context = {} },
        { action = "s3:DeleteObject", resource = "arn:aws:s3:::synthetic-firmbatch-releases/releases/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/release-manifest.json", context = {} },
        { action = "s3:GetObject", resource = "arn:aws:s3:::synthetic-firmbatch-state/staging/terraform.tfstate", context = {} },
        { action = "kms:Decrypt", resource = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-000000000000", context = {} },
        { action = "kms:Encrypt", resource = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-000000000000", context = { "kms:ViaService" = ["ecr.eu-central-1.amazonaws.com"] } },
        { action = "iam:PassRole", resource = "arn:aws:iam::111111111111:role/firmbatch-staging-web-api-task", context = { "iam:PassedToService" = ["ecs-tasks.amazonaws.com"] } },
        { action = "sts:AssumeRole", resource = "arn:aws:iam::111111111111:role/firmbatch-staging-github-apply", context = {} },
        { action = "ecs:UpdateService", resource = "arn:aws:ecs:eu-central-1:111111111111:service/firmbatch-staging/firmbatch-staging-web-api", context = {} },
        { action = "secretsmanager:GetSecretValue", resource = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/application-database-url", context = {} },
      ] :
      anytrue([
        for effects in [[
          for x in concat(
            [for s in jsondecode(aws_iam_role_policy.artifact_publish.policy).Statement : { w = "identity", s = s }],
            [for s in jsondecode(aws_iam_policy.artifact_publish_boundary.policy).Statement : { w = "boundary", s = s }],
          ) : "${x.w}:${x.s.Effect}"
          if(
            (can(x.s.Action) ? anytrue([for p in flatten([x.s.Action]) : can(regex("^${replace(replace(replace(lower(p), ".", "\\."), "*", ".*"), "?", ".")}$", lower(r.action)))]) : !anytrue([for p in flatten([x.s.NotAction]) : can(regex("^${replace(replace(replace(lower(p), ".", "\\."), "*", ".*"), "?", ".")}$", lower(r.action)))])) &&
            (can(x.s.Resource) ? anytrue([for p in flatten([x.s.Resource]) : can(regex("^${replace(replace(replace(p, ".", "\\."), "*", ".*"), "?", ".")}$", r.resource))]) : !anytrue([for p in flatten([x.s.NotResource]) : can(regex("^${replace(replace(replace(p, ".", "\\."), "*", ".*"), "?", ".")}$", r.resource))])) &&
            alltrue([
              for operator, entries in try(x.s.Condition, {}) : alltrue([
                for key, want in entries : alltrue([
                  for b in [{ present = contains(keys(r.context), key), vals = try(r.context[key], []), wants = flatten([want]) }] : alltrue([
                    for m in [{ eq = anytrue([for v in b.vals : contains(b.wants, v)]), like = anytrue([for v in b.vals : anytrue([for w in b.wants : can(regex("^${replace(replace(replace(w, ".", "\\."), "*", ".*"), "?", ".")}$", v))])]) }] :
                    operator == "StringEquals" || operator == "Bool" || operator == "ForAnyValue:StringEquals" ? (b.present && m.eq) :
                    operator == "StringNotEquals" || operator == "ForAllValues:StringNotEquals" ? (!b.present || !m.eq) :
                    operator == "StringEqualsIfExists" ? (!b.present || m.eq) :
                    operator == "StringNotEqualsIfExists" ? (!b.present || !m.eq) :
                    operator == "StringLike" || operator == "ArnEquals" || operator == "ArnLike" ? (b.present && m.like) :
                    operator == "ArnLikeIfExists" ? (!b.present || m.like) :
                    operator == "ArnNotEquals" || operator == "ArnNotLike" ? (!b.present || !m.like) :
                    operator == "Null" ? ((b.wants[0] == "true") != b.present) : false
                  ])
                ])
              ])
            ])
          )
        ]] :
        contains(effects, "identity:Allow") && contains(effects, "boundary:Allow") && !contains(effects, "identity:Deny") && !contains(effects, "boundary:Deny")
      ])
    ])
    error_message = "artifact-publish can delete or re-tag an image, push elsewhere, touch plans, state or a record's retention, use the key outside S3, pass or assume a role, deploy or read a secret."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_kms_key.release.policy).Statement :
      try(
        statement.Sid == "NoPipelineRoleChangesThisKey" && statement.Effect == "Deny" &&
        contains(statement.Action, "kms:PutKeyPolicy") && contains(statement.Action, "kms:CreateGrant") &&
        contains(statement.Condition.ArnLike["aws:PrincipalArn"], "arn:aws:iam::111111111111:role/firmbatch-artifact-publish"),
        false
      )
    ])
    error_message = "No pipeline role changes the release key or takes a grant on it."
  }
}

run "plan_retention_below_one_day_is_refused" {
  command = plan

  variables {
    plan_retention_days = 0
  }

  expect_failures = [var.plan_retention_days]
}

run "plan_retention_beyond_seven_days_is_refused" {
  command = plan

  variables {
    plan_retention_days = 8
  }

  expect_failures = [var.plan_retention_days]
}

run "state_and_plans_never_share_a_bucket" {
  command = plan

  variables {
    plan_bucket_name = "synthetic-firmbatch-state"
  }

  expect_failures = [var.plan_bucket_name]
}

run "release_records_never_share_a_bucket_with_plans" {
  command = plan

  variables {
    release_bucket_name = "synthetic-firmbatch-plans"
  }

  expect_failures = [var.release_bucket_name]
}

run "an_environment_named_release_identity_is_refused" {
  command = plan

  variables {
    release_name_prefix = "firmbatch-staging"
  }

  expect_failures = [var.release_name_prefix]
}

run "a_malformed_account_id_is_refused" {
  command = plan

  variables {
    expected_account_id = "11111"
  }

  # Terraform does not evaluate artifact_registry_account_id's rules while a variable one of them names is
  # itself invalid, so this run expects exactly the malformed variable's own failure.
  expect_failures = [var.expected_account_id]
}

run "credentials_for_another_account_are_refused" {
  command = plan

  variables {
    expected_account_id          = "222222222222"
    artifact_registry_account_id = "222222222222"
  }

  expect_failures = [data.aws_caller_identity.current]
}

# The registry is declared, never derived. This root creates the artifact-publish identity and the release
# key beside the registry, so a registry declared anywhere else is refused before anything is planned --
# never silently re-pointed at this account or region.
run "a_registry_declared_in_another_account_is_refused_by_this_root" {
  command = plan

  variables {
    artifact_registry_account_id = "333333333333"
  }

  expect_failures = [var.artifact_registry_account_id]
}

run "a_registry_declared_in_another_region_is_refused_by_this_root" {
  command = plan

  variables {
    artifact_registry_region = "eu-west-1"
  }

  expect_failures = [var.artifact_registry_region]
}

run "every_release_arn_names_the_declared_registry" {
  command = plan

  assert {
    condition     = output.artifact_registry.repository_url == "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane"
    error_message = "The declared registry output must name exactly the declared account, region and repository."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(aws_iam_role_policy.github_apply.policy).Statement :
      try(s.Sid != "ReverifyTheReleaseByDigest" || s.Resource == "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane", false)
    ])
    error_message = "The apply role's release re-verification names the declared registry's repository."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(aws_iam_role_policy.artifact_publish.policy).Statement :
      try(s.Sid != "ReleaseRecordEncryptionThroughS3Only" || s.Condition.StringEquals["kms:ViaService"] == "s3.eu-central-1.amazonaws.com", false)
    ])
    error_message = "artifact-publish uses the release key only through S3 in the declared registry region."
  }
}

# The plan role under its boundary: planning still works, and a side door -- any policy attached to the role
# beside its own, here one granting every action -- still cannot read a secret value or a parameter, decrypt
# with another key or the release key outside S3, read a saved plan or write state. The mock gives every KMS
# key one ARN, so each request for a key the plan role uses names the S3 service it is made through.
run "the_plan_boundary_admits_planning_and_refuses_a_side_door" {
  command = plan

  assert {
    condition = alltrue([
      for r in [
        { action = "s3:GetObject", resource = "arn:aws:s3:::synthetic-firmbatch-state/staging/terraform.tfstate", context = {} },
        { action = "s3:PutObject", resource = "arn:aws:s3:::synthetic-firmbatch-state/staging/terraform.tfstate.tflock", context = {} },
        { action = "s3:PutObject", resource = "arn:aws:s3:::synthetic-firmbatch-plans/plans/staging/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.tfplan", context = {} },
        { action = "kms:GenerateDataKey", resource = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-000000000000", context = { "kms:ViaService" = ["s3.eu-central-1.amazonaws.com"] } },
        { action = "kms:Decrypt", resource = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-000000000000", context = { "kms:ViaService" = ["s3.eu-central-1.amazonaws.com"] } },
        { action = "ec2:DescribeVpcs", resource = "*", context = {} },
        { action = "secretsmanager:DescribeSecret", resource = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/application-database-url", context = {} },
        { action = "ecr:DescribeImages", resource = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane", context = {} },
        { action = "s3:GetObject", resource = "arn:aws:s3:::synthetic-firmbatch-releases/releases/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/release-manifest.json", context = {} },
        { action = "sts:GetCallerIdentity", resource = "*", context = {} },
      ] :
      alltrue([
        for effects in [[
          for x in concat(
            [for s in jsondecode(aws_iam_role_policy.github_plan.policy).Statement : { w = "identity", s = s }],
            [for s in jsondecode(aws_iam_policy.plan_boundary.policy).Statement : { w = "boundary", s = s }],
          ) : "${x.w}:${x.s.Effect}"
          if(
            (can(x.s.Action) ? anytrue([for p in flatten([x.s.Action]) : can(regex("^${replace(replace(replace(lower(p), ".", "\\."), "*", ".*"), "?", ".")}$", lower(r.action)))]) : !anytrue([for p in flatten([x.s.NotAction]) : can(regex("^${replace(replace(replace(lower(p), ".", "\\."), "*", ".*"), "?", ".")}$", lower(r.action)))])) &&
            (can(x.s.Resource) ? anytrue([for p in flatten([x.s.Resource]) : can(regex("^${replace(replace(replace(p, ".", "\\."), "*", ".*"), "?", ".")}$", r.resource))]) : !anytrue([for p in flatten([x.s.NotResource]) : can(regex("^${replace(replace(replace(p, ".", "\\."), "*", ".*"), "?", ".")}$", r.resource))])) &&
            alltrue([
              for operator, entries in try(x.s.Condition, {}) : alltrue([
                for key, want in entries : alltrue([
                  for b in [{ present = contains(keys(r.context), key), vals = try(r.context[key], []), wants = flatten([want]) }] : alltrue([
                    for m in [{ eq = anytrue([for v in b.vals : contains(b.wants, v)]), like = anytrue([for v in b.vals : anytrue([for w in b.wants : can(regex("^${replace(replace(replace(w, ".", "\\."), "*", ".*"), "?", ".")}$", v))])]) }] :
                    operator == "StringEquals" || operator == "Bool" || operator == "ForAnyValue:StringEquals" ? (b.present && m.eq) :
                    operator == "StringNotEquals" || operator == "ForAllValues:StringNotEquals" ? (!b.present || !m.eq) :
                    operator == "StringEqualsIfExists" ? (!b.present || m.eq) :
                    operator == "StringNotEqualsIfExists" ? (!b.present || !m.eq) :
                    operator == "StringLike" || operator == "ArnEquals" || operator == "ArnLike" ? (b.present && m.like) :
                    operator == "ArnLikeIfExists" ? (!b.present || m.like) :
                    operator == "ArnNotEquals" || operator == "ArnNotLike" ? (!b.present || !m.like) :
                    operator == "Null" ? ((b.wants[0] == "true") != b.present) : false
                  ])
                ])
              ])
            ])
          )
        ]] :
        contains(effects, "identity:Allow") && contains(effects, "boundary:Allow") && !contains(effects, "identity:Deny") && !contains(effects, "boundary:Deny")
      ])
    ])
    error_message = "Under its boundary the plan role must still read state, take its lockfile, write a new saved plan, refresh and verify a release."
  }

  assert {
    condition = !anytrue([
      for r in [
        { action = "secretsmanager:GetSecretValue", resource = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/application-database-url", context = {} },
        { action = "secretsmanager:BatchGetSecretValue", resource = "*", context = {} },
        { action = "ssm:GetParameter", resource = "arn:aws:ssm:eu-central-1:111111111111:parameter/firmbatch-staging/database-url", context = {} },
        { action = "kms:Decrypt", resource = "arn:aws:kms:eu-central-1:111111111111:key/ffffffff-ffff-4fff-8fff-ffffffffffff", context = { "kms:ViaService" = ["s3.eu-central-1.amazonaws.com"] } },
        { action = "kms:Decrypt", resource = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-000000000000", context = {} },
        { action = "s3:GetObject", resource = "arn:aws:s3:::synthetic-firmbatch-plans/plans/staging/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.tfplan", context = {} },
        { action = "s3:PutObject", resource = "arn:aws:s3:::synthetic-firmbatch-state/staging/terraform.tfstate", context = {} },
      ] :
      anytrue([
        for effects in [[
          for x in concat(
            [for s in jsondecode(aws_iam_role_policy.github_plan.policy).Statement : { w = "identity", s = s }],
            [{ w = "identity", s = { Sid = "SideDoor", Effect = "Allow", Action = "*", Resource = "*" } }],
            [for s in jsondecode(aws_iam_policy.plan_boundary.policy).Statement : { w = "boundary", s = s }],
          ) : "${x.w}:${x.s.Effect}"
          if(
            (can(x.s.Action) ? anytrue([for p in flatten([x.s.Action]) : can(regex("^${replace(replace(replace(lower(p), ".", "\\."), "*", ".*"), "?", ".")}$", lower(r.action)))]) : !anytrue([for p in flatten([x.s.NotAction]) : can(regex("^${replace(replace(replace(lower(p), ".", "\\."), "*", ".*"), "?", ".")}$", lower(r.action)))])) &&
            (can(x.s.Resource) ? anytrue([for p in flatten([x.s.Resource]) : can(regex("^${replace(replace(replace(p, ".", "\\."), "*", ".*"), "?", ".")}$", r.resource))]) : !anytrue([for p in flatten([x.s.NotResource]) : can(regex("^${replace(replace(replace(p, ".", "\\."), "*", ".*"), "?", ".")}$", r.resource))])) &&
            alltrue([
              for operator, entries in try(x.s.Condition, {}) : alltrue([
                for key, want in entries : alltrue([
                  for b in [{ present = contains(keys(r.context), key), vals = try(r.context[key], []), wants = flatten([want]) }] : alltrue([
                    for m in [{ eq = anytrue([for v in b.vals : contains(b.wants, v)]), like = anytrue([for v in b.vals : anytrue([for w in b.wants : can(regex("^${replace(replace(replace(w, ".", "\\."), "*", ".*"), "?", ".")}$", v))])]) }] :
                    operator == "StringEquals" || operator == "Bool" || operator == "ForAnyValue:StringEquals" ? (b.present && m.eq) :
                    operator == "StringNotEquals" || operator == "ForAllValues:StringNotEquals" ? (!b.present || !m.eq) :
                    operator == "StringEqualsIfExists" ? (!b.present || m.eq) :
                    operator == "StringNotEqualsIfExists" ? (!b.present || !m.eq) :
                    operator == "StringLike" || operator == "ArnEquals" || operator == "ArnLike" ? (b.present && m.like) :
                    operator == "ArnLikeIfExists" ? (!b.present || m.like) :
                    operator == "ArnNotEquals" || operator == "ArnNotLike" ? (!b.present || !m.like) :
                    operator == "Null" ? ((b.wants[0] == "true") != b.present) : false
                  ])
                ])
              ])
            ])
          )
        ]] :
        contains(effects, "identity:Allow") && contains(effects, "boundary:Allow") && !contains(effects, "identity:Deny") && !contains(effects, "boundary:Deny")
      ])
    ])
    error_message = "Even with a side-door policy granting every action, the plan boundary must refuse secret values, parameters, other keys, the release key outside S3, saved-plan reads and state writes."
  }
}
