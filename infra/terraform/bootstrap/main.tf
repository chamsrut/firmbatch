locals {
  account_id = data.aws_caller_identity.current.account_id

  state_bucket_arn = "arn:aws:s3:::${var.state_bucket_name}"
  plan_bucket_arn  = "arn:aws:s3:::${var.plan_bucket_name}"

  # Saved plans live under this prefix only, as content-addressed objects:
  #   plans/<environment>/<40-hex source commit>/<64-hex plan SHA-256>.tfplan
  plan_object_prefix = "plans/"

  # ------------------------------------------------------------------ the delivery identities
  #
  # Fixed by ADR 0011 decision 9.1, not deployment parameters: the one repository and the three
  # environment names the OIDC trust policies name exactly.
  github_repository   = "chamsrut/firmbatch"
  oidc_host           = "token.actions.githubusercontent.com"
  plan_environment    = "${var.environment}-plan"
  apply_environment   = "${var.environment}-apply"
  publish_environment = "artifact-publish"

  github_role_name_prefix = "${var.name_prefix}-github-"
  plan_role_name          = "${local.github_role_name_prefix}plan"
  apply_role_name         = "${local.github_role_name_prefix}apply"
  apply_boundary_name     = "${local.github_role_name_prefix}apply-boundary"
  plan_boundary_name      = "${local.github_role_name_prefix}plan-boundary"
  publish_role_name       = "${var.release_name_prefix}-artifact-publish"
  publish_boundary_name   = "${var.release_name_prefix}-artifact-publish-boundary"

  github_role_arn_pattern = "arn:aws:iam::${local.account_id}:role/${local.github_role_name_prefix}*"
  github_plan_role_arn    = "arn:aws:iam::${local.account_id}:role/${local.plan_role_name}"
  github_apply_role_arn   = "arn:aws:iam::${local.account_id}:role/${local.apply_role_name}"
  publish_role_arn        = "arn:aws:iam::${local.account_id}:role/${local.publish_role_name}"

  # The staging root the deployment identities serve. Its state key and plan prefix, and the names
  # below, must equal what that root derives; infra/terraform/policy/check.py compares them.
  state_key               = "${var.environment}/terraform.tfstate"
  environment_plan_prefix = "${local.plan_object_prefix}${var.environment}/"
  state_object_arn        = "${local.state_bucket_arn}/${local.state_key}"
  lock_object_arn         = "${local.state_bucket_arn}/${local.state_key}.tflock"
  environment_plans_arn   = "${local.plan_bucket_arn}/${local.environment_plan_prefix}*"
  cluster_name            = var.name_prefix
  cluster_arn             = "arn:aws:ecs:${var.region}:${local.account_id}:cluster/${local.cluster_name}"

  # The ECS delivery contract the apply role works inside: exactly these task-definition families,
  # these two services -- each paired with its own family -- and these pre-created execution and
  # task roles. The staging root's compute module creates the roles on the first, human, apply;
  # afterwards the apply role may pass them and nothing more.
  workload_families = ["bootstrap", "identity-binding", "identity-broker", "migrate", "web-api"]
  service_families = {
    web_api         = "web-api"
    identity_broker = "identity-broker"
  }
  workload_role_arns = sort(flatten([
    for family in local.workload_families : [
      "arn:aws:iam::${local.account_id}:role/${var.name_prefix}-${family}-execution",
      "arn:aws:iam::${local.account_id}:role/${var.name_prefix}-${family}-task",
    ]
  ]))
  task_definition_arns = sort([
    for family in local.workload_families : "arn:aws:ecs:${var.region}:${local.account_id}:task-definition/${var.name_prefix}-${family}:*"
  ])
  service_arns = {
    for key, family in local.service_families : key => "arn:aws:ecs:${var.region}:${local.account_id}:service/${local.cluster_name}/${var.name_prefix}-${family}"
  }
  service_arn_list = sort(values(local.service_arns))
  service_task_definition_arns = {
    for key, family in local.service_families : key => "arn:aws:ecs:${var.region}:${local.account_id}:task-definition/${var.name_prefix}-${family}:*"
  }

  # The release registry the artifacts root creates later, in the DECLARED artifact registry account
  # and region -- never derived from this root's own account or region. Identity policies may name
  # these predictable ARNs before the resources exist; no resource policy names an identity before this
  # root has created it.
  release_repository_arn       = "arn:aws:ecr:${var.artifact_registry_region}:${var.artifact_registry_account_id}:repository/${var.release_repository_name}"
  release_bucket_arn           = "arn:aws:s3:::${var.release_bucket_name}"
  release_objects_arn          = "${local.release_bucket_arn}/releases/*"
  release_manifest_objects_arn = "${local.release_bucket_arn}/releases/*/release-manifest.json"

  # The account root principal delegates key use to IAM policies; no pipeline role is named in
  # a key policy, so none can grant itself more through one.
  account_administration_statement = {
    Sid       = "AccountAdministrationThroughIam"
    Effect    = "Allow"
    Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
    Action    = "kms:*"
    Resource  = "*"
  }

  deny_insecure_transport = {
    state = {
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [local.state_bucket_arn, "${local.state_bucket_arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }
    plans = {
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [local.plan_bucket_arn, "${local.plan_bucket_arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }
  }
}

# ------------------------------------------------------------------------------ KMS keys

resource "aws_kms_key" "state" {
  description             = "${var.name_prefix} Terraform state. State holds the Cognito client secret; treat it as sensitive."
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [local.account_administration_statement]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "state" {
  name          = "alias/${var.name_prefix}-terraform-state"
  target_key_id = aws_kms_key.state.key_id
}

resource "aws_kms_key" "plans" {
  description             = "${var.name_prefix} saved Terraform plans. A saved plan carries prior state; as sensitive as state."
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [local.account_administration_statement]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "plans" {
  name          = "alias/${var.name_prefix}-terraform-plans"
  target_key_id = aws_kms_key.plans.key_id
}

# The release key: release images (through ECR's own grant) and release records (through S3). It
# is created here, with the identities that use it, so every identity policy names the exact key
# rather than a pattern; the artifacts root takes its ARN as an input.
#
# No consumer grant is needed for ECR: the repository's encryption grant decrypts layers for
# every pull, in this account and any other the repository policy admits. A release-record reader
# in another account would need an explicit statement here -- a later, reviewed human change.
resource "aws_kms_key" "release" {
  description             = "${var.release_name_prefix} release images and release records"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      local.account_administration_statement,
      {
        Sid       = "NoPipelineRoleChangesThisKey"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = ["kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:RevokeGrant", "kms:RetireGrant", "kms:CreateGrant", "kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias"]
        Resource  = "*"
        Condition = { ArnLike = { "aws:PrincipalArn" = [local.github_role_arn_pattern, local.publish_role_arn] } }
      },
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "release" {
  name          = "alias/${var.release_name_prefix}-release"
  target_key_id = aws_kms_key.release.key_id
}
