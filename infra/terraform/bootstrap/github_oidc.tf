# The GitHub Actions OIDC provider and every identity it federates: the staging plan and apply
# roles and the artifact-publish role (ADR 0012 decisions 1, 5, 12 and 13).
#
# HUMAN-APPLIED, like everything in this root, and created FIRST: the bootstrap root creates the
# state and plan storage, the OIDC provider and these delivery identities; the artifacts root then
# names the already-existing roles in its repository and bucket policies; the human's first staging
# apply follows; ordinary changes use the protected pipeline afterwards. Nothing any later root or
# pipeline applies depends on an identity that does not exist yet, and no resource policy anywhere
# names a principal before this root has created it.
#
# No pipeline role can create, change or delete anything here: the apply boundary admits no IAM
# action but reads and passing the ten pre-created workload roles to ECS tasks, and
# `delivery.py plan-summary --mode apply` refuses a saved plan that changes an IAM resource.
#
# The trust names the environment, not the ref: GitHub's default subject for an environment job is
# repo:<owner>/<name>:environment:<environment>, and IAM sees no other claim of it. The ref is bound
# by each environment's main-only deployment branch policy, which every workflow's preflight
# verifies through the GitHub API before any job references the environment. No permanent AWS
# access key exists anywhere.

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]

  lifecycle {
    prevent_destroy = true
  }
}

locals {
  trust_policy = {
    for environment in [local.plan_environment, local.apply_environment, local.publish_environment] : environment => jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Sid       = "GitHubOidcExactRepositoryAndEnvironment"
        Effect    = "Allow"
        Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
        Action    = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${local.oidc_host}:aud" = "sts.amazonaws.com"
            "${local.oidc_host}:sub" = "repo:${local.github_repository}:environment:${environment}"
          }
        }
      }]
    })
  }
}

resource "aws_iam_role" "github_plan" {
  name                 = local.plan_role_name
  description          = "GitHub staging-plan environment only: read state, take the lockfile, verify a release by digest, create new saved-plan objects, under its permissions boundary. Cannot apply, push, deploy or read a secret value."
  assume_role_policy   = local.trust_policy[local.plan_environment]
  permissions_boundary = aws_iam_policy.plan_boundary.arn
  max_session_duration = 3600
}

resource "aws_iam_role" "github_apply" {
  name                 = local.apply_role_name
  description          = "GitHub staging-apply environment only: re-verify the release and apply one approved saved plan, under its permissions boundary."
  assume_role_policy   = local.trust_policy[local.apply_environment]
  permissions_boundary = aws_iam_policy.apply_boundary.arn
  max_session_duration = 7200
}

resource "aws_iam_role" "artifact_publish" {
  name                 = local.publish_role_name
  description          = "GitHub artifact-publish environment only: push one immutable release image and create or resume its release records. Cannot plan, apply, deploy or pass a role."
  assume_role_policy   = local.trust_policy[local.publish_environment]
  permissions_boundary = aws_iam_policy.artifact_publish_boundary.arn
  max_session_duration = 3600
}
