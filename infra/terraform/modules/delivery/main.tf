# The staging environment's workload permissions boundary and the operator's identity-binding run
# permission (ADR 0011 decisions 5 and 8; ADR 0012 decision 5).
#
# THE GITHUB DELIVERY IDENTITIES ARE NOT HERE. The staging plan and apply roles, the artifact-publish
# role, their trust policies, permission policies and boundaries are the bootstrap root's, created
# before the artifacts root and before this environment exists (infra/terraform/bootstrap). This
# module keeps the environment-scoped IAM the staging root's first, human apply creates: the boundary
# every ECS execution and task role carries, and the policy an operator's SSO permission set attaches
# to run the identity-binding task. Both are trust configuration, and so a human's: the apply
# boundary admits no IAM change, and `delivery.py plan-summary --mode apply` refuses a saved plan
# that changes any IAM resource before anything is applied.

locals {
  workload_boundary_name = "${var.name_prefix}-workload-boundary"

  state_bucket_arn = "arn:aws:s3:::${var.state_bucket_name}"
  plan_bucket_arn  = "arn:aws:s3:::${var.plan_bucket_name}"

  cluster_arn = "arn:aws:ecs:${var.region}:${var.account_id}:cluster/${var.cluster_name}"

  identity_binding_family = "${var.name_prefix}-identity-binding"
  identity_binding_role_arns = [
    "arn:aws:iam::${var.account_id}:role/${local.identity_binding_family}-execution",
    "arn:aws:iam::${var.account_id}:role/${local.identity_binding_family}-task",
  ]

  # The canonical release registry, in the artifacts root.
  release_repository_arn = "arn:aws:ecr:${var.release_registry_region}:${var.release_registry_account_id}:repository/${var.release_repository_name}"
}
