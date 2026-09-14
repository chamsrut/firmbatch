# Identifiers only. None of these is a secret; the artifacts and staging roots take them as
# explicit input variables rather than reading this root's state.

output "state_bucket_name" {
  value = aws_s3_bucket.state.bucket
}

output "state_kms_key_arn" {
  value = aws_kms_key.state.arn
}

output "plan_bucket_name" {
  value = aws_s3_bucket.plans.bucket
}

output "plan_kms_key_arn" {
  value = aws_kms_key.plans.arn
}

output "plan_object_prefix" {
  value = local.plan_object_prefix
}

output "plan_retention_days" {
  value = var.plan_retention_days
}

output "release_kms_key_arn" {
  value = aws_kms_key.release.arn
}

output "artifact_registry" {
  description = "The declared canonical registry these identities name: the artifacts root's expected_account_id, region, repository_name and release_bucket_name, the staging root's release_registry_* inputs and every environment's ARTIFACT_* variables must equal these values."
  value = {
    account_id          = var.artifact_registry_account_id
    region              = var.artifact_registry_region
    repository_name     = var.release_repository_name
    repository_url      = "${var.artifact_registry_account_id}.dkr.ecr.${var.artifact_registry_region}.amazonaws.com/${var.release_repository_name}"
    release_bucket_name = var.release_bucket_name
  }
}

output "github_oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.github.arn
}

output "github_plan_role_arn" {
  value = aws_iam_role.github_plan.arn
}

output "github_apply_role_arn" {
  value = aws_iam_role.github_apply.arn
}

output "artifact_publish_role_arn" {
  value = aws_iam_role.artifact_publish.arn
}

output "workload_role_arns" {
  description = "The only roles the apply role may pass, and only to ecs-tasks.amazonaws.com. The staging root's first apply creates them."
  value       = local.workload_role_arns
}
