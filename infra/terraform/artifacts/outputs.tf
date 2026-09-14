# Identifiers only. The staging root takes them as explicit input variables, and the
# artifact-publish, staging-plan and staging-apply environments carry them as configuration
# variables. The release key and the artifact-publish role are the bootstrap root's outputs.

output "release_repository_url" {
  value = aws_ecr_repository.release.repository_url
}

output "release_repository_arn" {
  value = aws_ecr_repository.release.arn
}

output "release_registry_account_id" {
  value = local.account_id
}

output "release_registry_region" {
  value = var.region
}

output "release_bucket_name" {
  value = aws_s3_bucket.releases.bucket
}
