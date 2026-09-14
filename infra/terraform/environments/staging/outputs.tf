# Identifiers only; nothing here is a credential. Marking an output `sensitive` would hide it
# from plan output and would NOT remove it from state or from a saved plan -- state holds the
# Cognito client secret whatever is output, which is why state and saved plans are equally
# sensitive (ADR 0011 decision 7). The GitHub delivery roles are the bootstrap root's outputs.

output "app_origin" {
  value = local.app_origin
}

output "alb_dns_name" {
  value = module.edge.alb_dns_name
}

output "approved_release_repository_url" {
  value = local.release_repository_url
}

output "operator_identity_binding_policy_arn" {
  value = module.delivery.operator_identity_binding_policy_arn
}

output "cognito_user_pool_id" {
  value = module.identity.user_pool_id
}

output "cognito_issuer" {
  value = module.identity.issuer
}

output "task_definition_families" {
  value = module.compute.task_definition_families
}
