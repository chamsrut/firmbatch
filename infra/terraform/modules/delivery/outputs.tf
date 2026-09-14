output "workload_permissions_boundary_arn" {
  value = aws_iam_policy.workload_boundary.arn
}

output "operator_identity_binding_policy_arn" {
  value = aws_iam_policy.operator_identity_binding.arn
}
