output "cluster_arn" {
  value = aws_ecs_cluster.this.arn
}

output "task_definition_families" {
  value = { for key, definition in aws_ecs_task_definition.this : key => definition.family }
}

output "execution_role_arns" {
  value = { for key, role in aws_iam_role.execution : key => role.arn }
}

output "task_role_arns" {
  value = { for key, role in aws_iam_role.task : key => role.arn }
}
