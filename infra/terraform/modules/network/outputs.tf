output "vpc_id" {
  value = aws_vpc.this.id
}

output "public_subnet_ids" {
  value = [for key in sort(keys(aws_subnet.public)) : aws_subnet.public[key].id]
}

output "private_subnet_ids" {
  value = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
}

output "database_subnet_ids" {
  value = [for key in sort(keys(aws_subnet.database)) : aws_subnet.database[key].id]
}

output "alb_security_group_id" {
  value = aws_security_group.alb.id
}

output "task_security_group_ids" {
  description = "Security group per service and one-off task, keyed web_api, identity_broker, migrate, bootstrap, identity_binding."
  value       = { for key, group in aws_security_group.task : key => group.id }
}

output "database_security_group_id" {
  value = aws_security_group.database.id
}

output "nat_egress_cidr" {
  description = "The NAT gateway's fixed Elastic IP as a /32. The Cognito WAF admits it separately; it never enters the ALB allow-list."
  value       = "${aws_eip.nat.public_ip}/32"
}
