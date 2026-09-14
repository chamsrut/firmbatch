output "alb_arn_suffix" {
  value = aws_lb.this.arn_suffix
}

output "alb_dns_name" {
  value = aws_lb.this.dns_name
}

output "target_group_arns" {
  description = "Keyed web_api and identity_broker."
  value       = { for key, group in aws_lb_target_group.service : key => group.arn }
}

output "target_group_arn_suffixes" {
  value = { for key, group in aws_lb_target_group.service : key => group.arn_suffix }
}

output "https_listener_arn" {
  value = aws_lb_listener.https.arn
}
