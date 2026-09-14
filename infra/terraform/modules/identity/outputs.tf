# Identifiers only. The app client's secret is deliberately not an output: it is in state,
# which is why state and saved plans are equally sensitive (ADR 0011 decision 7).

output "user_pool_id" {
  value = aws_cognito_user_pool.this.id
}

output "user_pool_arn" {
  value = aws_cognito_user_pool.this.arn
}

output "app_client_id" {
  value = aws_cognito_user_pool_client.broker.id
}

output "issuer" {
  description = "The exact issuer the broker validates, and half of every (issuer, subject) identity."
  value       = "https://cognito-idp.${split(":", aws_cognito_user_pool.this.arn)[3]}.amazonaws.com/${aws_cognito_user_pool.this.id}"
}

output "web_acl_arn" {
  value = aws_wafv2_web_acl.cognito.arn
}
