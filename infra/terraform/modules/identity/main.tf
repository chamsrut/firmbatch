# Cognito authenticates; Firmbatch authorizes (ADR 0011 decision 4; topology §6.1).
#
# One invite-only user pool with required TOTP, Managed Login v2 at a custom domain whose
# certificate is in us-east-1, one confidential app client using the authorization-code grant
# with exact URLs and `openid email` only, and a Cognito-associated WAF.
#
# Deliberately absent: Identity Pools, user groups, social identity providers, ALB
# authenticate-cognito, and any Cognito user. Users are never created by Terraform, whose state
# and plans would then hold their email addresses and temporary passwords.
#
# PKCE (S256) is not a user-pool setting. Cognito accepts code_challenge on any client; the
# identity broker (M3.3c) is what sends it on every authorization request.
#
# The client secret generated below is in Terraform state -- the one acknowledged exception
# (ADR 0011 decision 7). It is never an output, and `sensitive` would not remove it from state
# or from a saved plan in any case.

resource "aws_cognito_user_pool" "this" {
  name                = "${var.name_prefix}-customers"
  user_pool_tier      = "ESSENTIALS"
  deletion_protection = "ACTIVE"

  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  username_configuration {
    case_sensitive = false
  }

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  mfa_configuration = "ON"

  software_token_mfa_configuration {
    enabled = true
  }

  password_policy {
    minimum_length                   = 14
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 3
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  user_attribute_update_settings {
    attributes_require_verification_before_update = ["email"]
  }

  email_configuration {
    email_sending_account = "DEVELOPER"
    source_arn            = var.ses_identity_arn
    from_email_address    = var.from_email_address
  }
}

# ------------------------------------------------------------------ custom domain

resource "aws_acm_certificate" "auth" {
  provider = aws.us_east_1

  domain_name       = var.auth_hostname
  validation_method = "DNS"
  key_algorithm     = "RSA_2048"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "auth_certificate_validation" {
  for_each = {
    for option in aws_acm_certificate.auth.domain_validation_options : option.domain_name => option
  }

  zone_id         = var.route53_zone_id
  name            = each.value.resource_record_name
  type            = each.value.resource_record_type
  records         = [each.value.resource_record_value]
  ttl             = 300
  allow_overwrite = false
}

resource "aws_acm_certificate_validation" "auth" {
  provider = aws.us_east_1

  certificate_arn         = aws_acm_certificate.auth.arn
  validation_record_fqdns = [for record in aws_route53_record.auth_certificate_validation : record.fqdn]
}

resource "aws_cognito_user_pool_domain" "this" {
  domain                = var.auth_hostname
  user_pool_id          = aws_cognito_user_pool.this.id
  certificate_arn       = aws_acm_certificate_validation.auth.certificate_arn
  managed_login_version = 2
}

resource "aws_route53_record" "auth" {
  zone_id = var.route53_zone_id
  name    = var.auth_hostname
  type    = "A"

  alias {
    name                   = aws_cognito_user_pool_domain.this.cloudfront_distribution
    zone_id                = aws_cognito_user_pool_domain.this.cloudfront_distribution_zone_id
    evaluate_target_health = false
  }
}

# ------------------------------------------------------------------ app client

resource "aws_cognito_user_pool_client" "broker" {
  name         = "${var.name_prefix}-identity-broker"
  user_pool_id = aws_cognito_user_pool.this.id

  generate_secret = true

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email"]
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = [var.callback_url]
  default_redirect_uri                 = var.callback_url
  logout_urls                          = [var.logout_url]

  prevent_user_existence_errors = "ENABLED"
  enable_token_revocation       = true
  read_attributes               = ["email", "email_verified"]

  access_token_validity  = 5
  id_token_validity      = 5
  refresh_token_validity = 8
  auth_session_validity  = 3

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "hours"
  }

  refresh_token_rotation {
    feature                    = "ENABLED"
    retry_grace_period_seconds = 0
  }
}

resource "aws_cognito_managed_login_branding" "broker" {
  user_pool_id                = aws_cognito_user_pool.this.id
  client_id                   = aws_cognito_user_pool_client.broker.id
  use_cognito_provided_values = true
}

# ------------------------------------------------------------------ Cognito WAF

resource "aws_wafv2_ip_set" "reviewer_ipv4" {
  name               = "${var.name_prefix}-cognito-reviewers-ipv4"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = [for c in var.reviewer_cidrs : c if !strcontains(c, ":")]
}

resource "aws_wafv2_ip_set" "reviewer_ipv6" {
  name               = "${var.name_prefix}-cognito-reviewers-ipv6"
  scope              = "REGIONAL"
  ip_address_version = "IPV6"
  addresses          = [for c in var.reviewer_cidrs : c if strcontains(c, ":")]
}

# Added separately, and never to the ALB allow-list.
resource "aws_wafv2_ip_set" "broker_egress" {
  name               = "${var.name_prefix}-cognito-broker-egress"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = [var.broker_egress_cidr]
}

# Allow the reviewed list and the broker's egress, block everything else. No CAPTCHA and no
# challenge action: TOTP enrollment happens on these pages. Sampled requests stay off, because
# a sampled request can carry identity data.
resource "aws_wafv2_web_acl" "cognito" {
  name  = "${var.name_prefix}-cognito"
  scope = "REGIONAL"

  default_action {
    block {}
  }

  rule {
    name     = "allow-reviewer-ipv4"
    priority = 10

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.reviewer_ipv4.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "allow-reviewer-ipv4"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "allow-reviewer-ipv6"
    priority = 20

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.reviewer_ipv6.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "allow-reviewer-ipv6"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "allow-identity-broker-egress"
    priority = 30

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.broker_egress.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "allow-identity-broker-egress"
      sampled_requests_enabled   = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-cognito"
    sampled_requests_enabled   = false
  }
}

resource "aws_wafv2_web_acl_association" "cognito" {
  resource_arn = aws_cognito_user_pool.this.arn
  web_acl_arn  = aws_wafv2_web_acl.cognito.arn
}
