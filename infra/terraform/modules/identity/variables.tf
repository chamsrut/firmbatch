variable "name_prefix" {
  type     = string
  nullable = false
}

variable "route53_zone_id" {
  type     = string
  nullable = false
}

variable "auth_hostname" {
  description = "The Cognito Managed Login custom domain, proposed auth.staging.app.firmbatch.com: a human-confirmed parameter under the customer origin's registrable domain."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.auth_hostname))
    error_message = "auth_hostname must be a lowercase DNS host name."
  }
}

variable "callback_url" {
  description = "The one exact callback URL, for example https://staging.app.firmbatch.com/auth/callback."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^https://[a-z0-9.-]+/auth/callback$", var.callback_url))
    error_message = "callback_url must be an exact https URL ending in /auth/callback, with no wildcard, query or fragment."
  }
}

variable "logout_url" {
  description = "The one exact, clean logout URL, for example https://staging.app.firmbatch.com/."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^https://[a-z0-9.-]+/$", var.logout_url))
    error_message = "logout_url must be an exact https origin URL ending in /, with no wildcard, path, query or fragment."
  }
}

variable "reviewer_cidrs" {
  description = "The same reviewer allow-list the ALB admits. Validated structurally by the edge module, which receives the identical list from the root, and by the policy check."
  type        = list(string)
  nullable    = false
}

variable "broker_egress_cidr" {
  description = "The NAT gateway's Elastic IP as a /32, admitted separately so the identity broker can reach the token and revocation endpoints."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("/32$", var.broker_egress_cidr))
    error_message = "broker_egress_cidr must be a single IPv4 address as a /32."
  }
}

variable "ses_identity_arn" {
  description = "The SES identity Cognito sends invitation and recovery mail through: a human-confirmed parameter."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^arn:aws:ses:[a-z0-9-]+:[0-9]{12}:identity/.+$", var.ses_identity_arn))
    error_message = "ses_identity_arn must be an SES identity ARN."
  }
}

variable "from_email_address" {
  description = "The From address of Cognito's mail, on the SES identity."
  type        = string
  nullable    = false
}
