variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  nullable    = false
}

variable "vpc_id" {
  type     = string
  nullable = false
}

variable "public_subnet_ids" {
  description = "The two public subnets the internet-facing ALB spans."
  type        = list(string)
  nullable    = false

  validation {
    condition     = length(var.public_subnet_ids) == 2
    error_message = "The ALB spans exactly the two public subnets."
  }
}

variable "alb_security_group_id" {
  description = "The ALB's security group, created without ingress by the network module."
  type        = string
  nullable    = false
}

variable "route53_zone_id" {
  description = "The Route 53 hosted zone for the customer origin: a human-confirmed deployment parameter."
  type        = string
  nullable    = false
}

variable "app_hostname" {
  description = "The one customer origin's host, for example staging.app.firmbatch.com: a human-confirmed deployment parameter."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.app_hostname))
    error_message = "app_hostname must be a lowercase DNS host name."
  }
}

variable "application_port" {
  type     = number
  nullable = false
}

variable "web_api_health_check_path" {
  description = "Target-group health check for the web/API service."
  type        = string
  nullable    = false

  validation {
    condition     = startswith(var.web_api_health_check_path, "/v1/")
    error_message = "The web/API health check lives under /v1/."
  }
}

variable "identity_broker_health_check_path" {
  description = "Target-group health check for the identity broker; its route is M3.3c's."
  type        = string
  nullable    = false

  validation {
    condition     = startswith(var.identity_broker_health_check_path, "/auth/")
    error_message = "The identity broker's health check lives under /auth/."
  }
}

variable "reviewer_address_space_limit" {
  description = "The configured maximum address-space allowance of the whole reviewer allow-list: total IPv4 addresses and total IPv6 /64 networks. A human-confirmed parameter under a hard ceiling of 4,096 IPv4 addresses (sixteen /24s) and sixteen /64s."
  type = object({
    ipv4_addresses        = number
    ipv6_slash64_networks = number
  })
  nullable = false

  validation {
    condition = (
      var.reviewer_address_space_limit.ipv4_addresses >= 1 &&
      var.reviewer_address_space_limit.ipv4_addresses <= 4096 &&
      floor(var.reviewer_address_space_limit.ipv4_addresses) == var.reviewer_address_space_limit.ipv4_addresses &&
      var.reviewer_address_space_limit.ipv6_slash64_networks >= 0 &&
      var.reviewer_address_space_limit.ipv6_slash64_networks <= 16 &&
      floor(var.reviewer_address_space_limit.ipv6_slash64_networks) == var.reviewer_address_space_limit.ipv6_slash64_networks
    )
    error_message = "reviewer_address_space_limit must allow 1 to 4096 IPv4 addresses and 0 to 16 IPv6 /64 networks, in whole numbers."
  }
}

# The human-reviewed reviewer allow-list, shared by ports 443 and 80 (ADR 0011 decision 6).
# Supplied at plan time from protected configuration outside the repository and never
# committed. Validated structurally and fail-closed here, and independently by
# infra/terraform/policy/cidr_allowlist.py; each rule is its own validation block so a
# refusal names the property that failed. Every operand that can raise is inside try() or
# can(), and IPv4 and IPv6 entries are compared only within their own family.
variable "reviewer_cidrs" {
  description = "Reviewer CIDR allow-list for ALB ports 443 and 80; the Cognito WAF admits the same list."
  type        = list(string)
  nullable    = false

  validation {
    condition     = length(var.reviewer_cidrs) > 0
    error_message = "reviewer_cidrs must not be empty: an empty allow-list is refused, never read as open."
  }

  validation {
    condition     = length(var.reviewer_cidrs) <= 16
    error_message = "reviewer_cidrs holds at most 16 entries."
  }

  validation {
    condition = alltrue([
      for c in var.reviewer_cidrs :
      can(regex("^[0-9a-f.:]+/[0-9]{1,3}$", c)) && !(strcontains(c, ".") && strcontains(c, ":")) && try(cidrsubnet(c, 0, 0) == c, false)
    ])
    error_message = "Every reviewer_cidrs entry must be a valid, canonical IPv4 or IPv6 CIDR: lowercase, no host bits set, no leading zeros, no IPv4-mapped IPv6 form."
  }

  validation {
    condition = alltrue([
      for c in var.reviewer_cidrs :
      try(tonumber(split("/", c)[1]) >= (strcontains(c, ":") ? 64 : 24), false)
    ])
    error_message = "IPv4 reviewer entries must be /24 or narrower, and IPv6 entries /64 or narrower."
  }

  # IPv4: none of the IANA special-purpose ranges that are not globally routable.
  validation {
    condition = alltrue([
      for c in var.reviewer_cidrs : try(!anytrue([
        for special in [
          "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
          "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
          "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15",
          "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
        ] :
        cidrsubnet(format("%s/%s", cidrhost(c, 0), split("/", special)[1]), 0, 0) == special ||
        cidrsubnet(format("%s/%s", cidrhost(special, 0), split("/", c)[1]), 0, 0) == c
      ]), false) if !strcontains(c, ":")
    ])
    error_message = "An IPv4 reviewer entry is unspecified, private, shared, loopback, link-local, documentation, benchmarking, multicast, reserved or otherwise not globally routable."
  }

  # IPv6: global unicast (2000::/3) only, and none of its non-routable carve-outs.
  validation {
    condition = alltrue([
      for c in var.reviewer_cidrs : try(
        cidrsubnet(format("%s/3", cidrhost(c, 0)), 0, 0) == "2000::/3" &&
        !anytrue([
          for special in ["2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"] :
          cidrsubnet(format("%s/%s", cidrhost(c, 0), split("/", special)[1]), 0, 0) == special ||
          cidrsubnet(format("%s/%s", cidrhost(special, 0), split("/", c)[1]), 0, 0) == c
        ]),
        false
      ) if strcontains(c, ":")
    ])
    error_message = "An IPv6 reviewer entry is outside global unicast space (unspecified, loopback, IPv4-mapped, unique-local, link-local, multicast) or in a documentation, 6to4, IETF-protocol or other non-routable range."
  }

  validation {
    condition = alltrue(flatten([
      for family in [
        [for c in var.reviewer_cidrs : c if !strcontains(c, ":")],
        [for c in var.reviewer_cidrs : c if strcontains(c, ":")],
        ] : [
        for i, a in family : [
          for j, b in family : i == j || try(!(
            cidrsubnet(format("%s/%s", cidrhost(b, 0), split("/", a)[1]), 0, 0) == a ||
            cidrsubnet(format("%s/%s", cidrhost(a, 0), split("/", b)[1]), 0, 0) == b
          ), false)
        ]
      ]
    ]))
    error_message = "reviewer_cidrs must not contain duplicate or overlapping entries."
  }

  validation {
    condition = try(
      sum(concat([0], [for c in var.reviewer_cidrs : pow(2, 32 - tonumber(split("/", c)[1])) if !strcontains(c, ":")])) <= var.reviewer_address_space_limit.ipv4_addresses &&
      sum(concat([0], [for c in var.reviewer_cidrs : pow(2, 64 - tonumber(split("/", c)[1])) if strcontains(c, ":")])) <= var.reviewer_address_space_limit.ipv6_slash64_networks,
      false
    )
    error_message = "reviewer_cidrs together exceed reviewer_address_space_limit."
  }
}
