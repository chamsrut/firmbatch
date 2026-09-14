variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  nullable    = false
}

variable "region" {
  description = "The workload region; it names the S3 gateway endpoint's service."
  type        = string
  nullable    = false
}

variable "vpc_cidr" {
  description = "The VPC's IPv4 range, a human-confirmed deployment parameter inside RFC 1918 space."
  type        = string
  nullable    = false

  validation {
    condition = try(
      cidrsubnet(var.vpc_cidr, 0, 0) == var.vpc_cidr &&
      tonumber(split("/", var.vpc_cidr)[1]) >= 16 &&
      tonumber(split("/", var.vpc_cidr)[1]) <= 24 &&
      anytrue([
        for private in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] :
        cidrsubnet(format("%s/%s", cidrhost(var.vpc_cidr, 0), split("/", private)[1]), 0, 0) == private
      ]),
      false
    )
    error_message = "vpc_cidr must be a canonical IPv4 network from /16 to /24 inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16."
  }
}

variable "availability_zones" {
  description = "Exactly two availability zones in the region."
  type        = list(string)
  nullable    = false

  validation {
    condition     = length(var.availability_zones) == 2 && length(distinct(var.availability_zones)) == 2
    error_message = "availability_zones must name exactly two distinct zones."
  }
}

variable "public_subnet_cidrs" {
  description = "Two public subnets, one per zone: the ALB and the NAT gateway only."
  type        = list(string)
  nullable    = false

  validation {
    condition = length(var.public_subnet_cidrs) == 2 && alltrue([
      for c in var.public_subnet_cidrs :
      try(cidrsubnet(c, 0, 0) == c && cidrsubnet(format("%s/%s", cidrhost(c, 0), split("/", var.vpc_cidr)[1]), 0, 0) == var.vpc_cidr, false)
    ])
    error_message = "public_subnet_cidrs must be two canonical networks inside vpc_cidr."
  }
}

variable "private_subnet_cidrs" {
  description = "Two private application subnets, one per zone: ECS tasks, with no public IP and a default route to the NAT gateway."
  type        = list(string)
  nullable    = false

  validation {
    condition = length(var.private_subnet_cidrs) == 2 && alltrue([
      for c in var.private_subnet_cidrs :
      try(cidrsubnet(c, 0, 0) == c && cidrsubnet(format("%s/%s", cidrhost(c, 0), split("/", var.vpc_cidr)[1]), 0, 0) == var.vpc_cidr, false)
    ])
    error_message = "private_subnet_cidrs must be two canonical networks inside vpc_cidr."
  }
}

variable "database_subnet_cidrs" {
  description = "Two isolated database subnets, one per zone: RDS only, with no route to the internet."
  type        = list(string)
  nullable    = false

  validation {
    condition = length(var.database_subnet_cidrs) == 2 && alltrue([
      for c in var.database_subnet_cidrs :
      try(cidrsubnet(c, 0, 0) == c && cidrsubnet(format("%s/%s", cidrhost(c, 0), split("/", var.vpc_cidr)[1]), 0, 0) == var.vpc_cidr, false)
    ])
    error_message = "database_subnet_cidrs must be two canonical networks inside vpc_cidr."
  }
}

variable "application_port" {
  description = "The container port both services listen on behind the ALB."
  type        = number
  nullable    = false

  validation {
    condition     = var.application_port >= 1024 && var.application_port <= 65535
    error_message = "application_port must be an unprivileged port."
  }
}
