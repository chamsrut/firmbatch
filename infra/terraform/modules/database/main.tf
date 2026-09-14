# RDS PostgreSQL 16, private, encrypted, SSL enforced, Single-AZ, seven-day backups, deletion
# protection and a required final snapshot, with the master credential RDS-managed in Secrets
# Manager (ADR 0011 decision 7; topology §5).
#
# Terraform runs no SQL here: no PostgreSQL provider, no provisioner, and no password in any
# variable, plan or output. Roles, grants and migrations are the one-off bootstrap and migrate
# tasks' (M3.3c), run against this instance.

variable "name_prefix" {
  type     = string
  nullable = false
}

variable "database_subnet_ids" {
  description = "The two isolated database subnets."
  type        = list(string)
  nullable    = false

  validation {
    condition     = length(var.database_subnet_ids) == 2
    error_message = "The subnet group spans exactly the two isolated database subnets."
  }
}

variable "database_security_group_id" {
  type     = string
  nullable = false
}

variable "engine_version" {
  description = "The exact supported PostgreSQL 16 minor version, checked by a human immediately before deployment."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^16\\.[0-9]+$", var.engine_version))
    error_message = "engine_version must be an explicit PostgreSQL 16 minor version such as 16.x; the suite refuses any other major."
  }
}

variable "instance_class" {
  description = "RDS instance class: a human-confirmed sizing parameter."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^db\\.[a-z0-9]+\\.[a-z0-9]+$", var.instance_class))
    error_message = "instance_class must be an RDS instance class such as db.t4g.micro."
  }
}

variable "allocated_storage_gib" {
  type     = number
  nullable = false

  validation {
    condition     = var.allocated_storage_gib >= 20 && var.allocated_storage_gib <= 1000
    error_message = "allocated_storage_gib must be from 20 to 1000."
  }
}

variable "max_allocated_storage_gib" {
  type     = number
  nullable = false

  validation {
    condition     = var.max_allocated_storage_gib >= var.allocated_storage_gib && var.max_allocated_storage_gib <= 2000
    error_message = "max_allocated_storage_gib must be at least allocated_storage_gib and at most 2000."
  }
}

variable "kms_key_arn" {
  description = "Customer-managed key for storage and the RDS-managed master secret."
  type        = string
  nullable    = false
}

locals {
  backup_retention_days = 7
}

resource "aws_db_subnet_group" "this" {
  name        = "${var.name_prefix}-database"
  description = "Isolated database subnets across two availability zones"
  subnet_ids  = var.database_subnet_ids
}

resource "aws_db_parameter_group" "this" {
  name        = "${var.name_prefix}-postgres16"
  family      = "postgres16"
  description = "PostgreSQL 16 with SSL enforced"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }
}

resource "aws_db_instance" "this" {
  identifier     = "${var.name_prefix}-postgres"
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class
  port           = 5432

  allocated_storage     = var.allocated_storage_gib
  max_allocated_storage = var.max_allocated_storage_gib
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_arn

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [var.database_security_group_id]
  parameter_group_name   = aws_db_parameter_group.this.name
  publicly_accessible    = false
  multi_az               = false

  # The master password is generated and held by RDS in Secrets Manager; it never appears in
  # a variable, the state or a plan. Only the bootstrap task's execution role may read it.
  username                      = "firmbatch_master"
  manage_master_user_password   = true
  master_user_secret_kms_key_id = var.kms_key_arn

  iam_database_authentication_enabled = false
  ca_cert_identifier                  = "rds-ca-rsa2048-g1"

  backup_retention_period   = local.backup_retention_days
  copy_tags_to_snapshot     = true
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name_prefix}-postgres-final"

  # The exact minor is a reviewed parameter; RDS does not move it underneath a qualification.
  auto_minor_version_upgrade = false
  apply_immediately          = false
}

output "address" {
  value = aws_db_instance.this.address
}

output "port" {
  value = aws_db_instance.this.port
}

output "identifier" {
  value = aws_db_instance.this.identifier
}

output "master_user_secret_arn" {
  description = "ARN of the RDS-managed master secret -- an identifier, never the credential."
  value       = one(aws_db_instance.this.master_user_secret[*].secret_arn)
}
