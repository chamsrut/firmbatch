# One security group for the ALB, one per service and one per one-off task, and one for RDS
# (topology §3 and §4). RDS accepts PostgreSQL from exactly the five task groups.
#
# The ALB group's INGRESS rules are the edge module's, because that module owns the one
# structurally validated reviewer allow-list. Nothing here admits traffic from a CIDR.

locals {
  service_names = ["web_api", "identity_broker"]
  task_names    = ["web_api", "identity_broker", "migrate", "bootstrap", "identity_binding"]
}

resource "aws_security_group" "alb" {
  name                   = "${var.name_prefix}-alb"
  description            = "Internet-facing ALB; ingress only from the reviewed allow-list (edge module)"
  vpc_id                 = aws_vpc.this.id
  revoke_rules_on_delete = true

  tags = { Name = "${var.name_prefix}-alb" }
}

resource "aws_security_group" "task" {
  for_each = toset(local.task_names)

  name                   = "${var.name_prefix}-${replace(each.key, "_", "-")}"
  description            = "ECS ${replace(each.key, "_", "-")}; no public IP"
  vpc_id                 = aws_vpc.this.id
  revoke_rules_on_delete = true

  tags = { Name = "${var.name_prefix}-${replace(each.key, "_", "-")}" }
}

resource "aws_security_group" "database" {
  name                   = "${var.name_prefix}-database"
  description            = "RDS PostgreSQL; ingress only from the five task security groups"
  vpc_id                 = aws_vpc.this.id
  revoke_rules_on_delete = true

  tags = { Name = "${var.name_prefix}-database" }
}

# ALB -> the two services, on the application port only.
resource "aws_vpc_security_group_egress_rule" "alb_to_service" {
  for_each = toset(local.service_names)

  security_group_id            = aws_security_group.alb.id
  referenced_security_group_id = aws_security_group.task[each.key].id
  ip_protocol                  = "tcp"
  from_port                    = var.application_port
  to_port                      = var.application_port
  description                  = "To ${replace(each.key, "_", "-")}"
}

resource "aws_vpc_security_group_ingress_rule" "service_from_alb" {
  for_each = toset(local.service_names)

  security_group_id            = aws_security_group.task[each.key].id
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = var.application_port
  to_port                      = var.application_port
  description                  = "From the ALB only"
}

# Every service and task -> PostgreSQL, on the database group only.
resource "aws_vpc_security_group_egress_rule" "task_to_database" {
  for_each = toset(local.task_names)

  security_group_id            = aws_security_group.task[each.key].id
  referenced_security_group_id = aws_security_group.database.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "PostgreSQL"
}

resource "aws_vpc_security_group_ingress_rule" "database_from_task" {
  for_each = toset(local.task_names)

  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.task[each.key].id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "From ${replace(each.key, "_", "-")}"
}

# Every service and task -> HTTPS through the NAT gateway: ECR, Secrets Manager and CloudWatch
# Logs for all of them, and Cognito and KMS for the broker and the binding task. With only an
# S3 gateway endpoint this path is internet-routed and a security group cannot narrow it to
# those services -- an open question recorded in docs/tasks/current.md, not a decision here.
# This is EGRESS; no ingress rule anywhere in this module names a CIDR.
resource "aws_vpc_security_group_egress_rule" "task_https" {
  for_each = toset(local.task_names)

  security_group_id = aws_security_group.task[each.key].id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "HTTPS via the NAT gateway"
}
