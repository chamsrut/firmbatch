# VPC across two availability zones: public subnets for the ALB and the one NAT gateway,
# private application subnets for ECS tasks, isolated database subnets for RDS, and an S3
# gateway endpoint (ADR 0011 decision 3; topology §4).

locals {
  zones = { for index, zone in var.availability_zones : tostring(index) => zone }
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = var.name_prefix }
}

# The VPC's default security group keeps no rules at all, so nothing can fall back onto it.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-default-unused" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = { Name = var.name_prefix }
}

resource "aws_subnet" "public" {
  for_each = local.zones

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value
  cidr_block              = var.public_subnet_cidrs[tonumber(each.key)]
  map_public_ip_on_launch = false

  tags = { Name = "${var.name_prefix}-public-${each.value}", "firmbatch:tier" = "public" }
}

resource "aws_subnet" "private" {
  for_each = local.zones

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value
  cidr_block              = var.private_subnet_cidrs[tonumber(each.key)]
  map_public_ip_on_launch = false

  tags = { Name = "${var.name_prefix}-private-${each.value}", "firmbatch:tier" = "private" }
}

resource "aws_subnet" "database" {
  for_each = local.zones

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value
  cidr_block              = var.database_subnet_cidrs[tonumber(each.key)]
  map_public_ip_on_launch = false

  tags = { Name = "${var.name_prefix}-database-${each.value}", "firmbatch:tier" = "database" }
}

# One NAT gateway with one fixed Elastic IP: the egress address the Cognito WAF admits as a
# separate /32. Multiple NAT gateways are deferred (ADR 0011 decision 11).
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = { Name = "${var.name_prefix}-nat" }
}

resource "aws_nat_gateway" "this" {
  allocation_id     = aws_eip.nat.id
  subnet_id         = aws_subnet.public["0"].id
  connectivity_type = "public"

  tags = { Name = var.name_prefix }

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-public" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  for_each = local.zones

  subnet_id      = aws_subnet.public[each.key].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-private" }
}

resource "aws_route" "private_nat" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this.id
}

resource "aws_route_table_association" "private" {
  for_each = local.zones

  subnet_id      = aws_subnet.private[each.key].id
  route_table_id = aws_route_table.private.id
}

# The database route table has no default route: the database subnets reach nothing outside
# the VPC.
resource "aws_route_table" "database" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-database" }
}

resource "aws_route_table_association" "database" {
  for_each = local.zones

  subnet_id      = aws_subnet.database[each.key].id
  route_table_id = aws_route_table.database.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "${var.name_prefix}-s3" }
}
