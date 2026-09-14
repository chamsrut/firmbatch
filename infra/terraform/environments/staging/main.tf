locals {
  account_id = data.aws_caller_identity.current.account_id

  # Must equal the backend block's key in versions.tf, and the state key the bootstrap root's
  # delivery identities are confined to; the policy check asserts both.
  state_key = "staging/terraform.tfstate"

  application_port = 8080
  app_origin       = "https://${var.app_hostname}"

  # The canonical release repository, in the artifacts root. What every task runs is the verified
  # release reference in var.release_image -- this repository at a digest -- and never a tag.
  release_repository_url = "${var.release_registry_account_id}.dkr.ecr.${var.release_registry_region}.amazonaws.com/${var.release_repository_name}"
  release_repository_arn = "arn:aws:ecr:${var.release_registry_region}:${var.release_registry_account_id}:repository/${var.release_repository_name}"

  # Names are derived here, not read back from resources, so the delivery, compute and
  # observability modules -- and the bootstrap root's delivery identities -- agree on them without
  # depending on each other.
  cluster_name = var.name_prefix
  service_names = {
    web_api         = "${var.name_prefix}-web-api"
    identity_broker = "${var.name_prefix}-identity-broker"
  }
  log_group_suffixes = {
    web_api          = "web-api"
    identity_broker  = "identity-broker"
    migrate          = "migrate"
    bootstrap        = "bootstrap"
    identity_binding = "identity-binding"
  }
}

module "network" {
  source = "../../modules/network"

  name_prefix           = var.name_prefix
  region                = var.region
  vpc_cidr              = var.vpc_cidr
  availability_zones    = var.availability_zones
  public_subnet_cidrs   = var.public_subnet_cidrs
  private_subnet_cidrs  = var.private_subnet_cidrs
  database_subnet_cidrs = var.database_subnet_cidrs
  application_port      = local.application_port
}

module "edge" {
  source = "../../modules/edge"

  name_prefix                       = var.name_prefix
  vpc_id                            = module.network.vpc_id
  public_subnet_ids                 = module.network.public_subnet_ids
  alb_security_group_id             = module.network.alb_security_group_id
  route53_zone_id                   = var.route53_zone_id
  app_hostname                      = var.app_hostname
  application_port                  = local.application_port
  web_api_health_check_path         = "/v1/health"
  identity_broker_health_check_path = var.identity_broker_health_check_path
  reviewer_cidrs                    = var.reviewer_cidrs
  reviewer_address_space_limit      = var.reviewer_address_space_limit
}

module "secrets" {
  source = "../../modules/secrets"

  name_prefix = var.name_prefix
  account_id  = local.account_id
  region      = var.region
}

module "database" {
  source = "../../modules/database"

  name_prefix                = var.name_prefix
  database_subnet_ids        = module.network.database_subnet_ids
  database_security_group_id = module.network.database_security_group_id
  engine_version             = var.postgres_engine_version
  instance_class             = var.rds_instance_class
  allocated_storage_gib      = var.rds_allocated_storage_gib
  max_allocated_storage_gib  = var.rds_max_allocated_storage_gib
  kms_key_arn                = module.secrets.workload_kms_key_arn
}

module "identity" {
  source = "../../modules/identity"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  name_prefix        = var.name_prefix
  route53_zone_id    = var.route53_zone_id
  auth_hostname      = var.auth_hostname
  callback_url       = "${local.app_origin}/auth/callback"
  logout_url         = "${local.app_origin}/"
  reviewer_cidrs     = var.reviewer_cidrs
  broker_egress_cidr = module.network.nat_egress_cidr
  ses_identity_arn   = var.cognito_ses_identity_arn
  from_email_address = var.cognito_from_email_address
}

module "observability" {
  source = "../../modules/observability"

  name_prefix                    = var.name_prefix
  account_id                     = local.account_id
  log_retention_days             = var.log_retention_days
  kms_key_arn                    = module.secrets.workload_kms_key_arn
  alert_email                    = var.alert_email
  budget_limit_usd               = var.budget_limit_usd
  budget_alert_threshold_percent = var.budget_alert_threshold_percent
  log_group_suffixes             = local.log_group_suffixes
  alb_arn_suffix                 = module.edge.alb_arn_suffix
  target_group_arn_suffixes      = module.edge.target_group_arn_suffixes
  cluster_name                   = local.cluster_name
  service_names                  = local.service_names
  db_instance_identifier         = module.database.identifier
}

module "delivery" {
  source = "../../modules/delivery"

  name_prefix       = var.name_prefix
  account_id        = local.account_id
  region            = var.region
  state_bucket_name = var.state_bucket_name
  state_kms_key_arn = var.state_kms_key_arn
  plan_bucket_name  = var.plan_bucket_name
  plan_kms_key_arn  = var.plan_kms_key_arn
  cluster_name      = local.cluster_name

  release_registry_account_id = var.release_registry_account_id
  release_registry_region     = var.release_registry_region
  release_repository_name     = var.release_repository_name
}

module "compute" {
  source = "../../modules/compute"

  name_prefix                       = var.name_prefix
  account_id                        = local.account_id
  region                            = var.region
  cluster_name                      = local.cluster_name
  service_names                     = local.service_names
  runtime_contract_reviewed         = var.runtime_contract_reviewed
  approved_image_repository_url     = local.release_repository_url
  image_repository_arn              = local.release_repository_arn
  image                             = var.release_image
  commands                          = var.commands
  task_sizes                        = var.task_sizes
  desired_counts                    = var.desired_counts
  private_subnet_ids                = module.network.private_subnet_ids
  task_security_group_ids           = module.network.task_security_group_ids
  target_group_arns                 = module.edge.target_group_arns
  application_port                  = local.application_port
  log_group_names                   = module.observability.log_group_names
  secret_arns                       = module.secrets.secret_arns
  rds_master_secret_arn             = module.database.master_user_secret_arn
  workload_kms_key_arn              = module.secrets.workload_kms_key_arn
  refresh_token_kms_key_arn         = module.secrets.refresh_token_kms_key_arn
  app_origin                        = local.app_origin
  firmbatch_env                     = var.firmbatch_env
  workload_permissions_boundary_arn = module.delivery.workload_permissions_boundary_arn

  cognito = {
    user_pool_id  = module.identity.user_pool_id
    user_pool_arn = module.identity.user_pool_arn
    client_id     = module.identity.app_client_id
    issuer        = module.identity.issuer
  }
}
