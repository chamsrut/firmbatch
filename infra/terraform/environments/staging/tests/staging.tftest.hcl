# Mocked AWS only; no run block here can reach AWS. Both provider configurations this root
# declares -- the default and aws.us_east_1 -- are replaced by the mock_provider blocks below,
# the verification gate runs `terraform test` with every AWS credential removed and instance
# metadata disabled, and infra/terraform/policy/check.py refuses any test file that leaves a
# provider configuration unmocked. Every run is `command = plan`.
#
# Assertions can only see a module's own resources when the run targets that module, so the
# first run plans the whole composition and the later runs target one module each.
#
# Every value is synthetic. The reviewer ranges are globally routable test values chosen for
# these files; they are no reviewer's network.

mock_provider "aws" {
  override_during = plan

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111111111111"
      arn        = "arn:aws:iam::111111111111:role/synthetic-operator"
      user_id    = "SYNTHETIC"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "eu-central-1"
      name   = "eu-central-1"
    }
  }

  mock_resource "aws_acm_certificate" {
    defaults = {
      arn = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-4000-8000-000000000001"
      domain_validation_options = [{
        domain_name           = "staging.app.synthetic.example"
        resource_record_name  = "_synthetic.staging.app.synthetic.example."
        resource_record_type  = "CNAME"
        resource_record_value = "_synthetic.acm-validations.aws."
      }]
    }
  }

  mock_resource "aws_db_instance" {
    defaults = {
      master_user_secret = [{
        secret_arn    = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:rds!db-synthetic"
        kms_key_id    = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-000000000002"
        secret_status = "active"
      }]
    }
  }

  mock_resource "aws_eip" {
    defaults = {
      public_ip = "11.22.99.10"
    }
  }

  mock_resource "aws_cognito_user_pool" {
    defaults = {
      arn = "arn:aws:cognito-idp:eu-central-1:111111111111:userpool/eu-central-1_Synthetic"
      id  = "eu-central-1_Synthetic"
    }
  }

  mock_resource "aws_iam_policy" {
    defaults = {
      arn = "arn:aws:iam::111111111111:policy/synthetic-boundary"
    }
  }

  mock_resource "aws_nat_gateway" {
    defaults = {
      id = "nat-synthetic"
    }
  }
}

mock_provider "aws" {
  alias           = "us_east_1"
  override_during = plan

  mock_resource "aws_acm_certificate" {
    defaults = {
      arn = "arn:aws:acm:us-east-1:111111111111:certificate/00000000-0000-4000-8000-000000000003"
      domain_validation_options = [{
        domain_name           = "auth.staging.app.synthetic.example"
        resource_record_name  = "_synthetic.auth.staging.app.synthetic.example."
        resource_record_type  = "CNAME"
        resource_record_value = "_synthetic.acm-validations.aws."
      }]
    }
  }
}

variables {
  expected_account_id = "111111111111"
  region              = "eu-central-1"
  environment         = "staging"
  name_prefix         = "firmbatch-staging"

  state_bucket_name = "synthetic-firmbatch-state"
  state_kms_key_arn = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-00000000000a"
  plan_bucket_name  = "synthetic-firmbatch-plans"
  plan_kms_key_arn  = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-00000000000b"

  release_registry_account_id = "111111111111"
  release_registry_region     = "eu-central-1"
  release_repository_name     = "firmbatch/control-plane"

  route53_zone_id = "Z0SYNTHETIC00000000"
  app_hostname    = "staging.app.synthetic.example"
  auth_hostname   = "auth.staging.app.synthetic.example"

  vpc_cidr              = "10.40.0.0/16"
  availability_zones    = ["eu-central-1a", "eu-central-1b"]
  public_subnet_cidrs   = ["10.40.0.0/24", "10.40.1.0/24"]
  private_subnet_cidrs  = ["10.40.10.0/24", "10.40.11.0/24"]
  database_subnet_cidrs = ["10.40.20.0/24", "10.40.21.0/24"]

  reviewer_cidrs = ["11.22.33.0/24", "2a0f:ffff:1::/64"]
  reviewer_address_space_limit = {
    ipv4_addresses        = 256
    ipv6_slash64_networks = 1
  }

  runtime_contract_reviewed = true
  release_image             = "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane@sha256:5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e"

  # Synthetic commands. The broker, bootstrap and identity-binding programs do not exist yet
  # (M3.3c); these names only give the task-definition contract something to render.
  commands = {
    web_api          = ["python3", "-m", "firmbatch.control_plane.api", "--host", "0.0.0.0", "--port", "8080"]
    identity_broker  = ["synthetic-m3-3c-identity-broker"]
    migrate          = ["python3", "-m", "firmbatch.control_plane.migrate", "upgrade"]
    bootstrap        = ["synthetic-m3-3c-bootstrap"]
    identity_binding = ["synthetic-m3-3c-identity-binding"]
  }

  task_sizes = {
    web_api          = { cpu = 256, memory = 512 }
    identity_broker  = { cpu = 256, memory = 512 }
    migrate          = { cpu = 256, memory = 512 }
    bootstrap        = { cpu = 256, memory = 512 }
    identity_binding = { cpu = 256, memory = 512 }
  }

  desired_counts = {
    web_api         = 1
    identity_broker = 1
  }

  firmbatch_env                     = "production"
  identity_broker_health_check_path = "/auth/health"

  postgres_engine_version       = "16.0"
  rds_instance_class            = "db.t4g.micro"
  rds_allocated_storage_gib     = 20
  rds_max_allocated_storage_gib = 50

  cognito_ses_identity_arn   = "arn:aws:ses:eu-central-1:111111111111:identity/synthetic.example"
  cognito_from_email_address = "no-reply@synthetic.example"

  log_retention_days             = 30
  alert_email                    = "alerts@synthetic.example"
  budget_limit_usd               = "150"
  budget_alert_threshold_percent = 80
}

# ====================================================================== the composition

run "the_staging_composition_plans_against_mocks" {
  command = plan

  assert {
    condition     = output.app_origin == "https://staging.app.synthetic.example"
    error_message = "One customer origin."
  }

  assert {
    condition     = output.cognito_issuer == "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_Synthetic"
    error_message = "The exact issuer is derived from the one pool."
  }

  assert {
    condition     = toset(keys(output.task_definition_families)) == toset(["web_api", "identity_broker", "migrate", "bootstrap", "identity_binding"])
    error_message = "Exactly two services and three one-off tasks."
  }

  assert {
    condition     = output.approved_release_repository_url == "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane"
    error_message = "Every task runs from the canonical release repository in the artifacts root; the staging root creates no repository of its own."
  }
}

run "the_staging_composition_refuses_another_account" {
  command = plan

  variables {
    expected_account_id = "222222222222"
  }

  expect_failures = [data.aws_caller_identity.current]
}

run "a_tag_only_release_image_is_refused" {
  command = plan

  variables {
    release_image = "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane:latest"
  }

  expect_failures = [var.release_image]
}

run "a_release_image_with_both_tag_and_digest_is_refused" {
  command = plan

  variables {
    release_image = "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane:git-aaaaaaaa@sha256:5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e"
  }

  expect_failures = [var.release_image]
}

run "a_release_image_from_an_unapproved_repository_is_refused" {
  command = plan

  variables {
    release_image = "999999999999.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane@sha256:5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e"
  }

  expect_failures = [var.release_image]
}

# ====================================================================== network

run "network_keeps_tasks_and_database_private" {
  command = plan

  module {
    source = "../../modules/network"
  }

  variables {
    application_port = 8080
  }

  assert {
    condition = alltrue(concat(
      [for subnet in aws_subnet.public : subnet.map_public_ip_on_launch == false],
      [for subnet in aws_subnet.private : subnet.map_public_ip_on_launch == false],
      [for subnet in aws_subnet.database : subnet.map_public_ip_on_launch == false],
    ))
    error_message = "No subnet assigns public IPs on launch."
  }

  assert {
    condition     = length(aws_subnet.public) == 2 && length(aws_subnet.private) == 2 && length(aws_subnet.database) == 2
    error_message = "Two availability zones for each tier."
  }

  assert {
    condition     = aws_route.private_nat.nat_gateway_id == "nat-synthetic" && aws_route.private_nat.destination_cidr_block == "0.0.0.0/0"
    error_message = "Private subnets' default route goes through the one NAT gateway."
  }

  assert {
    condition     = aws_vpc_endpoint.s3.vpc_endpoint_type == "Gateway"
    error_message = "An S3 gateway endpoint."
  }

  assert {
    condition = length(aws_vpc_security_group_ingress_rule.database_from_task) == 5 && alltrue([
      for rule in aws_vpc_security_group_ingress_rule.database_from_task :
      rule.cidr_ipv4 == null && rule.cidr_ipv6 == null && rule.from_port == 5432
    ])
    error_message = "RDS admits PostgreSQL from exactly the five task security groups and no CIDR."
  }

  assert {
    condition = alltrue([
      for rule in aws_vpc_security_group_ingress_rule.service_from_alb :
      rule.cidr_ipv4 == null && rule.cidr_ipv6 == null
    ])
    error_message = "Services admit traffic only from the ALB security group."
  }
}

# ====================================================================== edge

run "edge_admits_only_the_reviewed_list_and_routes_the_one_origin" {
  command = plan

  module {
    source = "../../modules/edge"
  }

  variables {
    vpc_id                            = "vpc-synthetic"
    public_subnet_ids                 = ["subnet-synthetic-a", "subnet-synthetic-b"]
    alb_security_group_id             = "sg-synthetic-alb"
    application_port                  = 8080
    web_api_health_check_path         = "/v1/health"
    identity_broker_health_check_path = "/auth/health"
  }

  assert {
    condition = length(aws_vpc_security_group_ingress_rule.reviewer) == 4 && alltrue([
      for rule in aws_vpc_security_group_ingress_rule.reviewer :
      contains([80, 443], rule.from_port) && rule.from_port == rule.to_port &&
      contains(var.reviewer_cidrs, coalesce(rule.cidr_ipv4, rule.cidr_ipv6))
    ])
    error_message = "Ports 80 and 443 admit exactly the same reviewed list, and nothing else."
  }

  assert {
    condition     = aws_lb_listener.http.port == 80 && aws_lb_listener.http.default_action[0].type == "redirect" && aws_lb_listener.http.default_action[0].redirect[0].protocol == "HTTPS"
    error_message = "Port 80 only redirects to HTTPS."
  }

  assert {
    condition     = aws_lb_listener.https.default_action[0].type == "fixed-response"
    error_message = "Any host other than the customer origin is refused on 443."
  }

  assert {
    condition = (
      aws_lb.this.internal == false &&
      aws_lb.this.drop_invalid_header_fields == true &&
      aws_lb.this.desync_mitigation_mode == "strictest" &&
      aws_lb.this.enable_deletion_protection == true
    )
    error_message = "Internet-facing, strict header handling, deletion protection."
  }

  # Which target group each rule forwards to is compared from source by the policy check
  # (rule_network_ingress): target-group ARNs are unknown while planning against mocks.
  assert {
    condition = (
      aws_lb_listener_rule.identity_broker.priority < aws_lb_listener_rule.web_api.priority &&
      aws_lb_listener_rule.web_api.priority < aws_lb_listener_rule.web_api_default.priority &&
      anytrue([for c in aws_lb_listener_rule.identity_broker.condition : try(c.path_pattern[0].values == toset(["/auth/*"]), false)]) &&
      anytrue([for c in aws_lb_listener_rule.web_api.condition : try(c.path_pattern[0].values == toset(["/v1/*"]), false)]) &&
      alltrue([
        for rule in [aws_lb_listener_rule.identity_broker, aws_lb_listener_rule.web_api, aws_lb_listener_rule.web_api_default] :
        anytrue([for c in rule.condition : try(c.host_header[0].values == toset([var.app_hostname]), false)])
      ])
    )
    error_message = "/auth/* first, then /v1/*, then every other path, each only on the exact customer origin."
  }
}

# ====================================================================== database

run "database_is_private_encrypted_ssl_enforced_and_protected" {
  command = plan

  module {
    source = "../../modules/database"
  }

  variables {
    database_subnet_ids        = ["subnet-synthetic-db-a", "subnet-synthetic-db-b"]
    database_security_group_id = "sg-synthetic-db"
    engine_version             = "16.0"
    instance_class             = "db.t4g.micro"
    allocated_storage_gib      = 20
    max_allocated_storage_gib  = 50
    kms_key_arn                = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-00000000000c"
  }

  assert {
    condition = (
      aws_db_instance.this.publicly_accessible == false &&
      aws_db_instance.this.storage_encrypted == true &&
      aws_db_instance.this.multi_az == false &&
      aws_db_instance.this.backup_retention_period == 7 &&
      aws_db_instance.this.deletion_protection == true &&
      aws_db_instance.this.skip_final_snapshot == false &&
      aws_db_instance.this.manage_master_user_password == true &&
      aws_db_instance.this.engine == "postgres" &&
      startswith(aws_db_instance.this.engine_version, "16.")
    )
    error_message = "RDS PostgreSQL 16: private, encrypted, Single-AZ, seven-day backups, deletion protection, final snapshot, RDS-managed master secret."
  }

  assert {
    condition     = anytrue([for parameter in aws_db_parameter_group.this.parameter : parameter.name == "rds.force_ssl" && parameter.value == "1"])
    error_message = "SSL is enforced by the parameter group."
  }
}

run "a_non_16_engine_is_refused" {
  command = plan

  module {
    source = "../../modules/database"
  }

  variables {
    database_subnet_ids        = ["subnet-synthetic-db-a", "subnet-synthetic-db-b"]
    database_security_group_id = "sg-synthetic-db"
    engine_version             = "15.8"
    instance_class             = "db.t4g.micro"
    allocated_storage_gib      = 20
    max_allocated_storage_gib  = 50
    kms_key_arn                = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-00000000000c"
  }

  expect_failures = [var.engine_version]
}

# ====================================================================== secrets

run "secrets_are_containers_under_customer_managed_keys" {
  command = plan

  module {
    source = "../../modules/secrets"
  }

  variables {
    account_id = "111111111111"
  }

  assert {
    condition     = toset(keys(aws_secretsmanager_secret.runtime)) == toset(["application_database_url", "authenticator_database_url", "identity_binding_database_url", "migration_database_url", "cognito_client_secret"])
    error_message = "One container per runtime credential."
  }

  assert {
    condition     = aws_kms_key.workload.enable_key_rotation && aws_kms_key.refresh_token.enable_key_rotation && aws_kms_alias.workload.name != aws_kms_alias.refresh_token.name
    error_message = "A separate, rotating refresh-token key."
  }
}

# ====================================================================== identity

run "identity_is_invite_only_totp_code_grant_with_a_cognito_waf" {
  command = plan

  # Both mock providers, the default and aws.us_east_1, reach the module by name.
  module {
    source = "../../modules/identity"
  }

  variables {
    callback_url       = "https://staging.app.synthetic.example/auth/callback"
    logout_url         = "https://staging.app.synthetic.example/"
    broker_egress_cidr = "11.22.99.10/32"
    ses_identity_arn   = "arn:aws:ses:eu-central-1:111111111111:identity/synthetic.example"
    from_email_address = "no-reply@synthetic.example"
  }

  assert {
    condition = (
      aws_cognito_user_pool.this.mfa_configuration == "ON" &&
      aws_cognito_user_pool.this.software_token_mfa_configuration[0].enabled == true &&
      aws_cognito_user_pool.this.admin_create_user_config[0].allow_admin_create_user_only == true &&
      aws_cognito_user_pool.this.username_configuration[0].case_sensitive == false
    )
    error_message = "Invite-only, case-insensitive, required TOTP."
  }

  assert {
    condition = (
      aws_cognito_user_pool_client.broker.generate_secret == true &&
      aws_cognito_user_pool_client.broker.allowed_oauth_flows == toset(["code"]) &&
      aws_cognito_user_pool_client.broker.allowed_oauth_scopes == toset(["openid", "email"]) &&
      aws_cognito_user_pool_client.broker.callback_urls == toset(["https://staging.app.synthetic.example/auth/callback"]) &&
      aws_cognito_user_pool_client.broker.logout_urls == toset(["https://staging.app.synthetic.example/"]) &&
      aws_cognito_user_pool_client.broker.prevent_user_existence_errors == "ENABLED" &&
      aws_cognito_user_pool_client.broker.refresh_token_rotation[0].feature == "ENABLED"
    )
    error_message = "A confidential client: code grant only, exact URLs, openid and email only, rotation on."
  }

  assert {
    condition     = aws_cognito_user_pool_domain.this.managed_login_version == 2 && aws_cognito_user_pool_domain.this.domain == "auth.staging.app.synthetic.example"
    error_message = "Managed Login v2 at the custom domain."
  }

  assert {
    condition     = aws_wafv2_web_acl_association.cognito.resource_arn == aws_cognito_user_pool.this.arn && length(aws_wafv2_web_acl.cognito.default_action[0].block) == 1
    error_message = "The WAF is associated with the user pool and blocks by default."
  }

  assert {
    condition     = aws_wafv2_ip_set.broker_egress.addresses == toset(["11.22.99.10/32"]) && !contains(tolist(aws_wafv2_ip_set.reviewer_ipv4.addresses), "11.22.99.10/32")
    error_message = "The broker's NAT address is admitted separately, never inside the reviewer list."
  }
}

# ====================================================================== observability

run "observability_retains_encrypts_and_alerts" {
  command = plan

  module {
    source = "../../modules/observability"
  }

  variables {
    account_id             = "111111111111"
    kms_key_arn            = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-00000000000c"
    alb_arn_suffix         = "app/firmbatch-staging-alb/synthetic"
    cluster_name           = "firmbatch-staging"
    db_instance_identifier = "firmbatch-staging-postgres"
    log_group_suffixes = {
      web_api          = "web-api"
      identity_broker  = "identity-broker"
      migrate          = "migrate"
      bootstrap        = "bootstrap"
      identity_binding = "identity-binding"
    }
    target_group_arn_suffixes = {
      web_api         = "targetgroup/firmbatch-staging-web-api/synthetic"
      identity_broker = "targetgroup/firmbatch-staging-broker/synthetic"
    }
    service_names = {
      web_api         = "firmbatch-staging-web-api"
      identity_broker = "firmbatch-staging-identity-broker"
    }
  }

  assert {
    condition = length(aws_cloudwatch_log_group.task) == 5 && alltrue([
      for group in aws_cloudwatch_log_group.task : group.retention_in_days == 30 && group.kms_key_id != null
    ])
    error_message = "Every application log group has explicit retention and encryption."
  }

  assert {
    condition     = aws_budgets_budget.monthly.limit_amount == "150" && aws_budgets_budget.monthly.budget_type == "COST" && aws_budgets_budget.monthly.time_unit == "MONTHLY"
    error_message = "A monthly cost budget that alerts; it is not a spending cap."
  }
}

# ====================================================================== compute

run "compute_separates_credentials_and_keeps_every_task_private" {
  command = plan

  module {
    source = "../../modules/compute"
  }

  variables {
    account_id                    = "111111111111"
    cluster_name                  = "firmbatch-staging"
    approved_image_repository_url = "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane"
    image_repository_arn          = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane"
    image                         = "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane@sha256:5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e"
    private_subnet_ids            = ["subnet-synthetic-private-a", "subnet-synthetic-private-b"]
    application_port              = 8080
    app_origin                    = "https://staging.app.synthetic.example"
    service_names = {
      web_api         = "firmbatch-staging-web-api"
      identity_broker = "firmbatch-staging-identity-broker"
    }
    task_security_group_ids = {
      web_api          = "sg-synthetic-web-api"
      identity_broker  = "sg-synthetic-identity-broker"
      migrate          = "sg-synthetic-migrate"
      bootstrap        = "sg-synthetic-bootstrap"
      identity_binding = "sg-synthetic-identity-binding"
    }
    target_group_arns = {
      web_api         = "arn:aws:elasticloadbalancing:eu-central-1:111111111111:targetgroup/firmbatch-staging-web-api/synthetic"
      identity_broker = "arn:aws:elasticloadbalancing:eu-central-1:111111111111:targetgroup/firmbatch-staging-broker/synthetic"
    }
    log_group_names = {
      web_api          = "/ecs/firmbatch-staging/web-api"
      identity_broker  = "/ecs/firmbatch-staging/identity-broker"
      migrate          = "/ecs/firmbatch-staging/migrate"
      bootstrap        = "/ecs/firmbatch-staging/bootstrap"
      identity_binding = "/ecs/firmbatch-staging/identity-binding"
    }
    secret_arns = {
      application_database_url      = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/application-database-url"
      authenticator_database_url    = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/authenticator-database-url"
      identity_binding_database_url = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/identity-binding-database-url"
      migration_database_url        = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/migration-database-url"
      cognito_client_secret         = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/cognito-client-secret"
    }
    rds_master_secret_arn             = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:rds!db-synthetic"
    workload_kms_key_arn              = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-00000000000c"
    refresh_token_kms_key_arn         = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-00000000000d"
    workload_permissions_boundary_arn = "arn:aws:iam::111111111111:policy/firmbatch-staging-workload-boundary"
    cognito = {
      user_pool_id  = "eu-central-1_Synthetic"
      user_pool_arn = "arn:aws:cognito-idp:eu-central-1:111111111111:userpool/eu-central-1_Synthetic"
      client_id     = "syntheticclientid"
      issuer        = "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_Synthetic"
    }
  }

  assert {
    condition = alltrue([
      for service in aws_ecs_service.this :
      service.enable_execute_command == false &&
      service.network_configuration[0].assign_public_ip == false &&
      service.deployment_circuit_breaker[0].enable == true &&
      service.deployment_circuit_breaker[0].rollback == true
    ])
    error_message = "Services: no ECS Exec, no public IP, circuit-breaker rollback."
  }

  assert {
    condition = alltrue([
      for definition in aws_ecs_task_definition.this :
      jsondecode(definition.container_definitions)[0].image == "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane@sha256:5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e"
    ])
    error_message = "Every service and one-off task runs exactly the verified release reference, by digest."
  }

  assert {
    condition     = alltrue([for definition in aws_ecs_task_definition.this : definition.skip_destroy == true])
    error_message = "A digest rollout registers a new revision and never deregisters the previous one: every task definition is skip_destroy, so rollback always has a registered revision."
  }

  assert {
    condition = alltrue([
      for definition in aws_ecs_task_definition.this :
      definition.network_mode == "awsvpc" && length(definition.volume) == 0 &&
      jsondecode(definition.container_definitions)[0].privileged == false &&
      jsondecode(definition.container_definitions)[0].readonlyRootFilesystem == true &&
      jsondecode(definition.container_definitions)[0].user == "10001:10001" &&
      jsondecode(definition.container_definitions)[0].linuxParameters.capabilities.drop == ["ALL"] &&
      !can(jsondecode(definition.container_definitions)[0].linuxParameters.capabilities.add) &&
      !can(jsondecode(definition.container_definitions)[0].mountPoints)
    ])
    error_message = "Every container: awsvpc, no volume or host mount, unprivileged, read-only root filesystem, non-root user, every capability dropped and none added."
  }

  assert {
    condition     = [for s in jsondecode(aws_ecs_task_definition.this["web_api"].container_definitions)[0].secrets : s.name] == ["FIRMBATCH_DATABASE_URL"]
    error_message = "The web/API service receives the application database credential only."
  }

  assert {
    condition     = [for s in jsondecode(aws_ecs_task_definition.this["identity_broker"].container_definitions)[0].secrets : s.name] == ["FIRMBATCH_AUTHENTICATOR_DATABASE_URL", "FIRMBATCH_COGNITO_CLIENT_SECRET"]
    error_message = "The broker receives its authenticator credential and the Cognito client secret, and nothing else."
  }

  assert {
    condition     = [for s in jsondecode(aws_ecs_task_definition.this["migrate"].container_definitions)[0].secrets : s.name] == ["FIRMBATCH_MIGRATION_DATABASE_URL"]
    error_message = "The migrate task receives the migration credential only."
  }

  assert {
    condition     = [for s in jsondecode(aws_ecs_task_definition.this["bootstrap"].container_definitions)[0].secrets : s.valueFrom] == ["arn:aws:secretsmanager:eu-central-1:111111111111:secret:rds!db-synthetic"]
    error_message = "Only the bootstrap task receives the RDS-managed master secret."
  }

  assert {
    condition = (
      [for s in jsondecode(aws_ecs_task_definition.this["identity_binding"].container_definitions)[0].secrets : s.name] == ["FIRMBATCH_IDENTITY_BINDING_DATABASE_URL"] &&
      !strcontains(aws_iam_role_policy.execution["identity_binding"].policy, "authenticator") &&
      jsondecode(aws_iam_role_policy.task["identity_binding"].policy).Statement[0].Action == "cognito-idp:AdminGetUser"
    )
    error_message = "The identity-binding task holds its own one-function credential and a Cognito user read -- never the authenticator credential."
  }

  assert {
    condition = alltrue([
      for key, definition in aws_ecs_task_definition.this :
      key == "bootstrap" || !strcontains(definition.container_definitions, "rds!db")
    ])
    error_message = "No service or other task references the master secret."
  }

  assert {
    condition = alltrue([
      for policy in aws_iam_role_policy.execution :
      anytrue([for statement in jsondecode(policy.policy).Statement : try(statement.Sid == "PullFromTheReleaseRepository" && statement.Resource == "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane", false)])
    ])
    error_message = "Every execution role pulls from the release repository and no other."
  }

  assert {
    condition = alltrue(concat(
      [for role in aws_iam_role.execution : role.permissions_boundary == "arn:aws:iam::111111111111:policy/firmbatch-staging-workload-boundary"],
      [for role in aws_iam_role.task : role.permissions_boundary == "arn:aws:iam::111111111111:policy/firmbatch-staging-workload-boundary"],
    ))
    error_message = "Every workload role carries the workload permissions boundary."
  }

  assert {
    condition     = !contains(keys(aws_iam_role_policy.task), "web_api") && !contains(keys(aws_iam_role_policy.task), "migrate")
    error_message = "The web/API service and the migrate task hold no AWS permission."
  }

  assert {
    condition     = alltrue([for setting in aws_ecs_cluster.this.setting : setting.name == "containerInsights" && setting.value == "enabled"])
    error_message = "Container Insights, which the running-task alarms read, is the cluster's only setting."
  }
}

run "a_tag_only_image_is_refused_by_the_compute_module" {
  command = plan

  module {
    source = "../../modules/compute"
  }

  # Well-formed values everywhere except the one input under test, so the only refusal is the
  # image reference's own validation.
  variables {
    image                         = "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane:latest"
    account_id                    = "111111111111"
    cluster_name                  = "firmbatch-staging"
    approved_image_repository_url = "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane"
    image_repository_arn          = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane"
    private_subnet_ids            = ["subnet-synthetic-private-a", "subnet-synthetic-private-b"]
    application_port              = 8080
    app_origin                    = "https://staging.app.synthetic.example"
    service_names = {
      web_api         = "firmbatch-staging-web-api"
      identity_broker = "firmbatch-staging-identity-broker"
    }
    task_security_group_ids = {
      web_api          = "sg-synthetic-web-api"
      identity_broker  = "sg-synthetic-identity-broker"
      migrate          = "sg-synthetic-migrate"
      bootstrap        = "sg-synthetic-bootstrap"
      identity_binding = "sg-synthetic-identity-binding"
    }
    target_group_arns = {
      web_api         = "arn:aws:elasticloadbalancing:eu-central-1:111111111111:targetgroup/firmbatch-staging-web-api/synthetic"
      identity_broker = "arn:aws:elasticloadbalancing:eu-central-1:111111111111:targetgroup/firmbatch-staging-broker/synthetic"
    }
    log_group_names = {
      web_api          = "/ecs/firmbatch-staging/web-api"
      identity_broker  = "/ecs/firmbatch-staging/identity-broker"
      migrate          = "/ecs/firmbatch-staging/migrate"
      bootstrap        = "/ecs/firmbatch-staging/bootstrap"
      identity_binding = "/ecs/firmbatch-staging/identity-binding"
    }
    secret_arns = {
      application_database_url      = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/application-database-url"
      authenticator_database_url    = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/authenticator-database-url"
      identity_binding_database_url = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/identity-binding-database-url"
      migration_database_url        = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/migration-database-url"
      cognito_client_secret         = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/cognito-client-secret"
    }
    rds_master_secret_arn             = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:rds!db-synthetic"
    workload_kms_key_arn              = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-00000000000c"
    refresh_token_kms_key_arn         = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-00000000000d"
    workload_permissions_boundary_arn = "arn:aws:iam::111111111111:policy/firmbatch-staging-workload-boundary"
    cognito = {
      user_pool_id  = "eu-central-1_Synthetic"
      user_pool_arn = "arn:aws:cognito-idp:eu-central-1:111111111111:userpool/eu-central-1_Synthetic"
      client_id     = "syntheticclientid"
      issuer        = "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_Synthetic"
    }
  }

  expect_failures = [var.image]
}

run "an_image_from_an_unapproved_repository_is_refused_by_the_compute_module" {
  command = plan

  module {
    source = "../../modules/compute"
  }

  variables {
    image                         = "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch-staging@sha256:5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e"
    account_id                    = "111111111111"
    cluster_name                  = "firmbatch-staging"
    approved_image_repository_url = "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane"
    image_repository_arn          = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane"
    private_subnet_ids            = ["subnet-synthetic-private-a", "subnet-synthetic-private-b"]
    application_port              = 8080
    app_origin                    = "https://staging.app.synthetic.example"
    service_names = {
      web_api         = "firmbatch-staging-web-api"
      identity_broker = "firmbatch-staging-identity-broker"
    }
    task_security_group_ids = {
      web_api          = "sg-synthetic-web-api"
      identity_broker  = "sg-synthetic-identity-broker"
      migrate          = "sg-synthetic-migrate"
      bootstrap        = "sg-synthetic-bootstrap"
      identity_binding = "sg-synthetic-identity-binding"
    }
    target_group_arns = {
      web_api         = "arn:aws:elasticloadbalancing:eu-central-1:111111111111:targetgroup/firmbatch-staging-web-api/synthetic"
      identity_broker = "arn:aws:elasticloadbalancing:eu-central-1:111111111111:targetgroup/firmbatch-staging-broker/synthetic"
    }
    log_group_names = {
      web_api          = "/ecs/firmbatch-staging/web-api"
      identity_broker  = "/ecs/firmbatch-staging/identity-broker"
      migrate          = "/ecs/firmbatch-staging/migrate"
      bootstrap        = "/ecs/firmbatch-staging/bootstrap"
      identity_binding = "/ecs/firmbatch-staging/identity-binding"
    }
    secret_arns = {
      application_database_url      = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/application-database-url"
      authenticator_database_url    = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/authenticator-database-url"
      identity_binding_database_url = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/identity-binding-database-url"
      migration_database_url        = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/migration-database-url"
      cognito_client_secret         = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/cognito-client-secret"
    }
    rds_master_secret_arn             = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:rds!db-synthetic"
    workload_kms_key_arn              = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-00000000000c"
    refresh_token_kms_key_arn         = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-00000000000d"
    workload_permissions_boundary_arn = "arn:aws:iam::111111111111:policy/firmbatch-staging-workload-boundary"
    cognito = {
      user_pool_id  = "eu-central-1_Synthetic"
      user_pool_arn = "arn:aws:cognito-idp:eu-central-1:111111111111:userpool/eu-central-1_Synthetic"
      client_id     = "syntheticclientid"
      issuer        = "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_Synthetic"
    }
  }

  expect_failures = [var.image]
}

run "task_definitions_and_services_do_not_plan_before_m3_3c_review" {
  command = plan

  module {
    source = "../../modules/compute"
  }

  variables {
    runtime_contract_reviewed     = false
    account_id                    = "111111111111"
    cluster_name                  = "firmbatch-staging"
    approved_image_repository_url = "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane"
    image_repository_arn          = "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane"
    image                         = "111111111111.dkr.ecr.eu-central-1.amazonaws.com/firmbatch/control-plane@sha256:5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e"
    private_subnet_ids            = ["subnet-synthetic-private-a", "subnet-synthetic-private-b"]
    application_port              = 8080
    app_origin                    = "https://staging.app.synthetic.example"
    service_names = {
      web_api         = "firmbatch-staging-web-api"
      identity_broker = "firmbatch-staging-identity-broker"
    }
    task_security_group_ids = {
      web_api          = "sg-synthetic-web-api"
      identity_broker  = "sg-synthetic-identity-broker"
      migrate          = "sg-synthetic-migrate"
      bootstrap        = "sg-synthetic-bootstrap"
      identity_binding = "sg-synthetic-identity-binding"
    }
    target_group_arns = {
      web_api         = "arn:aws:elasticloadbalancing:eu-central-1:111111111111:targetgroup/firmbatch-staging-web-api/synthetic"
      identity_broker = "arn:aws:elasticloadbalancing:eu-central-1:111111111111:targetgroup/firmbatch-staging-broker/synthetic"
    }
    log_group_names = {
      web_api          = "/ecs/firmbatch-staging/web-api"
      identity_broker  = "/ecs/firmbatch-staging/identity-broker"
      migrate          = "/ecs/firmbatch-staging/migrate"
      bootstrap        = "/ecs/firmbatch-staging/bootstrap"
      identity_binding = "/ecs/firmbatch-staging/identity-binding"
    }
    secret_arns = {
      application_database_url      = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/application-database-url"
      authenticator_database_url    = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/authenticator-database-url"
      identity_binding_database_url = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/identity-binding-database-url"
      migration_database_url        = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/migration-database-url"
      cognito_client_secret         = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:firmbatch-staging/cognito-client-secret"
    }
    rds_master_secret_arn             = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:rds!db-synthetic"
    workload_kms_key_arn              = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-00000000000c"
    refresh_token_kms_key_arn         = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-00000000000d"
    workload_permissions_boundary_arn = "arn:aws:iam::111111111111:policy/firmbatch-staging-workload-boundary"
    cognito = {
      user_pool_id  = "eu-central-1_Synthetic"
      user_pool_arn = "arn:aws:cognito-idp:eu-central-1:111111111111:userpool/eu-central-1_Synthetic"
      client_id     = "syntheticclientid"
      issuer        = "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_Synthetic"
    }
  }

  # The services' identical precondition is asserted by infra/terraform/policy/check.py: once a
  # task definition refuses to plan, the services that reference it are not evaluated at all.
  expect_failures = [aws_ecs_task_definition.this]
}

# ====================================================================== delivery

# The GitHub delivery identities -- the plan, apply and artifact-publish roles, their policies and
# boundaries -- are the bootstrap root's, and infra/terraform/bootstrap/tests evaluates them. The
# delivery module keeps only the environment's workload boundary and the operator's
# identity-binding policy, both created by the human's first staging apply.

run "delivery_keeps_only_the_workload_boundary_and_the_operator_policy" {
  command = plan

  module {
    source = "../../modules/delivery"
  }

  variables {
    account_id   = "111111111111"
    cluster_name = "firmbatch-staging"
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_policy.workload_boundary.policy).Statement :
      try(
        statement.Sid == "PullTheReleaseRepository" &&
        statement.Resource == "arn:aws:ecr:eu-central-1:111111111111:repository/firmbatch/control-plane" &&
        length(setintersection(flatten([statement.Action]), ["ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:BatchDeleteImage"])) == 0,
        false
      )
    ])
    error_message = "Workloads pull from the release repository and push, re-tag or delete nothing."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_policy.workload_boundary.policy).Statement :
      try(statement.Sid == "NeverTheBootstrapKeysOrBuckets" && statement.Effect == "Deny" && contains(statement.Resource, "arn:aws:s3:::synthetic-firmbatch-plans/*"), false)
    ])
    error_message = "No workload role reaches the state or plan buckets or their keys."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_policy.operator_identity_binding.policy).Statement :
      try(
        statement.Sid == "PassOnlyTheIdentityBindingTasksOwnRoles" &&
        statement.Resource == ["arn:aws:iam::111111111111:role/firmbatch-staging-identity-binding-execution", "arn:aws:iam::111111111111:role/firmbatch-staging-identity-binding-task"] &&
        statement.Condition.StringEquals["iam:PassedToService"] == "ecs-tasks.amazonaws.com",
        false
      )
    ])
    error_message = "The operator passes only the identity-binding task's own two roles, to ECS tasks."
  }
}
