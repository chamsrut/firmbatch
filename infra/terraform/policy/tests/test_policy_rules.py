"""Every repository policy rule passes on the real repository, and refuses when the property
it protects is removed.

Each negative test copies the real repository's files into a :class:`check.Tree`, changes one
thing -- the smallest edit that removes one property -- and asserts the named rule reports it.
A rule that still passed after its property was removed would be a check that proves nothing.
"""

import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from policy import check  # noqa: E402

REPOSITORY = check.Tree.from_repository()
TF = check.TF
COMPUTE = f"{TF}/modules/compute"
DELIVERY = f"{TF}/modules/delivery"
BOOTSTRAP = check.BOOTSTRAP
POLICIES = f"{BOOTSTRAP}/delivery_policies.tf"
IDENTITIES = f"{BOOTSTRAP}/github_oidc.tf"
ARTIFACTS = check.ARTIFACTS


def mutated(path, old, new, count=1):
    return edited({path: [(old, new, count)]})


def edited(changes):
    """Apply several exact edits, across files; each old text must still be present."""
    files = dict(REPOSITORY.files)
    for path, edits in changes.items():
        for edit in edits:
            old, new, count = (*edit, 1) if len(edit) == 2 else edit
            if old not in files[path]:
                raise AssertionError(f"{path} no longer contains the text this test mutates: {old!r}")
            files[path] = files[path].replace(old, new, count)
    return check.Tree(files, REPOSITORY.listed)


def added(path, content, listed_only=False):
    files = dict(REPOSITORY.files)
    if not listed_only:
        files[path] = content
    return check.Tree(files, REPOSITORY.listed + [path])


def resource(kind, name, *body):
    return f'resource "{kind}" "{name}" {{\n' + "".join(f"  {line}\n" for line in body) + "}\n"


GUARD = "    if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.repository_id == '1349512121'\n"
FORMER_IAM_DENY = (
    "      {{\n"
    '        Sid       = "{sid}"\n'
    '        Effect    = "Deny"\n'
    '        NotAction = ["iam:Get*", "iam:List*", "iam:PassRole"]\n'
    '        Resource  = "*"\n'
    '        Condition = {{ StringLike = {{ "aws:RequestedRegion" = "*" }} }}\n'
    "      }},\n"
)
BEFORE_ACCOUNT_DENY = '      {\n        Sid      = "DenyIdentityAndAccountAdministration"'


class RepositoryIsClean(unittest.TestCase):
    def test_no_rule_reports_anything_on_the_repository(self):
        self.assertEqual(check.run_rules(REPOSITORY), [])


class Refusals(unittest.TestCase):
    def assertReports(self, rule, tree, fragment=""):
        findings = rule(tree)
        self.assertTrue(findings, f"{rule.__name__} reported nothing")
        if fragment:
            mentioned = any(fragment in f for f in findings)
            self.assertTrue(mentioned, f"{rule.__name__}: no finding mentions {fragment!r}: {findings}")

    # ------------------------------------------------------------------ compute

    def test_public_ecs_tasks(self):
        tree = mutated(f"{COMPUTE}/main.tf", "assign_public_ip = false", "assign_public_ip = true")
        self.assertReports(check.rule_compute, tree, "public IP")

    def test_ecs_exec(self):
        old = "enable_execute_command            = false"
        tree = mutated(f"{COMPUTE}/main.tf", old, old.replace("false", "true"))
        self.assertReports(check.rule_compute, tree, "ECS Exec")

    def test_ecs_exec_on_the_cluster(self):
        tree = mutated(
            f"{COMPUTE}/main.tf",
            "  # No execute_command_configuration: ECS Exec is not enabled for any service or task.\n",
            "  configuration {\n    execute_command_configuration {\n      logging = \"DEFAULT\"\n    }\n  }\n",
        )
        self.assertReports(check.rule_compute, tree, "ECS Exec")

    def test_mutable_image_tags(self):
        tree = mutated(f"{COMPUTE}/main.tf", "  image = var.image\n", '  image = "${var.approved_image_repository_url}:latest"\n')
        self.assertReports(check.rule_compute, tree, "tag")

    def test_digest_validation_removed(self):
        tree = mutated(f"{COMPUTE}/variables.tf", "@sha256:[0-9a-f]{64}$", "(:[a-z0-9._-]+)?$")
        self.assertReports(check.rule_compute, tree, "sha256")

    def test_approved_repository_validation_removed(self):
        condition = 'startswith(var.image, "${var.approved_image_repository_url}@sha256:")'
        tree = mutated(f"{COMPUTE}/variables.tf", condition, "true")
        self.assertReports(check.rule_compute, tree, "approved release repository")

    def test_task_definitions_that_deregister_on_rollout(self):
        tree = mutated(f"{COMPUTE}/main.tf", "  skip_destroy = true\n", "  skip_destroy = false\n")
        self.assertReports(check.rule_compute, tree, "skip_destroy")

    def test_container_hardening_removed(self):
        for fragment, (old, new) in {
            "read-only root filesystem": ("readonlyRootFilesystem = true", "readonlyRootFilesystem = false"),
            "unprivileged": ("privileged             = false", "privileged             = true"),
            "non-root user": ('user                   = "10001:10001"', 'user                   = "0"'),
            "every capability dropped": ('drop = ["ALL"]', 'drop = []'),
            "added capability": (
                'capabilities       = { drop = ["ALL"] }', 'capabilities       = { drop = ["ALL"], add = ["SYS_ADMIN"] }'
            ),
        }.items():
            with self.subTest(fragment=fragment):
                self.assertReports(check.rule_compute, mutated(f"{COMPUTE}/main.tf", old, new), fragment)

    def test_identity_binding_given_the_authenticator_credential(self):
        binding = "FIRMBATCH_IDENTITY_BINDING_DATABASE_URL = var.secret_arns.identity_binding_database_url\n"
        authenticator = "        FIRMBATCH_AUTHENTICATOR_DATABASE_URL = var.secret_arns.authenticator_database_url\n"
        tree = mutated(f"{COMPUTE}/main.tf", binding, binding + authenticator)
        self.assertReports(check.rule_compute, tree, "identity_binding")

    def test_runtime_contract_precondition_removed(self):
        tree = mutated(f"{COMPUTE}/main.tf", "condition     = var.runtime_contract_reviewed", "condition     = true")
        self.assertReports(check.rule_compute, tree, "runtime_contract_reviewed")

    # ------------------------------------------------------------------ database and network

    def test_publicly_accessible_rds(self):
        tree = mutated(f"{TF}/modules/database/main.tf", "publicly_accessible    = false", "publicly_accessible    = true")
        self.assertReports(check.rule_database, tree, "publicly_accessible")

    def test_rds_without_enforced_ssl_backups_or_a_16_minor(self):
        database = f"{TF}/modules/database/main.tf"
        cases = {
            "rds.force_ssl": (database, 'value        = "1"', 'value        = "0"'),
            "seven days": (database, "backup_retention_days = 7", "backup_retention_days = 1"),
            "16.x minor": (database, "^16\\\\.[0-9]+$", "^[0-9.]+$"),
        }
        for fragment, (path, old, new) in cases.items():
            with self.subTest(fragment=fragment):
                self.assertReports(check.rule_database, mutated(path, old, new), fragment)

    def test_service_without_circuit_breaker_rollback(self):
        tree = mutated(f"{COMPUTE}/main.tf", "rollback = true", "rollback = false")
        self.assertReports(check.rule_compute, tree, "rolls back")

    def test_identity_pool_client_and_waf_departures(self):
        identity = f"{TF}/modules/identity/main.tf"
        cases = {
            "MFA is required": ('mfa_configuration = "ON"', 'mfa_configuration = "OPTIONAL"'),
            "invite-only": ("allow_admin_create_user_only = true", "allow_admin_create_user_only = false"),
            "authorization-code grant only": ('= ["code"]', '= ["code", "implicit"]'),
            "openid and email only": ('["openid", "email"]', '["openid", "email", "aws.cognito.signin.user.admin"]'),
            "confidential client": ("generate_secret = true", "generate_secret = false"),
            "Managed Login v2": ("managed_login_version = 2", "managed_login_version = 1"),
            "us-east-1": ("  provider = aws.us_east_1\n\n  domain_name", "  domain_name"),
            "associated with the Cognito user pool": ("resource_arn = aws_cognito_user_pool.this.arn", 'resource_arn = "synthetic"'),
        }
        for fragment, (old, new) in cases.items():
            with self.subTest(fragment=fragment):
                self.assertReports(check.rule_identity, mutated(identity, old, new), fragment)

    def test_dependencies_not_installed_from_the_locks(self):
        tree = mutated("Dockerfile", "--require-hashes ", "")
        self.assertReports(check.rule_container, tree, "locks")

    def test_rds_without_final_snapshot(self):
        tree = mutated(f"{TF}/modules/database/main.tf", "skip_final_snapshot       = false", "skip_final_snapshot       = true")
        self.assertReports(check.rule_database, tree, "skip_final_snapshot")

    def test_unrestricted_ingress(self):
        rule = resource(
            "aws_vpc_security_group_ingress_rule", "open",
            "security_group_id = aws_security_group.alb.id", 'cidr_ipv4 = "0.0.0.0/0"', 'ip_protocol = "-1"',
        )
        self.assertReports(check.rule_network_ingress, added(f"{TF}/modules/network/open.tf", rule), "whole internet")

    def test_ingress_from_a_cidr_outside_the_validated_list(self):
        rule = resource(
            "aws_vpc_security_group_ingress_rule", "extra",
            "security_group_id = aws_security_group.alb.id", 'cidr_ipv4 = "11.22.33.0/24"', 'ip_protocol = "tcp"',
        )
        tree = added(f"{TF}/modules/network/extra.tf", rule)
        self.assertReports(check.rule_network_ingress, tree, "validated reviewer allow-list")

    def test_inline_security_group_ingress(self):
        tree = mutated(
            f"{TF}/modules/network/security_groups.tf",
            "  revoke_rules_on_delete = true\n\n  tags = { Name = \"${var.name_prefix}-database\" }",
            "  revoke_rules_on_delete = true\n\n  ingress {\n    from_port = 0\n  }\n\n  tags = { Name = \"${var.name_prefix}-database\" }",
        )
        self.assertReports(check.rule_network_ingress, tree, "inline")

    def test_auth_routed_to_the_web_api_service(self):
        broker = 'target_group_arn = aws_lb_target_group.service["identity_broker"].arn'
        tree = mutated(f"{TF}/modules/edge/main.tf", broker, broker.replace("identity_broker", "web_api"))
        self.assertReports(check.rule_network_ingress, tree, "identity_broker")

    def test_http_listener_that_forwards(self):
        tree = mutated(f"{TF}/modules/edge/main.tf", 'type = "redirect"', 'type = "forward"')
        self.assertReports(check.rule_network_ingress, tree, "port 80")

    def test_alb_access_logs_enabled(self):
        tree = mutated(
            f"{TF}/modules/edge/main.tf",
            "  # No access_logs block: ALB access logs stay disabled for M3.3 (ADR 0011 decision 10).\n",
            "  access_logs {\n    bucket  = \"synthetic\"\n    enabled = true\n  }\n",
        )
        self.assertReports(check.rule_network_ingress, tree, "access logs")

    # ------------------------------------------------------------------ secrets and forbidden constructs

    def test_secret_value_in_terraform(self):
        version = resource("aws_secretsmanager_secret_version", "leak", 'secret_id = "x"', 'secret_string = "synthetic"')
        tree = added(f"{TF}/modules/secrets/value.tf", version)
        self.assertReports(check.rule_forbidden_constructs, tree, "aws_secretsmanager_secret_version")
        self.assertReports(check.rule_no_secret_values, tree, "secret_string")

    def test_password_in_the_database(self):
        username = 'username                      = "firmbatch_master"'
        tree = mutated(f"{TF}/modules/database/main.tf", username, username + '\n  password = "synthetic"')
        self.assertReports(check.rule_no_secret_values, tree, "password")

    def test_random_password(self):
        tree = added(f"{TF}/modules/secrets/random.tf", resource("random_password", "db", "length = 32"))
        self.assertReports(check.rule_forbidden_constructs, tree, "random_password")

    def test_valued_tfvars_file(self):
        tree = added(f"{TF}/environments/staging/staging.tfvars", "", listed_only=True)
        self.assertReports(check.rule_no_valued_tfvars, tree, "staging.tfvars")

    def test_values_in_the_example_tfvars(self):
        example = f"{TF}/environments/staging/staging.tfvars.example"
        tree = mutated(example, 'expected_account_id = ""', 'expected_account_id = "123456789012"')
        self.assertReports(check.rule_no_valued_tfvars, tree, "example")

    def test_state_or_plan_file_in_the_repository(self):
        for name in ("terraform.tfstate", "staging.tfplan", "crash.log"):
            with self.subTest(name=name):
                tree = added(f"{TF}/environments/staging/{name}", "", listed_only=True)
                self.assertReports(check.rule_no_valued_tfvars, tree)

    def test_postgresql_provider(self):
        aws = '    aws = {\n      source  = "hashicorp/aws"\n      version = "6.64.0"\n    }\n'
        postgresql = '    postgresql = {\n      source = "cyrilgdn/postgresql"\n    }\n'
        tree = mutated(f"{TF}/modules/database/versions.tf", aws, aws + postgresql)
        self.assertReports(check.rule_versions, tree, "postgresql")
        self.assertReports(check.rule_forbidden_constructs, tree, "postgresql")

    def test_postgresql_resource(self):
        tree = added(f"{TF}/modules/database/roles.tf", resource("postgresql_role", "app", 'name = "app"'))
        self.assertReports(check.rule_forbidden_constructs, tree, "postgresql_role")

    def test_provisioner(self):
        source = 'resource "terraform_data" "sql" {\n  provisioner "local-exec" {\n    command = "psql -c select"\n  }\n}\n'
        self.assertReports(check.rule_forbidden_constructs, added(f"{TF}/modules/database/run.tf", source), "provisioner")

    def test_alb_cognito_authentication(self):
        forward = (
            '  action {\n    type             = "forward"\n'
            '    target_group_arn = aws_lb_target_group.service["identity_broker"].arn\n  }'
        )
        tree = mutated(f"{TF}/modules/edge/main.tf", forward, '  action {\n    type = "authenticate-cognito"\n  }')
        self.assertReports(check.rule_forbidden_constructs, tree, "ALB authentication")

    def test_cognito_identity_pool_and_groups(self):
        for kind in ("aws_cognito_identity_pool", "aws_cognito_user_group", "aws_cognito_user"):
            with self.subTest(resource=kind):
                tree = added(f"{TF}/modules/identity/extra.tf", resource(kind, "x", 'name = "x"'))
                self.assertReports(check.rule_forbidden_constructs, tree, kind)

    def test_workspace_reference(self):
        key = 'state_key = "staging/terraform.tfstate"'
        tree = mutated(f"{TF}/environments/staging/main.tf", key, 'state_key = "${terraform.workspace}/terraform.tfstate"')
        self.assertReports(check.rule_backends_and_workspaces, tree, "workspaces")

    def test_dynamodb_locking(self):
        tree = mutated(f"{TF}/environments/staging/versions.tf", "use_lockfile = true", 'use_lockfile = true\n    dynamodb_table = "locks"')
        self.assertReports(check.rule_backends_and_workspaces, tree, "dynamodb_table")

    # ------------------------------------------------------------------ layout: JSON and override configuration

    def test_json_syntax_terraform_configuration(self):
        for path in (f"{TF}/bootstrap/extra.tf.json", f"{TF}/modules/delivery/policies.tf.json", "infra/delivery/x.tf.json"):
            with self.subTest(path=path):
                self.assertReports(check.rule_layout, added(path, "{}"), "JSON-syntax Terraform")

    def test_terraform_override_files(self):
        for name in ("override.tf", "backend_override.tf", "override.tf.json", "iam_override.tf.json"):
            with self.subTest(name=name):
                self.assertReports(check.rule_layout, added(f"{TF}/bootstrap/{name}", ""), "override files")

    def test_override_directories_plugin_mirrors_and_cli_configuration(self):
        cases = (
            (f"{TF}/modules/network/overrides/main.tf", False),
            (f"{TF}/environments/staging/local_override/providers.tf", False),
            (f"{TF}/terraform.d/plugins/registry.terraform.io/hashicorp/aws/6.64.0/linux_amd64/terraform-provider-aws", False),
            (".terraformrc", True),
            ("infra/terraform/terraform.rc", True),
        )
        for path, listed_only in cases:
            with self.subTest(path=path):
                self.assertReports(check.rule_layout, added(path, "", listed_only=listed_only), "override directories")

    # ------------------------------------------------------------------ account restrictions and test reach

    def test_missing_account_restriction(self):
        tree = mutated(f"{TF}/environments/staging/providers.tf", "  allowed_account_ids = [var.expected_account_id]\n", "")
        self.assertReports(check.rule_account_and_region, tree, "allowed_account_ids")

    def test_missing_caller_identity_postcondition(self):
        tree = mutated(f"{TF}/bootstrap/providers.tf", "self.account_id == var.expected_account_id", "true")
        self.assertReports(check.rule_account_and_region, tree, "postcondition")

    def test_a_terraform_test_that_could_reach_aws(self):
        path = f"{TF}/environments/staging/tests/staging.tftest.hcl"
        alias = 'mock_provider "aws" {\n  alias           = "us_east_1"'
        tree = mutated(path, alias, alias.replace("us_east_1", "us_west_2"))
        self.assertReports(check.rule_tests_are_mocked, tree, "us_east_1")

    def test_a_test_with_a_real_provider_block(self):
        path = f"{TF}/bootstrap/tests/bootstrap.tftest.hcl"
        marker = "# Synthetic values only.\n"
        tree = mutated(path, marker, 'provider "aws" {\n  region = "eu-central-1"\n}\n\n' + marker)
        self.assertReports(check.rule_tests_are_mocked, tree, "real provider")

    def test_a_test_that_applies(self):
        path = f"{TF}/bootstrap/tests/bootstrap.tftest.hcl"
        tree = mutated(path, "  command = plan\n", "  command = apply\n")
        self.assertReports(check.rule_tests_are_mocked, tree, "command = plan")

    def test_a_json_terraform_test(self):
        tree = added(f"{TF}/environments/staging/tests/extra.tftest.json", '{"run": {"x": {"command": "apply"}}}')
        self.assertReports(check.rule_layout, tree, "JSON Terraform tests")

    def test_a_test_outside_a_root(self):
        tree = added(f"{TF}/modules/network/tests/network.tftest.hcl", 'run "x" {\n  command = plan\n}\n')
        self.assertReports(check.rule_layout, tree, "outside")

    # ------------------------------------------------------------------ delivery identities: the bootstrap root

    def test_wildcard_oidc_subject(self):
        subject = '"${local.oidc_host}:sub" = "repo:${local.github_repository}:environment:${environment}"'
        tree = mutated(IDENTITIES, subject, '"${local.oidc_host}:sub" = "repo:${local.github_repository}:*"')
        self.assertReports(check.rule_delivery_trust, tree, "exact repository and environment")

    def test_string_like_trust(self):
        tree = mutated(IDENTITIES, "StringEquals = {", "StringLike = {")
        self.assertReports(check.rule_delivery_trust, tree, "wildcard")

    def test_wrong_audience(self):
        audience = '"${local.oidc_host}:aud" = "sts.amazonaws.com"'
        tree = mutated(IDENTITIES, audience, '"${local.oidc_host}:aud" = "github"')
        self.assertReports(check.rule_delivery_trust, tree, "audience")

    def test_shared_plan_and_apply_trust(self):
        apply_trust = "assume_role_policy   = local.trust_policy[local.apply_environment]"
        tree = mutated(IDENTITIES, apply_trust, apply_trust.replace("apply_environment", "plan_environment"))
        self.assertReports(check.rule_delivery_trust, tree, "only through its own environment")

    def test_apply_trust_through_the_plan_environment(self):
        old = 'apply_environment   = "${var.environment}-apply"'
        tree = mutated(f"{BOOTSTRAP}/main.tf", old, old.replace("-apply", "-plan"))
        self.assertReports(check.rule_delivery_trust, tree, "staging-apply")

    def test_publish_trust_widened(self):
        tree = mutated(f"{BOOTSTRAP}/main.tf", 'publish_environment = "artifact-publish"', 'publish_environment = "*"')
        self.assertReports(check.rule_delivery_trust, tree, "artifact-publish environments exactly")

    def test_environment_validation_weakened(self):
        tree = mutated(f"{BOOTSTRAP}/variables.tf", 'var.environment == "staging"', 'var.environment != ""')
        self.assertReports(check.rule_delivery_trust, tree, "staging environment only")

    def test_missing_permissions_boundaries(self):
        for boundary in ("apply_boundary", "artifact_publish_boundary"):
            with self.subTest(boundary=boundary):
                line = f"aws_iam_policy.{boundary}.arn\n"
                tree = mutated(IDENTITIES, f"  permissions_boundary = {line}", "")
                self.assertReports(check.rule_delivery_trust, tree, "permissions boundary")

    def test_a_delivery_identity_outside_the_bootstrap_root(self):
        role = resource("aws_iam_role", "github_apply", 'name = "firmbatch-staging-github-apply"', 'assume_role_policy = "{}"')
        for path in (f"{DELIVERY}/roles.tf", f"{ARTIFACTS}/roles.tf", f"{TF}/environments/staging/roles.tf"):
            with self.subTest(path=path):
                self.assertReports(check.rule_delivery_trust, added(path, role), "bootstrap root")

    def test_the_oidc_provider_outside_the_bootstrap_root(self):
        provider = resource(
            "aws_iam_openid_connect_provider", "github",
            'url = "https://token.actions.githubusercontent.com"', 'client_id_list = ["sts.amazonaws.com"]',
        )
        self.assertReports(check.rule_delivery_trust, added(f"{DELIVERY}/oidc.tf", provider), "bootstrap root")

    def test_boundary_missing_any_required_deny(self):
        for sid in check.APPLY_BOUNDARY_DENIES:
            with self.subTest(sid=sid):
                tree = mutated(POLICIES, f'"{sid}"', '"Renamed"')
                self.assertReports(check.rule_delivery_trust, tree, sid)

    def test_apply_role_passing_any_role(self):
        grant = (
            'Resource  = local.workload_role_arns\n'
            '        Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }\n'
            '      },\n      {\n        Sid    = "ManageTheDatabase'
        )
        tree = mutated(POLICIES, grant, grant.replace("local.workload_role_arns", '"*"'))
        self.assertReports(check.rule_delivery_trust, tree, "iam:PassRole only on local.workload_role_arns")

    def test_apply_role_passing_roles_to_another_service(self):
        passed = (
            '{ StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }\n'
            '      },\n      {\n        Sid    = "ManageTheDatabase'
        )
        tree = mutated(POLICIES, passed, passed.replace("ecs-tasks.amazonaws.com", "lambda.amazonaws.com"))
        self.assertReports(check.rule_delivery_trust, tree, "ecs-tasks.amazonaws.com only")

    def test_apply_boundary_letting_any_role_be_passed(self):
        tree = mutated(POLICIES, "NotResource = local.workload_role_arns", 'NotResource = ["*"]')
        self.assertReports(check.rule_delivery_trust, tree, "pre-created workload roles")

    def test_apply_boundary_ceiling_passing_any_role(self):
        ceiling = (
            'Resource  = local.workload_role_arns\n'
            '        Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }\n'
            '      },\n      {\n        # Defense'
        )
        tree = mutated(POLICIES, ceiling, ceiling.replace("local.workload_role_arns", '"*"'))
        self.assertReports(check.rule_delivery_trust, tree, "admits iam:PassRole only on the ten workload roles")

    def test_apply_boundary_ceiling_admitting_an_iam_mutation(self):
        for addition in ('"iam:*", ', '"iam:PutRolePolicy", ', '"*", '):
            with self.subTest(addition=addition):
                ceiling = '"sts:GetCallerIdentity", "s3:*", "kms:*",'
                tree = mutated(POLICIES, ceiling, addition + ceiling)
                self.assertReports(check.rule_delivery_trust, tree, "ceiling admits")

    def test_apply_role_registering_task_definitions_outside_the_contract(self):
        tree = mutated(POLICIES, "Resource = local.task_definition_arns", 'Resource = "*"')
        self.assertReports(check.rule_delivery_trust, tree, "ecs:RegisterTaskDefinition only")

    def test_apply_role_granted_deregistration(self):
        grant = 'Action   = "ecs:RegisterTaskDefinition"'
        tree = mutated(POLICIES, grant, 'Action   = ["ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition"]')
        self.assertReports(check.rule_delivery_trust, tree, "ecs:DeregisterTaskDefinition")

    def test_a_service_rollout_without_its_family_ecs_exec_or_cluster_conditions(self):
        cases = {
            "family": ('ArnLikeIfExists      = { "ecs:task-definition" = local.service_task_definition_arns.web_api }\n', ""),
            "another family": ("local.service_task_definition_arns.web_api }", "local.service_task_definition_arns.identity_broker }"),
            "ECS Exec": ('StringEqualsIfExists = { "ecs:enable-execute-command" = "false" }\n', ""),
        }
        for name, (old, new) in cases.items():
            with self.subTest(case=name):
                self.assertReports(check.rule_delivery_trust, mutated(POLICIES, old, new), "requires its own family")

    def test_boundary_family_and_ecs_exec_denies_weakened(self):
        cases = {
            "family deny without the presence test": ('Null       = { "ecs:task-definition" = "false" }\n', "", "its own family"),
            "family deny naming another family": (
                'ArnNotLike = { "ecs:task-definition" = local.service_task_definition_arns.web_api }',
                'ArnNotLike = { "ecs:task-definition" = local.service_task_definition_arns.identity_broker }', "its own family",
            ),
            "exec deny weakened": (
                'StringNotEquals = { "ecs:enable-execute-command" = "false" }',
                'StringNotEquals = { "ecs:enable-execute-command" = "true" }',
                "ECS Exec",
            ),
        }
        for name, (old, new, fragment) in cases.items():
            with self.subTest(case=name):
                self.assertReports(check.rule_delivery_trust, mutated(POLICIES, old, new), fragment)

    def test_plan_or_apply_role_that_can_push(self):
        cluster = '"ecs:CreateCluster", "ecs:UpdateCluster"'
        self.assertReports(check.rule_delivery_trust, mutated(POLICIES, cluster, cluster + ', "ecr:PutImage"'), "ecr:PutImage")
        denied = (
            '"ecr:GetAuthorizationToken", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage",\n'
            '          "ecr:BatchDeleteImage", "ecr:PutImageTagMutability",\n'
            '          "cognito-idp:ListUsers"'
        )
        tree = mutated(POLICIES, denied, '"cognito-idp:ListUsers"')
        self.assertReports(check.rule_delivery_trust, tree, "plan role is denied every image push")

    def test_human_applied_types_blocking_the_pipeline(self):
        prefixes = "HUMAN_APPLIED_TYPE_PREFIXES = (\n"
        tree = mutated("infra/delivery/delivery.py", prefixes, prefixes + '    "aws_ecs_",\n')
        self.assertReports(check.rule_delivery_trust, tree, "refuses the pipeline's own changes")

    def test_apply_role_granted_an_iam_change(self):
        cluster = '"ecs:CreateCluster", "ecs:UpdateCluster"'
        tree = mutated(POLICIES, cluster, '"iam:UpdateAssumeRolePolicy", ' + cluster)
        self.assertReports(check.rule_delivery_trust, tree, "iam:UpdateAssumeRolePolicy")

    def test_apply_role_granted_a_secret_value_or_a_one_off_task(self):
        rds_secret = 'Action    = ["secretsmanager:CreateSecret", "secretsmanager:TagResource", "secretsmanager:DeleteSecret"]'
        cluster = '"ecs:CreateCluster", "ecs:UpdateCluster"'
        for fragment, old, new in (
            ("secretsmanager:UpdateSecret", rds_secret, rds_secret.replace("]", ', "secretsmanager:UpdateSecret"]')),
            ("ecs:RunTask", cluster, cluster + ', "ecs:RunTask"'),
        ):
            with self.subTest(fragment=fragment):
                self.assertReports(check.rule_delivery_trust, mutated(POLICIES, old, new), fragment)

    def test_plan_role_allowed_to_read_plan_history(self):
        grant = 'Action   = "s3:PutObject"\n        Resource = local.environment_plans_arn'
        widened = grant.replace('"s3:PutObject"', '["s3:PutObject", "s3:GetObjectVersion"]')
        self.assertReports(check.rule_delivery_trust, mutated(POLICIES, grant, widened), "s3:GetObjectVersion")

    def test_plan_role_allowed_to_apply(self):
        reads = '"sts:GetCallerIdentity",\n          "ec2:Describe*",'
        widened = '"sts:GetCallerIdentity",\n          "ec2:CreateVpc",\n          "ec2:Describe*",'
        self.assertReports(check.rule_delivery_trust, mutated(POLICIES, reads, widened), "ec2:CreateVpc")

    def test_apply_role_allowed_to_enumerate_plan_versions(self):
        grant = 'Action   = ["s3:GetObjectVersion", "s3:GetObjectRetention"]'
        widened = grant.replace("]", ', "s3:ListBucketVersions"]')
        self.assertReports(check.rule_delivery_trust, mutated(POLICIES, grant, widened), "s3:ListBucketVersions")

    def test_human_applied_types_drift(self):
        tree = mutated("infra/delivery/delivery.py", '    "aws_secretsmanager_",', "")
        self.assertReports(check.rule_delivery_trust, tree, "HUMAN_APPLIED_TYPE_PREFIXES")

    def test_artifact_publish_granted_more_than_publication(self):
        grant = '"ecr:PutImage", "ecr:BatchGetImage", "ecr:DescribeImages", "ecr:GetDownloadUrlForLayer",'
        actions = ("ecs:UpdateService", "iam:PassRole", "sts:AssumeRole", "secretsmanager:GetSecretValue", "kms:Encrypt", "s3:DeleteObject")
        for action in actions:
            with self.subTest(action=action):
                tree = mutated(POLICIES, grant, grant + f' "{action}",')
                self.assertReports(check.rule_delivery_trust, tree, action)

    def test_artifact_publish_using_the_release_key_through_ecr(self):
        via = (
            'Resource  = aws_kms_key.release.arn\n'
            '        Condition = { StringEquals = { "kms:ViaService" = "s3.${var.artifact_registry_region}.amazonaws.com" } }\n'
            '      },\n      {\n        Sid      = "CallerIdentity"'
        )
        tree = mutated(POLICIES, via, via.replace('"s3.${var.artifact_registry_region}', '"ecr.${var.artifact_registry_region}'))
        self.assertReports(check.rule_delivery_trust, tree, "through S3 in the declared registry region only")
        self.assertReports(check.rule_policy_semantics, tree, "artifact-publish role cannot kms:GenerateDataKey")

    # ------------------------------------------------------------------ policy semantics: evaluated, not read

    def test_the_former_iam_deny_denied_every_non_iam_operation(self):
        tree = mutated(POLICIES, BEFORE_ACCOUNT_DENY, FORMER_IAM_DENY.format(sid="DenyEveryIamChange") + BEFORE_ACCOUNT_DENY)
        self.assertReports(check.rule_delivery_trust, tree, "DenyEveryIamChange")
        for fragment in ("cannot s3:GetObject", "cannot ec2:CreateVpc", "cannot rds:CreateDBInstance", "cannot ecs:UpdateService",
                         "denies or allows everything except a short allow-list"):
            with self.subTest(fragment=fragment):
                self.assertReports(check.rule_policy_semantics, tree, fragment)

    def test_a_broad_not_action_deny_is_refused_for_what_it_does_not_its_name(self):
        tree = mutated(POLICIES, BEFORE_ACCOUNT_DENY, FORMER_IAM_DENY.format(sid="DenyOnlyTheUsualThings") + BEFORE_ACCOUNT_DENY)
        self.assertEqual(check.rule_delivery_trust(tree), [])
        self.assertReports(check.rule_policy_semantics, tree, "statement DenyOnlyTheUsualThings denies or allows everything except")

    def test_a_region_deny_that_loses_its_region_condition_denies_everything(self):
        condition = '        Condition = { StringNotEquals = { "aws:RequestedRegion" = [var.region, "us-east-1"] } }\n'
        tree = mutated(POLICIES, condition, "")
        self.assertReports(check.rule_policy_semantics, tree, "statement DenyRegionsOutsideStagingAndTheCertificateRegion denies")
        self.assertReports(check.rule_policy_semantics, tree, "cannot s3:PutObject")

    def test_not_resource_and_not_action_allows_are_refused(self):
        grant = (
            '"ecs:CreateCluster", "ecs:UpdateCluster", "ecs:DeleteCluster", "ecs:Describe*", '
            '"ecs:List*", "ecs:TagResource", "ecs:UntagResource"]\n'
            '        Resource  = "*"'
        )
        tree = mutated(POLICIES, grant, grant.replace('Resource  = "*"', 'NotResource = "arn:aws:ecs:*:*:cluster/other"'))
        self.assertReports(check.rule_policy_semantics, tree, "ManageTheCluster denies or allows everything except")
        tree = mutated(POLICIES, 'Sid    = "CeilingIsTheAcceptedStagingFamilies"\n        Effect = "Allow"\n        Action = [',
                       'Sid    = "CeilingIsTheAcceptedStagingFamilies"\n        Effect = "Allow"\n        NotAction = [')
        self.assertReports(check.rule_policy_semantics, tree, "CeilingIsTheAcceptedStagingFamilies denies or allows everything except")

    def test_a_not_resource_deny_over_every_service_is_refused(self):
        every_service = 'Action      = "s3:*"\n        NotResource = [local.state_bucket_arn'
        tree = mutated(POLICIES, every_service, every_service.replace('"s3:*"', '"*"'))
        self.assertReports(check.rule_policy_semantics, tree, "DenyS3OutsideStatePlansAndReleaseRecords denies or allows everything except")

    def test_each_representative_staging_request_the_apply_role_needs(self):
        cases = {
            "cannot s3:GetObject": ('NotResource = [local.state_bucket_arn, "${local.state_bucket_arn}/*", ', "NotResource = ["),
            "cannot s3:GetObjectVersion on arn:aws:s3:::synthetic-plans": (
                'Action   = ["s3:GetObjectVersion", "s3:GetObjectRetention"]', 'Action   = ["s3:GetObjectRetention"]',
            ),
            "cannot ec2:CreateVpc": (
                '"ec2:RunInstances", "ec2:StartInstances",', '"ec2:CreateVpc", "ec2:RunInstances", "ec2:StartInstances",',
            ),
            "cannot rds:CreateDBInstance": (
                'StringNotEqualsIfExists = { "rds:DatabaseClass" = var.rds_instance_class }',
                'StringLike = { "aws:RequestedRegion" = "*" }',
            ),
            "cannot ecs:RegisterTaskDefinition": (
                '["ecs:RunTask", "ecs:StartTask", "ecs:ExecuteCommand", "ecs:CreateTaskSet"',
                '["ecs:RegisterTaskDefinition", "ecs:RunTask", "ecs:StartTask", "ecs:ExecuteCommand", "ecs:CreateTaskSet"',
            ),
            "cannot ecs:UpdateService": ('NotResource = local.service_arn_list', 'NotResource = []'),
            "cannot cloudwatch:PutMetricAlarm": (
                '"cloudwatch:DisableAlarmActions", "cloudwatch:SetAlarmState",', '"cloudwatch:PutMetricAlarm", "cloudwatch:SetAlarmState",',
            ),
            "cannot budgets:ModifyBudget": (
                '"budgets:CreateBudgetAction", "budgets:UpdateBudgetAction",', '"budgets:ModifyBudget", "budgets:UpdateBudgetAction",',
            ),
            "cannot iam:PassRole": (
                'Condition = { StringNotEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }',
                'Condition = { StringNotEquals = { "iam:PassedToService" = "ecs.amazonaws.com" } }',
            ),
        }
        for fragment, (old, new) in cases.items():
            with self.subTest(case=fragment):
                self.assertReports(check.rule_policy_semantics, mutated(POLICIES, old, new), fragment)

    def test_representative_iam_mutations_stay_outside_the_boundary(self):
        reads = '"iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags",'
        tree = mutated(POLICIES, reads, '"iam:PutRolePolicy", ' + reads, count=-1)
        self.assertReports(check.rule_policy_semantics, tree, "can iam:PutRolePolicy")

    def test_a_rollout_that_could_deregister_run_another_family_or_open_ecs_exec(self):
        cases = {
            "can ecs:DeregisterTaskDefinition": [
                ('Action   = "ecs:RegisterTaskDefinition"', 'Action   = ["ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition"]'),
                ('Action   = ["ecs:DeregisterTaskDefinition", "ecs:DeleteTaskDefinitions"]', 'Action   = ["ecs:DeleteTaskDefinitions"]'),
            ],
            "can ecs:UpdateService": [
                ('ArnLikeIfExists      = { "ecs:task-definition" = local.service_task_definition_arns.web_api }\n', ""),
                (
                    'ArnNotLike = { "ecs:task-definition" = local.service_task_definition_arns.web_api }',
                    'ArnNotLike = { "ecs:task-definition" = "*" }',
                ),
            ],
        }
        for fragment, edits in cases.items():
            with self.subTest(case=fragment):
                self.assertReports(check.rule_policy_semantics, edited({POLICIES: edits}), fragment)

    def test_artifact_publish_policies_decide_its_requests(self):
        cases = {
            "artifact-publish role cannot kms:GenerateDataKey": (
                'Condition = { StringNotEquals = { "kms:ViaService" = "s3.${var.artifact_registry_region}.amazonaws.com" } }',
                'Condition = { StringNotEquals = { "kms:ViaService" = "ecr.${var.artifact_registry_region}.amazonaws.com" } }',
            ),
            "artifact-publish role can ecr:BatchDeleteImage": (
                '"ecr:BatchDeleteImage", "ecr:PutImageTagMutability", "ecr:SetRepositoryPolicy"', '"ecr:SetRepositoryPolicy"',
            ),
        }
        edits = {
            "artifact-publish role can ecr:BatchDeleteImage": [
                (
                    '"ecr:PutImage", "ecr:BatchGetImage", "ecr:DescribeImages", "ecr:GetDownloadUrlForLayer",',
                    '"ecr:PutImage", "ecr:BatchGetImage", "ecr:DescribeImages", "ecr:GetDownloadUrlForLayer", "ecr:BatchDeleteImage",',
                    3,
                ),
            ],
        }
        for fragment, (old, new) in cases.items():
            with self.subTest(case=fragment):
                tree = edited({POLICIES: [(old, new, -1), *edits.get(fragment, [])]})
                self.assertReports(check.rule_policy_semantics, tree, fragment)

    def test_an_unbound_reference_fails_closed(self):
        tree = mutated(POLICIES, "Resource = local.task_definition_arns", "Resource = local.some_new_list")
        self.assertReports(check.rule_policy_semantics, tree, "failing closed")

    # ------------------------------------------------------------------ saved plans and state

    def test_saved_plan_overwrite(self):
        condition = 'Null    = { "s3:if-none-match" = "true" }'
        tree = mutated(f"{TF}/bootstrap/plan_bucket.tf", condition, condition.replace("if-none-match", "if-match"))
        self.assertReports(check.rule_saved_plans_and_state, tree, "If-None-Match")

    def test_another_role_writing_saved_plans(self):
        condition = 'Condition = { ArnNotEquals = { "aws:PrincipalArn" = local.github_plan_role_arn } }'
        for replacement in (
            'Condition = { ArnNotLike = { "aws:PrincipalArn" = local.github_role_arn_pattern } }',
            'Condition = { ArnEquals = { "aws:PrincipalArn" = local.github_apply_role_arn } }',
        ):
            with self.subTest(replacement=replacement):
                tree = mutated(f"{TF}/bootstrap/plan_bucket.tf", condition, replacement)
                self.assertReports(check.rule_saved_plans_and_state, tree, "every principal but the exact plan role")

    def test_arbitrary_version_access_through_the_bucket_policy(self):
        tree = mutated(f"{TF}/bootstrap/plan_bucket.tf", '          "s3:ListBucketVersions",\n', "")
        self.assertReports(check.rule_saved_plans_and_state, tree, "s3:ListBucketVersions")

    def test_retention_bypass_allowed(self):
        tree = mutated(f"{TF}/bootstrap/plan_bucket.tf", '          "s3:BypassGovernanceRetention",\n', "")
        self.assertReports(check.rule_saved_plans_and_state, tree, "s3:BypassGovernanceRetention")

    def test_lifecycle_rule_touching_state(self):
        abort = "    abort_incomplete_multipart_upload {\n      days_after_initiation = 7\n    }"
        tree = mutated(f"{TF}/bootstrap/state_bucket.tf", abort, "    expiration {\n      days = 30\n    }\n\n" + abort)
        self.assertReports(check.rule_saved_plans_and_state, tree, "state")

    def test_plan_lifecycle_escaping_the_plan_prefix(self):
        tree = mutated(f"{TF}/bootstrap/plan_bucket.tf", "      prefix = local.plan_object_prefix\n", '      prefix = ""\n')
        self.assertReports(check.rule_saved_plans_and_state, tree, "plans/ prefix")

    def test_plan_versions_that_never_expire(self):
        cases = {
            "current plan versions expire": ("    expiration {\n      days = var.plan_retention_days\n    }\n\n", ""),
            "noncurrent plan versions expire": (
                "    noncurrent_version_expiration {\n      noncurrent_days = var.plan_retention_days\n    }\n\n", ""
            ),
            "delete markers expire": ("expired_object_delete_marker = true", "expired_object_delete_marker = false"),
        }
        for fragment, (old, new) in cases.items():
            with self.subTest(fragment=fragment):
                self.assertReports(check.rule_saved_plans_and_state, mutated(f"{TF}/bootstrap/plan_bucket.tf", old, new), fragment)

    def test_plan_role_allowed_to_read_saved_plans_through_the_bucket_policy(self):
        tree = mutated(f"{TF}/bootstrap/plan_bucket.tf", '"DenyPlanReadsByPlanRole"', '"Renamed"')
        self.assertReports(check.rule_saved_plans_and_state, tree, "plan role any saved-plan read")

    def test_plan_object_lock_not_governance(self):
        tree = mutated(f"{TF}/bootstrap/plan_bucket.tf", 'mode = "GOVERNANCE"', 'mode = "COMPLIANCE"')
        self.assertReports(check.rule_saved_plans_and_state, tree, "GOVERNANCE")

    # ------------------------------------------------------------------ workflows

    def test_apply_time_replanning(self):
        before = '          PLAN_FILE="$PRIVATE_DIR/staging.tfplan"\n          if ! terraform apply'
        replan = '          terraform plan -out="$PLAN_FILE" > "$PRIVATE_DIR/replan.log" 2>&1\n'
        after = before.replace("          if ! terraform apply", replan + "          if ! terraform apply")
        self.assertReports(check.rule_deployment_workflows, mutated(check.APPLY_WORKFLOW, before, after), "never generates a new plan")

    def test_apply_without_the_saved_plan(self):
        apply = 'terraform apply -input=false -lock-timeout=5m "$PLAN_FILE"'
        tree = mutated(check.APPLY_WORKFLOW, apply, "terraform apply -input=false -auto-approve")
        self.assertReports(check.rule_deployment_workflows, tree, "saved plan")

    def test_apply_skipping_an_independent_verification(self):
        for step in ("check-plan-object", "compare-lock", "check-terraform-version", "verify-checkout", "plan-summary --mode apply",
                     "check-deployment-authorization", "verify-release", "describe-image-scan-findings"):
            with self.subTest(step=step):
                tree = mutated(check.APPLY_WORKFLOW, step, step.replace("-", "_").upper(), count=-1)
                self.assertReports(check.rule_deployment_workflows, tree, step)

    def test_apply_without_the_checksum_the_exact_version_or_the_authorized_record(self):
        for text in ("sha256sum --check --status", "--version-id", ' --expected-record-version-id "$RELEASE_RECORD_VERSION_ID"',
                     ' --expected-record-sha256 "$RELEASE_RECORD_SHA256"'):
            with self.subTest(text=text):
                tree = mutated(check.APPLY_WORKFLOW, text, "", count=-1)
                self.assertReports(check.rule_deployment_workflows, tree, "before applying")

    def test_apply_authorization_checked_only_after_the_oidc_token(self):
        step = "      - name: Refuse unless one unexpired authorization names exactly this plan and release, before any OIDC token\n" \
               "        run: python3 infra/delivery/delivery.py check-deployment-authorization\n\n"
        late = "      - name: Late authorization\n        run: python3 infra/delivery/delivery.py check-deployment-authorization\n\n"
        release = "      - name: Re-verify the authorized release immediately before applying"
        tree = edited({check.APPLY_WORKFLOW: [(step, ""), (release, late + release)]})
        self.assertReports(check.rule_deployment_workflows, tree, "before any OIDC token")

    def test_approval_prompt_missing_part_of_the_deployment_tuple(self):
        for part in (
            " record ${{ inputs.release_record_version_id }}",
            " | release ${{ inputs.release_commit }}",
            " version ${{ inputs.plan_version_id }}",
        ):
            with self.subTest(part=part):
                tree = mutated(check.APPLY_WORKFLOW, part, "")
                self.assertReports(check.rule_deployment_workflows, tree, "run name")

    def test_plan_without_the_allow_list_check_on_its_variables(self):
        tree = mutated(check.PLAN_WORKFLOW, "write-tfvars", "cp-tfvars")
        self.assertReports(check.rule_deployment_workflows, tree, "allow-list check")

    def test_workflow_runnable_from_pull_requests(self):
        for workflow in (check.PLAN_WORKFLOW, check.APPLY_WORKFLOW):
            with self.subTest(workflow=workflow):
                tree = mutated(workflow, "on:\n  workflow_dispatch:", "on:\n  pull_request:\n  workflow_dispatch:")
                self.assertReports(check.rule_deployment_workflows, tree, "workflow_dispatch only")

    def test_workflow_runnable_from_pull_request_target_or_push(self):
        for trigger in ("pull_request_target:", "push:", "workflow_run:"):
            with self.subTest(trigger=trigger):
                tree = mutated(check.PLAN_WORKFLOW, "on:\n  workflow_dispatch:", f"on:\n  {trigger}\n  workflow_dispatch:")
                self.assertReports(check.rule_deployment_workflows, tree, "workflow_dispatch only")

    def test_triggers_are_normalized_whatever_their_spelling(self):
        for spelling in (
            "on: [workflow_dispatch, push]\n", "on: push\n", "on: [pull_request_target]\n", "on:\n  - workflow_dispatch\n  - schedule\n",
        ):
            with self.subTest(spelling=spelling):
                tree = mutated(check.PUBLISH_WORKFLOW, "on:\n  workflow_dispatch:\n", spelling)
                self.assertReports(check.rule_deployment_workflows, tree, "workflow_dispatch only")
        scalar = mutated(check.PUBLISH_WORKFLOW, "on:\n  workflow_dispatch:\n", "on: workflow_dispatch\n")
        self.assertEqual(check.rule_deployment_workflows(scalar), [])

    def test_pull_request_target_anywhere(self):
        tree = mutated(check.CI_WORKFLOW, "  pull_request:\n", "  pull_request_target:\n")
        self.assertReports(check.rule_publication_credentials, tree, "pull_request_target")
        self.assertReports(check.rule_ci_workflow, tree, "pull_request_target")

    def test_credential_job_guard_weakened(self):
        for workflow in (check.PUBLISH_WORKFLOW, check.PLAN_WORKFLOW, check.APPLY_WORKFLOW):
            for replacement in (
                GUARD.rstrip("\n") + " || always()\n", "    if: always()\n", "    if: failure()\n", "    if: ${{ !cancelled() }}\n",
                GUARD.replace(" && github.ref == 'refs/heads/main'", ""), "",
            ):
                with self.subTest(workflow=workflow, replacement=replacement):
                    tree = mutated(workflow, GUARD, replacement)
                    self.assertReports(check.rule_deployment_workflows, tree, "guarded by exactly")

    def test_a_status_function_or_guard_on_another_job(self):
        tree = mutated(check.PUBLISH_WORKFLOW, "    needs: preflight\n    permissions:\n      contents: read\n    uses:",
                       "    needs: preflight\n    if: always()\n    permissions:\n      contents: read\n    uses:")
        self.assertReports(check.rule_deployment_workflows, tree, "carries an `if`")

    def test_continue_on_error(self):
        cases = {
            "on the job": (
                check.APPLY_WORKFLOW, "    environment: staging-apply\n", "    environment: staging-apply\n    continue-on-error: true\n",
            ),
            "on a step": (check.PLAN_WORKFLOW, "      - name: Initialize against the remote state\n",
                          "      - name: Initialize against the remote state\n        continue-on-error: true\n"),
            "on the preflight": (
                check.PUBLISH_WORKFLOW, "    timeout-minutes: 10\n", "    timeout-minutes: 10\n    continue-on-error: true\n",
            ),
        }
        for name, (workflow, old, new) in cases.items():
            with self.subTest(case=name):
                self.assertReports(check.rule_deployment_workflows, mutated(workflow, old, new), "continue")

    def test_a_step_level_if_other_than_the_cleanup(self):
        for condition in ("success()", "always()", "github.ref == 'refs/heads/main'"):
            with self.subTest(condition=condition):
                tree = mutated(check.PLAN_WORKFLOW, "      - name: Initialize against the remote state\n",
                               f"      - name: Initialize against the remote state\n        if: {condition}\n")
                self.assertReports(check.rule_deployment_workflows, tree, "only the final cleanup step does")

    def test_cleanup_that_does_not_always_run_or_removes_less(self):
        cases = {
            "not always": ("        if: always()\n", "        if: success()\n"),
            "no condition": ("        if: always()\n", ""),
            "keeps Terraform's leftovers": (
                "          rm -f -- infra/terraform/environments/staging/errored.tfstate infra/terraform/environments/staging/crash.log "
                "infra/terraform/environments/staging/crash.*.log\n", "",
            ),
            "keeps the private directory": ('          rm -rf -- "$PRIVATE_DIR"\n', ""),
        }
        for name, (old, new) in cases.items():
            with self.subTest(case=name):
                self.assertReports(check.rule_deployment_workflows, mutated(check.APPLY_WORKFLOW, old, new), "cleanup")

    def test_checkout_credentials_kept_or_only_mentioned_in_a_comment(self):
        tree = mutated(check.PLAN_WORKFLOW, "persist-credentials: false", "persist-credentials: true")
        self.assertReports(check.rule_deployment_workflows, tree, "persist-credentials")
        comment = "          persist-credentials: false\n          fetch-depth: 0\n"
        tree = mutated(check.PLAN_WORKFLOW, comment, "          fetch-depth: 0  # persist-credentials: false\n")
        self.assertReports(check.rule_deployment_workflows, tree, "not a comment")

    def test_write_all_and_unparsed_permissions(self):
        block = "    permissions:\n      contents: read\n      actions: read\n      pull-requests: read\n      id-token: write\n"
        tree = mutated(check.APPLY_WORKFLOW, block, "    permissions: write-all\n")
        self.assertReports(check.rule_publication_credentials, tree, "write-all")
        self.assertReports(check.rule_deployment_workflows, tree, "holds exactly the permissions")

    def test_an_id_token_hidden_from_a_text_match(self):
        tree = mutated(check.CI_WORKFLOW, "permissions:\n  contents: read\n", 'permissions:\n  contents: read\n  "id-token": write\n')
        self.assertReports(check.rule_publication_credentials, tree, "failing closed")
        self.assertReports(check.rule_ci_workflow, tree, "failing closed")

    def test_a_quoted_or_duplicated_key_fails_closed(self):
        for old, new in (
            ("name: artifact-publish\n", '"name": artifact-publish\n'),
            ("on:\n  workflow_dispatch:\n", "'on':\n  workflow_dispatch:\n"),
        ):
            with self.subTest(new=new):
                tree = mutated(check.PUBLISH_WORKFLOW, old, new)
                self.assertReports(check.rule_deployment_workflows, tree, "failing closed")
                self.assertReports(check.rule_publication_credentials, tree, "failing closed")

    def test_reserved_environments_belong_to_their_own_workflow(self):
        container = "  container:\n    runs-on: ubuntu-latest\n"
        tree = mutated(check.CI_WORKFLOW, container, container + "    environment: staging-apply\n")
        self.assertReports(check.rule_publication_credentials, tree, "reserved to")
        self.assertReports(check.rule_ci_workflow, tree, "no environment")
        mapping = mutated(check.PLAN_WORKFLOW, "    environment: staging-plan\n", "    environment:\n      name: staging-apply\n")
        self.assertReports(check.rule_publication_credentials, mapping, "reserved to")
        self.assertReports(check.rule_deployment_workflows, mapping, "may bind only the staging-plan environment")

    def test_the_oidc_job_without_its_private_directory(self):
        cases = {
            "files in RUNNER_TEMP": (check.PLAN_WORKFLOW, '"$PRIVATE_DIR/plan.log"', '"$RUNNER_TEMP/plan.log"', "RUNNER_TEMP"),
            "no umask before a private write": (
                check.PLAN_WORKFLOW, "          umask 077\n          aws s3api get-object --region",
                "          aws s3api get-object --region", "umask 077",
            ),
            "a world-readable private directory": (
                check.APPLY_WORKFLOW, '          mkdir -m 700 "$PRIVATE_DIR"\n', '          mkdir "$PRIVATE_DIR"\n', "mode 700",
            ),
            "Terraform's data outside it": (
                check.APPLY_WORKFLOW, "      TF_DATA_DIR: ${{ runner.temp }}/firmbatch-private/terraform-data\n", "", "data directory",
            ),
            "another private directory": (
                check.PUBLISH_WORKFLOW, "      PRIVATE_DIR: ${{ runner.temp }}/firmbatch-private\n",
                "      PRIVATE_DIR: /tmp/release\n", "PRIVATE_DIR",
            ),
        }
        for name, (workflow, old, new, fragment) in cases.items():
            with self.subTest(case=name):
                self.assertReports(check.rule_deployment_workflows, mutated(workflow, old, new), fragment)

    def test_environment_job_that_does_not_wait_for_preflight(self):
        tree = mutated(check.APPLY_WORKFLOW, "    needs: preflight\n", "")
        self.assertReports(check.rule_deployment_workflows, tree, "after the preflight")

    def test_preflight_bound_to_an_environment(self):
        name = "    name: Preflight (no environment, no AWS)\n"
        tree = mutated(check.PLAN_WORKFLOW, name, name + "    environment: staging-plan\n")
        self.assertReports(check.rule_deployment_workflows, tree, "preflight")

    def test_oidc_token_outside_the_protected_environment(self):
        permissions = "      actions: read\n      pull-requests: read\n    outputs:"
        widened = "      actions: read\n      pull-requests: read\n      id-token: write\n    outputs:"
        tree = mutated(check.PLAN_WORKFLOW, permissions, widened)
        self.assertReports(check.rule_deployment_workflows, tree, "OIDC")

    def test_apply_bound_to_the_plan_environment(self):
        tree = mutated(check.APPLY_WORKFLOW, "    environment: staging-apply\n", "    environment: staging-plan\n")
        self.assertReports(check.rule_deployment_workflows, tree, "staging-apply")

    def test_plan_artifact_upload(self):
        cleanup = "      - name: Remove the plan, its logs, the release documents, the variables and Terraform's files from the runner\n"
        upload = (
            "      - name: Upload\n"
            "        uses: actions/upload-artifact@0000000000000000000000000000000000000000\n"
            "        with:\n"
            "          path: plan\n\n"
        )
        self.assertReports(check.rule_deployment_workflows, mutated(check.PLAN_WORKFLOW, cleanup, upload + cleanup), "artifact")

    def test_full_plan_rendering_in_the_log(self):
        redirected = '-out="$PLAN_FILE" > "$PRIVATE_DIR/plan.log" 2>&1; then'
        tree = mutated(check.PLAN_WORKFLOW, redirected, '-out="$PLAN_FILE"; then')
        self.assertReports(check.rule_deployment_workflows, tree, "private runner file")

    def test_terraform_show_to_the_log(self):
        pipe = (
            '| python3 "$GITHUB_WORKSPACE/infra/delivery/delivery.py" plan-summary --mode plan '
            '--terraform-version 1.15.8 --expected-image "$RELEASE_IMAGE" >> "$GITHUB_STEP_SUMMARY"'
        )
        self.assertReports(check.rule_deployment_workflows, mutated(check.PLAN_WORKFLOW, pipe, ""), "sanitized summary")

    def test_plan_log_echoed(self):
        tree = mutated(check.PLAN_WORKFLOW, "            exit 1\n", '            cat "$PRIVATE_DIR/plan.log"\n            exit 1\n')
        self.assertReports(check.rule_deployment_workflows, tree, "echo")

    def test_input_interpolated_into_a_script(self):
        before = 'PLAN_FILE="$PRIVATE_DIR/staging.tfplan"\n          aws s3api head-object'
        after = before.replace("\n", '\n          echo "${{ inputs.plan_key }}"\n', 1)
        self.assertReports(check.rule_deployment_workflows, mutated(check.APPLY_WORKFLOW, before, after), "env")

    def test_unpinned_action(self):
        pinned = "hashicorp/setup-terraform@dfe3c3f87815947d99a8997f908cb6525fc44e9e"
        tree = mutated(check.PLAN_WORKFLOW, pinned, "hashicorp/setup-terraform@v4")
        self.assertReports(check.rule_deployment_workflows, tree, "not pinned")

    def test_plan_upload_that_can_overwrite(self):
        tree = mutated(check.PLAN_WORKFLOW, " --if-none-match '*'", "")
        self.assertReports(check.rule_deployment_workflows, tree, "if-none-match")

    def test_plan_reading_a_truncated_scan(self):
        tree = mutated(check.PLAN_WORKFLOW, '--image-id "imageDigest=$DIGEST"', '--image-id "imageDigest=$DIGEST" --max-items 1')
        self.assertReports(check.rule_deployment_workflows, tree, "truncated scan")

    def test_an_admission_exception_supplied_through_an_input_or_option(self):
        inputs = '        type: string\n\npermissions: {}'
        exception_input = '      admission_exception:\n        description: "x"\n        required: false\n        type: string\n'
        tree = mutated(check.PLAN_WORKFLOW, inputs, inputs.replace("\n\npermissions", "\n" + exception_input + "\npermissions"))
        self.assertReports(check.rule_deployment_workflows, tree, "workflow input")
        option = 'release.add_argument("--expected-image")'
        tree = mutated("infra/delivery/delivery.py", option, option + '\n    release.add_argument("--admission-policy")')
        self.assertReports(check.rule_publication_credentials, tree, "never from an option")

    def test_ci_gaining_aws_credentials(self):
        tree = mutated(check.CI_WORKFLOW, "permissions:\n  contents: read\n", "permissions:\n  contents: read\n  id-token: write\n")
        self.assertReports(check.rule_ci_workflow, tree)

    def test_ci_container_job_that_pushes(self):
        build = "run: docker build --pull --tag firmbatch-control-plane:ci ."
        tree = mutated(check.CI_WORKFLOW, build, build + " && docker push firmbatch-control-plane:ci")
        self.assertReports(check.rule_ci_workflow, tree, "push")

    def test_ci_terraform_version_drift(self):
        tree = mutated(check.CI_WORKFLOW, "terraform_version: 1.15.8", "terraform_version: 1.16.2")
        self.assertReports(check.rule_ci_workflow, tree, "1.15.8")

    def test_codeowners_missing_infra(self):
        tree = mutated(".github/CODEOWNERS", "/infra/         @chamsrut\n", "")
        self.assertReports(check.rule_codeowners, tree, "/infra/")

    # ------------------------------------------------------------------ container and evidence

    def test_unpinned_base_image(self):
        pinned = "FROM node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df AS portal"
        tree = mutated("Dockerfile", pinned, "FROM node:24-bookworm-slim AS portal")
        self.assertReports(check.rule_container, tree, "digest")

    def test_root_container(self):
        self.assertReports(check.rule_container, mutated("Dockerfile", "USER 10001:10001", "USER root"), "non-root")

    def test_credential_in_the_image(self):
        line = "    PYTHONUNBUFFERED=1 \\\n"
        tree = mutated("Dockerfile", line, line + "    FIRMBATCH_DATABASE_URL=postgresql://synthetic \\\n")
        self.assertReports(check.rule_container, tree, "credential")

    def test_whole_context_copied(self):
        tree = mutated("Dockerfile", "COPY __init__.py /app/firmbatch/__init__.py", "COPY . /app/firmbatch")
        self.assertReports(check.rule_container, tree, "whole context")

    def test_dockerignore_admitting_everything(self):
        tree = mutated(".dockerignore", "*\n\n!__init__.py", "!__init__.py")
        self.assertReports(check.rule_container, tree, ".dockerignore")

    def test_m3_3_staging_evidence_before_authorization(self):
        tree = added(f"{check.DEPLOYMENT_EVIDENCE}plan-summary.txt", "")
        self.assertReports(check.rule_readiness_and_deployment_evidence, tree, "before an authorized M3.3d deployment")

    def test_the_old_boolean_authorization_is_refused(self):
        authorizations = '"schema_version": 1,\n    "authorizations": []'
        tree = mutated("infra/delivery/readiness.json", authorizations, '"m3_3d_deployment_authorized": true')
        self.assertReports(check.rule_readiness_and_deployment_evidence, tree, "bound to exact plans and releases")

    def test_other_m3_evidence_is_unaffected(self):
        tree = added("docs/evidence/m3/portal-suite.txt", "")
        self.assertEqual(check.rule_readiness_and_deployment_evidence(tree), [])

    # ------------------------------------------------------------------ build once, promote by digest, resume

    def test_plan_or_apply_that_builds_pushes_or_logs_in(self):
        init = "      - name: Initialize against the remote state\n"
        build = "      - name: Rebuild\n        run: docker build --tag firmbatch-release:rebuilt .\n\n"
        self.assertReports(check.rule_deployment_workflows, mutated(check.PLAN_WORKFLOW, init, build + init), "never builds")
        push = "      - name: Retag\n        run: aws ecr get-login-password | docker login --password-stdin x\n\n"
        self.assertReports(check.rule_deployment_workflows, mutated(check.APPLY_WORKFLOW, init, push + init), "never builds")

    def test_plan_resolving_the_release_by_tag(self):
        tree = mutated(check.PLAN_WORKFLOW, "imageDigest=$DIGEST", "imageTag=git-$RELEASE_COMMIT")
        self.assertReports(check.rule_deployment_workflows, tree, "by tag")

    def test_plan_skipping_release_verification(self):
        tree = mutated(check.PLAN_WORKFLOW, "infra/delivery/delivery.py verify-release", "infra/delivery/delivery.py release-digest")
        self.assertReports(check.rule_deployment_workflows, tree, "verify-release")

    def test_apply_not_bound_to_the_verified_image(self):
        tree = mutated(check.APPLY_WORKFLOW, ' --expected-image "$RELEASE_IMAGE"', "", count=-1)
        self.assertReports(check.rule_deployment_workflows, tree, "release_image")

    def test_publish_from_pull_requests_or_pushes(self):
        for trigger in ("pull_request:", "pull_request_target:", "push:"):
            with self.subTest(trigger=trigger):
                tree = mutated(check.PUBLISH_WORKFLOW, "on:\n  workflow_dispatch:", f"on:\n  {trigger}\n  workflow_dispatch:")
                self.assertReports(check.rule_deployment_workflows, tree, "workflow_dispatch only")

    def test_publish_without_the_required_verification(self):
        tree = mutated(check.PUBLISH_WORKFLOW, "    needs: [preflight, verify]\n", "    needs: preflight\n")
        self.assertReports(check.rule_deployment_workflows, tree, "verification passed")

    def test_publish_with_a_build_argument(self):
        tree = mutated(check.PUBLISH_WORKFLOW, "docker build --pull", "docker build --build-arg FIRMBATCH_ENV=staging --pull")
        self.assertReports(check.rule_deployment_workflows, tree, "build argument")

    def test_publish_building_twice(self):
        push = '            docker push "$REPOSITORY_URL:$TAG" > "$PRIVATE_DIR/push.log" 2>&1\n'
        tree = mutated(check.PUBLISH_WORKFLOW, push, push + '            docker build --tag "$REPOSITORY_URL:$TAG" .\n')
        self.assertReports(check.rule_deployment_workflows, tree, "exactly once")

    def test_publish_pushing_a_mutable_tag(self):
        push = '            docker push "$REPOSITORY_URL:$TAG" > "$PRIVATE_DIR/push.log" 2>&1\n'
        tree = mutated(check.PUBLISH_WORKFLOW, push, push + '            docker push "$REPOSITORY_URL:latest"\n')
        self.assertReports(check.rule_deployment_workflows, tree, "exactly one tag")

    def test_publish_pushing_even_when_the_tag_exists(self):
        push = '            docker push "$REPOSITORY_URL:$TAG" > "$PRIVATE_DIR/push.log" 2>&1\n'
        marker = "          # From the registry's own bytes"
        tree = edited({check.PUBLISH_WORKFLOW: [(push, ""), (marker, push.replace("            ", "          ") + marker)]})
        self.assertReports(check.rule_deployment_workflows, tree, "only when git-<commit> does not exist")

    def test_publish_pushing_before_the_sbom_is_stored(self):
        sbom = (
            '            put_once "$(python3 "$DELIVERY" sbom-key --draft "$PRIVATE_DIR/draft.json")" '
            '"$PRIVATE_DIR/sbom.spdx.json" sbom "$LOCAL_CONFIG_DIGEST"\n'
        )
        push = '            docker push "$REPOSITORY_URL:$TAG" > "$PRIVATE_DIR/push.log" 2>&1\n'
        tree = edited({check.PUBLISH_WORKFLOW: [(sbom, ""), (push, push + sbom)]})
        self.assertReports(check.rule_deployment_workflows, tree, "after that image's SBOM is stored")

    def test_publish_without_its_provenance_labels(self):
        for label in check.PROVENANCE_LABELS:
            with self.subTest(label=label):
                tree = mutated(check.PUBLISH_WORKFLOW, f'--label "{label}=', '--label "x-removed=')
                self.assertReports(check.rule_deployment_workflows, tree, label)

    def test_publish_skipping_a_resumption_proof(self):
        for step in (
            "publication-mode", "tag-digest", "registry-identity",
            "compare-release-object", "get-download-url-for-layer", "ImageNotFoundException",
        ):
            with self.subTest(step=step):
                tree = mutated(check.PUBLISH_WORKFLOW, step, step.upper().replace("-", "_"), count=-1)
                self.assertReports(check.rule_deployment_workflows, tree, step)

    def test_publish_deleting_overwriting_or_retagging(self):
        marker = "          # From the registry's own bytes"
        for command in ("aws ecr batch-delete-image --repository-name x --image-ids imageTag=y",
                        "aws s3api delete-object --bucket x --key y",
                        "aws ecr put-image --repository-name x --image-tag latest --image-manifest m"):
            with self.subTest(command=command):
                tree = mutated(check.PUBLISH_WORKFLOW, marker, f"          {command}\n{marker}")
                self.assertReports(check.rule_deployment_workflows, tree, "never deletes")

    def test_publish_credentials_before_the_build_or_the_draft(self):
        credentials = (
            "      - name: Early credentials\n"
            "        uses: aws-actions/configure-aws-credentials@cbe3b392738ccf3f987d68400dafcf4b0624a56c # v6.2.4\n\n"
        )
        for step in ("      - name: Build the image once, with its provenance in its labels, before any credential exists\n",
                     "      - name: Inspect the image and write the release draft, before any credential exists\n"):
            with self.subTest(step=step):
                tree = mutated(check.PUBLISH_WORKFLOW, step, credentials + step)
                self.assertReports(check.rule_deployment_workflows, tree, "before any credential exists")

    def test_publish_overwriting_a_release_record(self):
        tree = mutated(check.PUBLISH_WORKFLOW, " --if-none-match '*'", "")
        self.assertReports(check.rule_deployment_workflows, tree, "created once")

    def test_publish_uploading_the_sbom_as_an_artifact(self):
        tree = mutated(check.PUBLISH_WORKFLOW, "upload-artifact: false", "upload-artifact: true")
        self.assertReports(check.rule_deployment_workflows, tree, "artifact")

    def test_publish_without_the_frozen_approval(self):
        tree = mutated(check.PUBLISH_WORKFLOW, "      APPROVAL_EVIDENCE: ${{ needs.preflight.outputs.approval_evidence }}\n", "")
        self.assertReports(check.rule_deployment_workflows, tree, "approval evidence")

    def test_another_workflow_reaching_publication_credentials(self):
        role = "      STAGING_APPLY_ROLE_ARN: ${{ vars.STAGING_APPLY_ROLE_ARN }}\n"
        tree = mutated(check.APPLY_WORKFLOW, role, role + "      ARTIFACT_PUBLISH_ROLE_ARN: ${{ vars.ARTIFACT_PUBLISH_ROLE_ARN }}\n")
        self.assertReports(check.rule_publication_credentials, tree, "only")

    def test_a_pull_request_workflow_requesting_an_oidc_token(self):
        tree = mutated(check.CI_WORKFLOW, "permissions:\n  contents: read\n", "permissions:\n  contents: read\n  id-token: write\n")
        self.assertReports(check.rule_publication_credentials, tree, "OIDC token")

    def test_ci_no_longer_reusable_as_the_publish_verification(self):
        tree = mutated(check.CI_WORKFLOW, "  workflow_call:\n", "")
        self.assertReports(check.rule_ci_workflow, tree, "workflow_call")

    def test_a_second_or_environment_repository(self):
        repository = resource("aws_ecr_repository", "staging", 'name = "firmbatch-staging"', 'image_tag_mutability = "IMMUTABLE"')
        tree = added(f"{COMPUTE}/registry.tf", repository)
        self.assertReports(check.rule_release_registry, tree, "exactly one ECR repository")

    def test_mutable_or_excepted_release_tags(self):
        artifacts = f"{ARTIFACTS}/main.tf"
        cases = {
            "IMMUTABLE": ('  image_tag_mutability = "IMMUTABLE"', '  image_tag_mutability = "MUTABLE"'),
            "exclusion filter": (
                "  # No image_tag_mutability_exclusion_filter: every tag, git-<commit> included, is immutable.\n",
                '  image_tag_mutability_exclusion_filter {\n    filter      = "dev-*"\n    filter_type = "WILDCARD"\n  }\n',
            ),
            "release key": ("kms_key         = var.release_kms_key_arn", 'kms_key         = "alias/aws/ecr"'),
        }
        for fragment, (old, new) in cases.items():
            with self.subTest(fragment=fragment):
                self.assertReports(check.rule_release_registry, mutated(artifacts, old, new), fragment)

    def test_lifecycle_expiring_release_images(self):
        tree = mutated(f"{ARTIFACTS}/main.tf", 'tagStatus   = "untagged"', 'tagStatus   = "any"')
        self.assertReports(check.rule_release_registry, tree, "untagged")

    def test_replication_configured(self):
        replication = resource("aws_ecr_replication_configuration", "this", "replication_configuration {", "}")
        self.assertReports(check.rule_release_registry, added(f"{ARTIFACTS}/replication.tf", replication), "replication")

    def test_someone_other_than_artifact_publish_can_push(self):
        condition = "Condition = { ArnNotEquals = { \"aws:PrincipalArn\" = local.publish_role_arn } }"
        tree = mutated(f"{ARTIFACTS}/main.tf", condition, 'Condition = { ArnNotLike = { "aws:PrincipalArn" = "*" } }')
        self.assertReports(check.rule_release_registry, tree, "every push")

    def test_the_artifacts_root_creating_an_identity_or_a_key(self):
        for kind, body in (("aws_kms_key", ('description = "x"',)), ("aws_iam_role", ('name = "x"', 'assume_role_policy = "{}"')),
                           ("aws_iam_policy", ('name = "x"', 'policy = "{}"'))):
            with self.subTest(kind=kind):
                self.assertReports(check.rule_release_registry, added(f"{ARTIFACTS}/extra.tf", resource(kind, "x", *body)), kind)

    def test_the_artifacts_root_naming_a_principal_it_has_not_proven_exists(self):
        cases = {
            "no existence check": (
                f"{ARTIFACTS}/publish_role.tf", "condition     = self.arn == var.artifact_publish_role_arn",
                "condition     = true", "already exists",
            ),
            "no boundary check": (f"{ARTIFACTS}/publish_role.tf", "self.permissions_boundary ==", "var.region ==", "already exists"),
            "repository policy not waiting": (
                f"{ARTIFACTS}/main.tf", "  depends_on = [data.aws_iam_role.artifact_publish, data.aws_iam_role.release_readers]\n",
                "", "proven to exist",
            ),
            "record policy not waiting": (
                f"{ARTIFACTS}/release_bucket.tf", ", data.aws_iam_role.artifact_publish, data.aws_iam_role.release_readers]",
                "]", "proven to exist",
            ),
        }
        for name, (path, old, new, fragment) in cases.items():
            with self.subTest(case=name):
                self.assertReports(check.rule_release_registry, mutated(path, old, new), fragment)

    def test_release_record_overwrite(self):
        condition = 'Condition = { Null = { "s3:if-none-match" = "true" } }'
        tree = mutated(f"{ARTIFACTS}/release_bucket.tf", condition, condition.replace("if-none-match", "if-match"))
        self.assertReports(check.rule_release_registry, tree, "If-None-Match")

    def test_ecs_contract_drift_between_delivery_compute_and_the_bootstrap_identities(self):
        secret = '            "FIRMBATCH_COGNITO_CLIENT_SECRET": "cognito-client-secret",\n'
        self.assertReports(check.rule_ecs_contract_agreement, mutated("infra/delivery/delivery.py", secret, ""), "disagree")
        families = '"bootstrap", "identity-binding", "identity-broker", "migrate", "web-api"]'
        tree = mutated(f"{BOOTSTRAP}/main.tf", families, families.replace("]", ', "operator-shell"]'))
        self.assertReports(check.rule_ecs_contract_agreement, tree, "bootstrap")

    # ------------------------------------------------------------------ third correction pass: each bypass the verification confirmed

    def test_an_environment_named_by_an_expression_or_another_case_escapes_no_reservation(self):
        workflow = (
            "name: rogue\non:\n  workflow_dispatch:\n    inputs:\n      env:\n        type: string\npermissions: {}\n"
            "jobs:\n  deploy:\n    runs-on: ubuntu-24.04\n    environment: ${{ inputs.env }}\n"
            "    permissions:\n      id-token: write\n    steps:\n      - run: echo\n"
        )
        tree = added(".github/workflows/rogue.yml", workflow)
        self.assertReports(check.rule_publication_credentials, tree, "by an expression")
        named = workflow.replace("    environment: ${{ inputs.env }}\n", "    environment:\n      name: ${{ inputs.env }}\n")
        self.assertReports(check.rule_publication_credentials, added(".github/workflows/rogue.yml", named), "by an expression")
        cased = added(".github/workflows/rogue.yml", workflow.replace("${{ inputs.env }}", "Staging-Apply"))
        self.assertReports(check.rule_publication_credentials, cased, "reserved to")

    def test_a_dynamic_block_hides_the_nested_blocks_it_generates(self):
        source = (
            'resource "aws_security_group" "open" {\n  name   = "open"\n  vpc_id = "vpc-1"\n\n'
            '  dynamic "ingress" {\n    for_each = ["0.0.0.0/0"]\n    content {\n      cidr_blocks = [ingress.value]\n'
            '      from_port   = 0\n      to_port     = 0\n      protocol    = "-1"\n    }\n  }\n}\n'
        )
        self.assertReports(check.rule_forbidden_constructs, added(f"{TF}/modules/network/open.tf", source), "dynamic")

    def test_a_provider_configured_inside_a_module(self):
        tree = added(f"{TF}/modules/network/provider.tf", 'provider "aws" {\n  region = "us-west-2"\n}\n')
        self.assertReports(check.rule_versions, tree, "a module configures no provider")

    def test_a_module_source_that_resolves_outside_the_modules_directory(self):
        # ../../modules is infra/terraform/modules from environments/staging or from a module; from the
        # bootstrap or artifacts root it is infra/modules, which the text match accepted.
        for path in (f"{BOOTSTRAP}/extra.tf", f"{ARTIFACTS}/extra.tf"):
            with self.subTest(path=path):
                tree = added(path, 'module "network" {\n  source = "../../modules/network"\n}\n')
                self.assertReports(check.rule_forbidden_constructs, tree, "infra/terraform/modules")
        tree = added(f"{TF}/environments/staging/extra.tf", 'module "network" {\n  source = "../../../modules/network"\n}\n')
        self.assertReports(check.rule_forbidden_constructs, tree, "infra/terraform/modules")

    def test_ci_verification_that_continues_on_error_or_runs_conditionally(self):
        step = "      - name: Verify repository\n"
        verify = "  verify:\n    runs-on: ubuntu-latest\n"
        container = "  container:\n    runs-on: ubuntu-latest\n"
        cases = {
            "continue-on-error on a step": (step, step + "        continue-on-error: true\n", "continues on error"),
            "a conditional step": (step, step + "        if: false\n", "conditionally"),
            "continue-on-error on a job": (verify, verify + "    continue-on-error: true\n", "continues on error"),
            "a conditional job": (container, container + "    if: github.event_name == 'push'\n", "conditionally"),
        }
        for name, (old, new, fragment) in cases.items():
            with self.subTest(case=name):
                self.assertReports(check.rule_ci_workflow, mutated(check.CI_WORKFLOW, old, new), fragment)

    def test_a_conditional_preflight_step(self):
        step = "      - name: Preflight\n        id: preflight\n"
        for workflow in (check.PUBLISH_WORKFLOW, check.PLAN_WORKFLOW, check.APPLY_WORKFLOW):
            with self.subTest(workflow=workflow):
                tree = mutated(workflow, step, step + "        if: github.ref != 'refs/heads/main'\n")
                self.assertReports(check.rule_deployment_workflows, tree, "every preflight step runs")

    def test_an_always_true_or_unmodelled_condition_is_decided_as_aws_would_or_fails_closed(self):
        condition = '        Condition = { StringNotEquals = { "aws:RequestedRegion" = [var.region, "us-east-1"] } }\n'
        always = mutated(POLICIES, condition, '        Condition = { Bool = { "aws:SecureTransport" = "true" } }\n')
        self.assertReports(check.rule_policy_semantics, always, "statement DenyRegionsOutsideStagingAndTheCertificateRegion denies")
        self.assertReports(check.rule_policy_semantics, always, "cannot s3:GetObject")
        unmodelled = mutated(POLICIES, condition, '        Condition = { StringEquals = { "aws:PrincipalTag/team" = "delivery" } }\n')
        self.assertReports(check.rule_policy_semantics, unmodelled, "failing closed")
        tls = {
            "Sid": "Tls", "Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*", "Condition": {"Bool": {"aws:SecureTransport": "true"}},
        }
        self.assertEqual(check.broad_not_action_denies([tls]), ["Tls"])

    def test_the_plan_role_is_evaluated_and_never_reads_a_secret_value(self):
        grant = edited({POLICIES: [
            (
                '"secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy",',
                '"secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy", "secretsmanager:GetSecretValue",',
            ),
            (
                '"secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue", "secretsmanager:PutSecretValue",',
                '"secretsmanager:BatchGetSecretValue", "secretsmanager:PutSecretValue",',
            ),
        ]})
        # The grant is refused for what the statement says; the plan boundary also keeps the read from being effective.
        granted = "plan role's statement RefreshStagingResourceFamilies grants secretsmanager:GetSecretValue"
        self.assertReports(check.rule_policy_semantics, grant, granted)
        self.assertFalse([f for f in check.rule_policy_semantics(grant) if "plan role can secretsmanager:GetSecretValue" in f])
        self.assertReports(check.rule_delivery_trust, grant, "plan role may not secretsmanager:GetSecretValue")
        allow = 'Sid      = "CreateNewSavedPlanObjects"\n        Effect   = "Allow"'
        denied = mutated(POLICIES, allow, allow.replace('"Allow"', '"Deny"'))
        self.assertReports(check.rule_policy_semantics, denied, "plan role cannot s3:PutObject")

    def test_a_policy_held_in_a_reference_is_read_not_skipped(self):
        iam = f"{COMPUTE}/iam.tf"
        broad = mutated(iam, '        Action   = "cognito-idp:AdminGetUser"', '        NotAction = "cognito-idp:AdminGetUser"')
        fragment = "task statement ValidateTheSelectedSubjectInTheOnePool denies or allows everything"
        self.assertReports(check.rule_policy_semantics, broad, fragment)
        opaque = mutated(iam, "  policy = each.value\n", "  policy = data.aws_iam_policy_document.task[each.key].json\n")
        self.assertReports(check.rule_policy_semantics, opaque, "failing closed")
        unread = added(f"{TF}/modules/observability/queue.tf", resource("aws_sqs_queue_policy", "x", 'queue_url = "q"', 'policy = "{}"'))
        self.assertReports(check.rule_policy_semantics, unread, "a type the evaluator does not read")

    def test_the_release_registry_derived_from_this_root_rather_than_declared(self):
        declared = (
            'release_repository_arn       = "arn:aws:ecr:${var.artifact_registry_region}:${var.artifact_registry_account_id}'
            ':repository/${var.release_repository_name}"'
        )
        derived = 'release_repository_arn       = "arn:aws:ecr:${var.region}:${local.account_id}:repository/${var.release_repository_name}"'
        self.assertReports(check.rule_delivery_trust, mutated(f"{BOOTSTRAP}/main.tf", declared, derived), "declared artifact_registry")
        via = '"kms:ViaService" = "s3.${var.artifact_registry_region}.amazonaws.com"'
        tree = mutated(POLICIES, via, '"kms:ViaService" = "s3.${var.region}.amazonaws.com"')
        self.assertReports(check.rule_delivery_trust, tree, "declared artifact_registry_region only")
        for fragment in ("var.artifact_registry_account_id == var.expected_account_id", "var.artifact_registry_region == var.region"):
            with self.subTest(fragment=fragment):
                self.assertReports(check.rule_delivery_trust, mutated(f"{BOOTSTRAP}/variables.tf", fragment, "true"), fragment)

    def test_publication_required_to_wait_for_the_staging_apply_it_precedes(self):
        publish = '    "publish": (\n        "state_plan_buckets_and_delivery_identities_bootstrapped_by_human",\n'
        tree = mutated("infra/delivery/delivery.py", publish, publish + '        "human_applied_resources_applied_by_human",\n')
        self.assertReports(check.rule_readiness_and_deployment_evidence, tree, "follows publication")
        renamed = mutated("infra/delivery/readiness.json", '"release_registry_applied_by_human"', '"release_registry_applied"')
        self.assertReports(check.rule_readiness_and_deployment_evidence, renamed, "exactly the prerequisites")

    def test_publish_addressing_the_sbom_by_the_local_image_id(self):
        metadata = '            --metadata-file "$PRIVATE_DIR/build-metadata.json" \\\n'
        self.assertReports(check.rule_deployment_workflows, mutated(check.PUBLISH_WORKFLOW, metadata, ""), "--metadata-file")
        digest = 'LOCAL_CONFIG_DIGEST="$(python3 "$DELIVERY" draft-config-digest --draft "$PRIVATE_DIR/draft.json")"'
        local_id = 'LOCAL_CONFIG_DIGEST="$(docker image inspect --format \'{{.Id}}\' "firmbatch-release:$TAG")"'
        tree = mutated(check.PUBLISH_WORKFLOW, digest, local_id)
        self.assertReports(check.rule_deployment_workflows, tree, "local image ID")
        self.assertReports(check.rule_deployment_workflows, tree, "draft-config-digest")
        tree = mutated(check.PUBLISH_WORKFLOW, ' --build-metadata "$PRIVATE_DIR/build-metadata.json"', "")
        self.assertReports(check.rule_deployment_workflows, tree, "draft verifies")

    def test_publish_checking_its_own_attempt_late_or_never(self):
        step = (
            "      - name: Refuse unless this attempt's own preflight and verification jobs succeeded in it, before any credential\n"
            "        env:\n          GITHUB_TOKEN: ${{ github.token }}\n"
            "        run: python3 infra/delivery/delivery.py check-publish-attempt\n\n"
        )
        self.assertReports(check.rule_deployment_workflows, mutated(check.PUBLISH_WORKFLOW, step, ""), "check-publish-attempt")
        marker = "      - name: Assume the artifact-publish role through OIDC\n"
        late = edited({check.PUBLISH_WORKFLOW: [(step, ""), (marker, step + marker)]})
        self.assertReports(check.rule_deployment_workflows, late, "before the build and any credential")
        run = "        run: python3 infra/delivery/delivery.py check-publish-attempt"
        no_token = mutated(check.PUBLISH_WORKFLOW, "          GITHUB_TOKEN: ${{ github.token }}\n" + run, run)
        self.assertReports(check.rule_deployment_workflows, no_token, "job's own token")
        permissions = "      contents: read\n      actions: read\n      id-token: write\n"
        narrowed = mutated(check.PUBLISH_WORKFLOW, permissions, "      contents: read\n      id-token: write\n")
        self.assertReports(check.rule_deployment_workflows, narrowed, "holds exactly the permissions")

    def test_plan_variables_checked_only_after_the_oidc_token(self):
        run = "        run: python3 infra/delivery/delivery.py check-environment-variables --workflow plan\n"
        secret = "        env:\n          STAGING_TFVARS_JSON: ${{ secrets.STAGING_TFVARS_JSON }}\n" + run
        self.assertReports(check.rule_deployment_workflows, mutated(check.PLAN_WORKFLOW, secret, run), "before the OIDC token")

    # ------------------------------------------------------------------ fourth pass: every policy a delivery identity can hold

    SECRET_READ = (
        'jsonencode({\n    Version = "2012-10-17"\n'
        '    Statement = [{ Effect = "Allow", Action = "secretsmanager:GetSecretValue", Resource = "*" }]\n  })'
    )

    def test_a_side_door_policy_on_a_delivery_identity_in_any_form_fails_closed(self):
        side = self.SECRET_READ
        cases = {
            "a literal inline policy": (f"{BOOTSTRAP}/side_door.tf", resource(
                "aws_iam_role_policy", "plan_side_door", 'name = "side"', "role = aws_iam_role.github_plan.id", f"policy = {side}",
            )),
            "a policy held in a local": (f"{BOOTSTRAP}/side_door.tf", "locals {\n  side_door = " + side + "\n}\n" + resource(
                "aws_iam_role_policy", "plan_side_door", 'name = "side"', "role = aws_iam_role.github_plan.id", "policy = local.side_door",
            )),
            "policies built by for_each": (f"{BOOTSTRAP}/side_door.tf", "locals {\n  side_doors = { read = " + side + " }\n}\n" + resource(
                "aws_iam_role_policy", "apply_side_doors", "for_each = local.side_doors", 'name = each.key',
                "role = aws_iam_role.github_apply.id", "policy = each.value",
            )),
            "a managed-policy attachment": (f"{BOOTSTRAP}/side_door.tf", resource(
                "aws_iam_role_policy_attachment", "admin", "role = aws_iam_role.github_apply.name",
                'policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"',
            )),
            "a managed policy created and attached by reference": (f"{BOOTSTRAP}/side_door.tf", resource(
                "aws_iam_policy", "side", 'name = "side"', f"policy = {side}",
            ) + resource(
                "aws_iam_role_policy_attachment", "side", "role = aws_iam_role.artifact_publish.name",
                "policy_arn = aws_iam_policy.side.arn",
            )),
            "an exclusive attachment set": (f"{BOOTSTRAP}/side_door.tf", resource(
                "aws_iam_role_policy_attachments_exclusive", "plan", "role_name = aws_iam_role.github_plan.name",
                'policy_arns = ["arn:aws:iam::aws:policy/SecretsManagerReadWrite"]',
            )),
            "an attachment from another root by role name": (f"{TF}/environments/staging/side_door.tf", resource(
                "aws_iam_policy_attachment", "side", 'name = "side"', 'roles = ["firmbatch-staging-github-plan"]',
                'policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"',
            )),
            "an attachment from a module through a variable": (f"{COMPUTE}/side_door.tf", resource(
                "aws_iam_role_policy_attachment", "side", "role = var.delivery_role_name",
                'policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"',
            )),
            "an exclusive inline set from the artifacts root": (f"{ARTIFACTS}/side_door.tf", resource(
                "aws_iam_role_policies_exclusive", "publish", 'role_name = "firmbatch-artifact-publish"', 'policy_names = ["side"]',
            )),
        }
        for name, (path, source) in cases.items():
            with self.subTest(case=name):
                self.assertReports(check.rule_policy_semantics, added(path, source), "failing closed")

    def test_managed_or_inline_policies_declared_on_a_role_fail_closed(self):
        role = "  assume_role_policy   = local.trust_policy[local.plan_environment]\n"
        for extra in ('  managed_policy_arns  = ["arn:aws:iam::aws:policy/AdministratorAccess"]\n',
                      '  inline_policy {\n    name   = "side"\n    policy = "{}"\n  }\n'):
            with self.subTest(extra=extra):
                tree = mutated(IDENTITIES, role, role + extra)
                self.assertReports(check.rule_policy_semantics, tree, "managed_policy_arns or inline_policy")

    def test_an_admitted_delivery_policy_expressed_through_a_local_fails_closed(self):
        start = (
            'resource "aws_iam_role_policy" "artifact_publish" {\n  name = "publish"\n'
            "  role = aws_iam_role.artifact_publish.id\n\n  policy = jsonencode({"
        )
        replaced = start.replace("  policy = jsonencode({", "  policy = local.publish_policy\n  unused = jsonencode({")
        self.assertReports(check.rule_policy_semantics, mutated(POLICIES, start, replaced), "not a literal jsonencode document")

    def test_wildcard_secret_parameter_and_key_grants_are_refused_for_every_delivery_identity(self):
        refresh = '"secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy",'
        cases = {
            "grants every action": (refresh, refresh + ' "*",'),
            "grants secretsmanager:GetSecretValue": (refresh, refresh + ' "secretsmanager:Get*",'),
            "grants ssm:GetParameter": (refresh, refresh + ' "ssm:GetParameter",'),
            "grants ssm:GetParametersByPath": (refresh, refresh + ' "ssm:Get*",'),
        }
        for fragment, (old, new) in cases.items():
            with self.subTest(case=fragment):
                fragment_text = f"plan role's statement RefreshStagingResourceFamilies {fragment}"
                self.assertReports(check.rule_policy_semantics, mutated(POLICIES, old, new), fragment_text)
        publish_key = (
            'Sid       = "ReleaseRecordEncryptionThroughS3Only"\n        Effect    = "Allow"\n'
            '        Action    = ["kms:GenerateDataKey", "kms:Decrypt"]\n        Resource  = aws_kms_key.release.arn'
        )
        tree = mutated(POLICIES, publish_key, publish_key.replace("Resource  = aws_kms_key.release.arn", 'Resource  = "*"'))
        self.assertReports(check.rule_policy_semantics, tree, "grants kms:Decrypt beyond the state, plan and release keys")
        apply_plans = (
            'Sid      = "DecryptSavedPlans"\n        Effect   = "Allow"\n        Action   = "kms:Decrypt"\n'
            "        Resource = aws_kms_key.plans.arn"
        )
        tree = mutated(POLICIES, apply_plans, apply_plans.replace("Resource = aws_kms_key.plans.arn", 'Resource = "*"'))
        self.assertReports(check.rule_policy_semantics, tree, "apply role's statement DecryptSavedPlans grants kms:Decrypt beyond")

    def test_the_plan_boundary_is_required_complete_and_refuses_a_side_door(self):
        unbounded = mutated(IDENTITIES, "  permissions_boundary = aws_iam_policy.plan_boundary.arn\n", "")
        self.assertReports(check.rule_delivery_trust, unbounded, "permissions boundary")
        for sid in check.PLAN_BOUNDARY_DENIES:
            with self.subTest(sid=sid):
                self.assertReports(check.rule_delivery_trust, mutated(POLICIES, f'"{sid}"', '"Renamed"'), sid)
        ceiling = '"ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:DescribeImageScanFindings",\n        ]\n        Resource = "*"'
        narrowed = mutated(POLICIES, ceiling, '"ecr:DescribeRepositories",\n        ]\n        Resource = "*"')
        self.assertReports(check.rule_delivery_trust, narrowed, "does not admit the plan role's own actions")
        self.assertReports(check.rule_policy_semantics, narrowed, "plan role cannot ecr:DescribeImages")
        # Remove the boundary's secret deny and widen its ceiling: a side door attached to the role could then read secrets.
        ceiling_start = (
            'Sid    = "CeilingIsThePlanRolesOwnActions"\n        Effect = "Allow"\n'
            '        Action = [\n          "sts:GetCallerIdentity",'
        )
        secret_deny = '"DenyPlanRoleSecretValuesAndParameters"\n        Effect = "Deny"'
        widened = edited({POLICIES: [
            (ceiling_start, ceiling_start + ' "secretsmanager:*",'),
            (secret_deny, secret_deny.replace('"Deny"', '"Allow"')),
        ]})
        self.assertReports(check.rule_policy_semantics, widened, "plan boundary does not stop secretsmanager:GetSecretValue")
        self.assertReports(check.rule_delivery_trust, widened, "no wildcard service")

    def test_the_plan_boundary_alone_stops_a_side_door(self):
        boundary = check.policy_statements(REPOSITORY, BOOTSTRAP, "aws_iam_policy", "plan_boundary", check.BOOTSTRAP_BINDINGS)
        for request in (
            check._request("secretsmanager:GetSecretValue", check._SECRET),
            check._request("ssm:GetParameter", f"{check._PARAMETER}/database-url"),
            check._request("kms:Decrypt", check._OTHER_KEY),
        ):
            with self.subTest(action=request["action"]):
                # A side door on its own would grant it; the boundary alone refuses it.
                self.assertTrue(check.effective([check.SIDE_DOOR], None, request))
                self.assertFalse(check.effective([check.SIDE_DOOR], boundary, request))

    # ------------------------------------------------------------------ fifth pass: who may declare or adopt a delivery identity

    ROLE_BODY = 'assume_role_policy = "{}"'
    RESERVED_NAME = "its effective name is a GitHub delivery identity's"

    def test_the_reviewers_shadow_role_imported_from_the_plan_identity_is_refused(self):
        shadow = (
            'import {\n  to = aws_iam_role.shadow\n  id = "firmbatch-staging-github-plan"\n}\n\n'
            + resource("aws_iam_role", "shadow", 'name = "firmbatch-staging-github-plan"', self.ROLE_BODY)
            + resource(
                "aws_iam_role_policy_attachment", "shadow", "role = aws_iam_role.shadow.name",
                'policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"',
            )
        )
        tree = added(f"{TF}/environments/staging/shadow.tf", shadow)
        self.assertReports(check.rule_forbidden_constructs, tree, "import block")
        self.assertReports(check.rule_delivery_trust, tree, f"aws_iam_role.shadow: {self.RESERVED_NAME}")
        attachment = "aws_iam_role_policy_attachment.shadow attaches a policy to a role not proven"
        self.assertReports(check.rule_policy_semantics, tree, attachment)

    def test_the_reviewers_compute_role_named_as_the_apply_identity_is_refused(self):
        document = '{ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "ecs:UpdateService", Resource = "*" }] }'
        source = resource("aws_iam_role", "deployer", 'name = "${var.name_prefix}-github-apply"', self.ROLE_BODY) + resource(
            "aws_iam_role_policy", "deployer", 'name = "deployer"', "role = aws_iam_role.deployer.id", f"policy = jsonencode({document})",
        )
        tree = added(f"{COMPUTE}/deployer.tf", source)
        self.assertReports(check.rule_delivery_trust, tree, f"aws_iam_role.deployer: {self.RESERVED_NAME}")
        self.assertReports(check.rule_policy_semantics, tree, "aws_iam_role_policy.deployer attaches a policy to a role not proven")

    def test_every_import_block_is_refused(self):
        for path, identifier in (
            (f"{TF}/environments/staging/adopt.tf", "firmbatch-staging-github-apply"),
            (f"{ARTIFACTS}/adopt.tf", "firmbatch-artifact-publish"),
            (f"{COMPUTE}/adopt.tf", "firmbatch-staging-web-api-task"),
        ):
            with self.subTest(identifier=identifier):
                tree = added(path, f'import {{\n  to = aws_iam_role.adopted\n  id = "{identifier}"\n}}\n')
                self.assertReports(check.rule_forbidden_constructs, tree, "import block")

    def test_a_delivery_name_reached_through_a_local_a_variable_a_name_prefix_or_letter_case_is_refused(self):
        staging = f"{TF}/environments/staging/extra_role.tf"
        compute = f"{COMPUTE}/extra_role.tf"
        call = 'module "compute" {\n  source = "../../modules/compute"\n\n'
        supplied = dict(REPOSITORY.files)
        supplied[f"{TF}/environments/staging/main.tf"] = supplied[f"{TF}/environments/staging/main.tf"].replace(
            call, call + '  deployer_name = "${var.name_prefix}-github-plan"\n', 1,
        )
        supplied[compute] = 'variable "deployer_name" {\n  type = string\n}\n' + resource(
            "aws_iam_role", "extra", "name = var.deployer_name", self.ROLE_BODY,
        )
        suffix_default = 'variable "role_suffix" {\n  type    = string\n  default = "artifact-publish"\n}\n'
        cases = {
            "a local in an environment root": (added(staging, 'locals {\n  deploy_role = "firmbatch-staging-github-apply"\n}\n' + resource(
                "aws_iam_role", "extra", "name = local.deploy_role", self.ROLE_BODY)), self.RESERVED_NAME),
            "interpolation of a module local": (added(compute, 'locals {\n  identity_kind = "plan"\n}\n' + resource(
                "aws_iam_role", "extra", 'name = "${var.name_prefix}-github-${local.identity_kind}"', self.ROLE_BODY)), self.RESERVED_NAME),
            "a module variable's default": (added(compute, suffix_default + resource(
                "aws_iam_role", "extra", 'name = "${var.name_prefix}-${var.role_suffix}"', self.ROLE_BODY)), self.RESERVED_NAME),
            "a root-supplied module variable": (check.Tree(supplied, REPOSITORY.listed + [compute]), self.RESERVED_NAME),
            "a reserved name_prefix": (added(staging, resource(
                "aws_iam_role", "extra", 'name_prefix = "firmbatch-staging-github-plan"', self.ROLE_BODY)),
                "its effective name_prefix is a GitHub delivery identity's"),
            "a literal name in another letter case": (added(staging, resource(
                "aws_iam_role", "extra", 'name = "Firmbatch-Staging-GitHub-Plan"', self.ROLE_BODY)), self.RESERVED_NAME),
        }
        for name, (tree, fragment) in cases.items():
            with self.subTest(case=name):
                self.assertReports(check.rule_delivery_trust, tree, f"aws_iam_role.extra: {fragment}")

    def test_a_role_name_that_cannot_be_proven_clear_fails_closed(self):
        staging = f"{TF}/environments/staging/extra_role.tf"
        cases = {
            "a function call": ('name = format("%s-%s", var.name_prefix, var.kind)', "effective name cannot be resolved"),
            "a conditional": ('name = var.admin ? "a" : "b"', "effective name cannot be resolved"),
            "plan-time text that could complete a reserved suffix": (
                'name = "${var.name_prefix}-${var.kind}"', "could complete a delivery identity's name",
            ),
            "a plan-time prefix before a partial suffix": ('name = "${var.name_prefix}-plan"', "could complete a delivery identity's name"),
        }
        for name, (line, fragment) in cases.items():
            with self.subTest(case=name):
                tree = added(staging, resource("aws_iam_role", "extra", line, self.ROLE_BODY))
                self.assertReports(check.rule_delivery_trust, tree, fragment)
                self.assertReports(check.rule_delivery_trust, tree, "failing closed")
        tree = added(staging, resource("aws_iam_role", "extra", "for_each = var.roles", "name = each.key", self.ROLE_BODY))
        self.assertReports(check.rule_delivery_trust, tree, "its for_each cannot be read")

    def test_the_workload_roles_stay_accepted_and_resolve_to_their_reviewed_names(self):
        self.assertEqual(check.delivery_identity_adoption(REPOSITORY), [])
        tasks = check._local_value(REPOSITORY, COMPUTE, "local.tasks")
        families = sorted(entry["family"] for entry in tasks.values())
        self.assertEqual(families, ["bootstrap", "identity-binding", "identity-broker", "migrate", "web-api"])
        for label in ("execution", "task"):
            with self.subTest(role=label):
                role = next(block for _, block in REPOSITORY.resource(COMPUTE, "aws_iam_role", label))
                names = sorted(
                    name for entry in tasks.items() for name in check._name_candidates(REPOSITORY, COMPUTE, role.attributes["name"], entry)
                )
                self.assertEqual(names, sorted(f"{check._PLAN_TIME}-{family}-{label}" for family in families))
                self.assertEqual({check._delivery_name_verdict(name) for name in names}, {"clear"})
        unlisted = added(f"{COMPUTE}/worker.tf", resource("aws_iam_role", "worker", 'name = "${var.name_prefix}-worker"', self.ROLE_BODY))
        self.assertReports(check.rule_delivery_trust, unlisted, "aws_iam_role.worker is not an allow-listed workload role")
        task_name = '"${var.name_prefix}-${each.value.family}-task"'
        renamed = mutated(f"{COMPUTE}/iam.tf", task_name, task_name.replace("-task", "-runner"))
        self.assertReports(check.rule_delivery_trust, renamed, "aws_iam_role.task is not an allow-listed workload role")

    def test_the_literal_document_check_itself_refuses_each_admitted_policy_in_another_form(self):
        # The evaluator also fails closed on these, with its own wording; this pins the graph check's own refusal.
        admitted = {
            ("aws_iam_role_policy", "github_plan"): "plan", ("aws_iam_role_policy", "github_apply"): "apply",
            ("aws_iam_role_policy", "artifact_publish"): "artifact-publish", ("aws_iam_policy", "plan_boundary"): "plan",
            ("aws_iam_policy", "apply_boundary"): "apply", ("aws_iam_policy", "artifact_publish_boundary"): "artifact-publish",
        }
        text = REPOSITORY.files[POLICIES]
        literal = "  policy = jsonencode({"
        for (kind, name), role in admitted.items():
            for reference in ("local.delivery_policy", "each.value", "data.aws_iam_policy_document.delivery.json"):
                with self.subTest(resource=name, reference=reference):
                    at = text.index(literal, text.index(f'resource "{kind}" "{name}" {{'))
                    changed = text[:at] + f"  policy = {reference}\n  unused = jsonencode({{" + text[at + len(literal):]
                    tree = check.Tree({**REPOSITORY.files, POLICIES: changed}, REPOSITORY.listed)
                    refusal = f"{kind}.{name} is not a literal jsonencode document; a delivery identity's policy is never a local"
                    graph = check.delivery_policy_graph(tree)
                    self.assertTrue(any(refusal in finding for finding in graph), graph)
                    if reference.startswith("local."):
                        self.assertReports(check.rule_policy_semantics, tree, f"the {role} policies could not be evaluated")

    def test_the_always_refused_requests_catch_what_the_statement_scan_cannot(self):
        anchor = (
            '      {\n        Sid      = "CallerIdentity"\n        Effect   = "Allow"\n        Action   = "sts:GetCallerIdentity"\n'
            '        Resource = "*"\n      },\n    ]\n  })\n}\n\nresource "aws_iam_policy" "artifact_publish_boundary"'
        )
        side = (
            '      {\n        Sid       = "NotActionSideDoor"\n        Effect    = "Allow"\n'
            '        NotAction = ["iam:*"]\n        Resource  = "*"\n      },\n'
        )
        tree = mutated(POLICIES, anchor, side + anchor)
        refused = f"the artifact-publish role can kms:Decrypt on {check._OTHER_KEY}, which it must never do"
        self.assertReports(check.rule_policy_semantics, tree, refused)
        # A NotAction allow names no action, so the per-statement grant scan reports nothing for it.
        self.assertFalse([f for f in check.rule_policy_semantics(tree) if "NotActionSideDoor grants" in f])
        saved = check.DELIVERY_NEVER
        check.DELIVERY_NEVER = ()
        try:
            self.assertFalse([f for f in check.rule_policy_semantics(tree) if refused in f])
        finally:
            check.DELIVERY_NEVER = saved
        for identity_name, boundary_name in (("github_plan", "plan_boundary"), ("github_apply", "apply_boundary"),
                                             ("artifact_publish", "artifact_publish_boundary")):
            identity = check.policy_statements(REPOSITORY, BOOTSTRAP, "aws_iam_role_policy", identity_name, check.BOOTSTRAP_BINDINGS)
            boundary = check.policy_statements(REPOSITORY, BOOTSTRAP, "aws_iam_policy", boundary_name, check.BOOTSTRAP_BINDINGS)
            for request in check.DELIVERY_NEVER:
                with self.subTest(identity=identity_name, action=request["action"]):
                    self.assertFalse(check.effective(identity, boundary, request))

    # ------------------------------------------------------------------ fail closed

    def test_an_unreadable_file_fails_closed(self):
        tree = mutated(f"{TF}/modules/network/main.tf", 'resource "aws_vpc" "this" {', 'resource "aws_vpc" "this" {{')
        findings = check.run_rules(tree)
        self.assertTrue(any("failing closed" in f for f in findings), findings)


class Evaluator(unittest.TestCase):
    """The IAM evaluator itself, on hand-written statements."""

    def test_action_resource_and_condition_matching(self):
        deny_outside_region = {
            "Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["eu-central-1"]}},
        }
        self.assertFalse(check.statement_applies(deny_outside_region, check._request("s3:GetObject", "arn:aws:s3:::b/k")))
        elsewhere = check._request("s3:GetObject", "arn:aws:s3:::b/k", region="us-west-2")
        self.assertTrue(check.statement_applies(deny_outside_region, elsewhere))
        self.assertFalse(check.statement_applies(deny_outside_region, check._request("IAM:CreateRole", "*", region="us-west-2")))
        if_exists = {
            "Effect": "Allow", "Action": "ecs:UpdateService", "Resource": "*",
            "Condition": {"ArnLikeIfExists": {"ecs:task-definition": "arn:x:task-definition/web:*"}},
        }
        self.assertTrue(check.statement_applies(if_exists, {"action": "ecs:UpdateService", "resource": "s", "context": {}}))
        other_family = {
            "action": "ecs:UpdateService", "resource": "s", "context": {"ecs:task-definition": ["arn:x:task-definition/other:1"]},
        }
        self.assertFalse(check.statement_applies(if_exists, other_family))
        null_and_not_like = {"Effect": "Deny", "Action": "ecs:UpdateService", "Resource": "*", "Condition": {
            "Null": {"ecs:task-definition": "false"}, "ArnNotLike": {"ecs:task-definition": "arn:x:task-definition/web:*"},
        }}
        self.assertFalse(check.statement_applies(null_and_not_like, {"action": "ecs:UpdateService", "resource": "s", "context": {}}))
        self.assertTrue(check.statement_applies(null_and_not_like, other_family))
        with self.assertRaises(check.PolicyUnresolved):
            unsupported = {"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"DateLessThan": {"aws:CurrentTime": "x"}}}
            check.statement_applies(unsupported,
                                    {"action": "a:b", "resource": "*", "context": {}})

    def test_broad_denies_are_judged_by_semantics(self):
        narrow_region = {
            "Sid": "Region", "Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["eu-central-1"]}},
        }
        always = {
            "Sid": "Always", "Effect": "Deny", "NotAction": ["iam:Get*"], "Resource": "*",
            "Condition": {"StringLike": {"aws:RequestedRegion": "*"}},
        }
        service_not_resource = {"Sid": "S3", "Effect": "Deny", "Action": "s3:*", "NotResource": ["arn:aws:s3:::b/*"]}
        every_service_not_resource = {"Sid": "All", "Effect": "Deny", "Action": "*", "NotResource": ["arn:aws:s3:::b/*"]}
        self.assertEqual(check.broad_not_action_denies([narrow_region, service_not_resource]), [])
        self.assertEqual(check.broad_not_action_denies([always, every_service_not_resource]), ["Always", "All"])


if __name__ == "__main__":
    unittest.main()
