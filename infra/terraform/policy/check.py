#!/usr/bin/env python3
"""Structural and semantic policy checks over the Milestone 3.3b Terraform, workflow, container
and delivery files (ADR 0011 decisions 6-9; ADR 0012).

    python3 infra/terraform/policy/check.py

Independent of Terraform: it reads the files as text and structure and asserts the
properties the architecture requires, so a mistake in a Terraform validation, a test
assertion or a workflow is caught by a second, separately written check. Every rule reads a
:class:`Tree` -- a mapping of repository-relative path to content -- so the tests can mutate a
copy of the real repository and prove each rule refuses the property's absence.

The delivery policies are also EVALUATED, not only read: a small IAM evaluator resolves each
policy against synthetic bindings and decides representative requests statement by statement --
Action or NotAction, Resource or NotResource, and every condition operator the policies use -- so
a statement that reads plausibly but denies what it should not (a NotAction deny of everything
but IAM reads, say) is refused for what it does.

Standard library only. It makes no network call and runs no Terraform.
"""

from __future__ import annotations

import ast
import json
import pathlib
import posixpath
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
if __package__ in (None, ""):
    sys.path.insert(0, str(HERE.parent))

from policy import hcl, yaml_subset  # noqa: E402
from policy.hcl import Call  # noqa: E402

REPO = HERE.parents[2]
TF = "infra/terraform"
MODULES = ("network", "edge", "compute", "database", "identity", "secrets", "observability", "delivery")
ROOTS = {"bootstrap": f"{TF}/bootstrap", "artifacts": f"{TF}/artifacts", "staging": f"{TF}/environments/staging"}
BOOTSTRAP = ROOTS["bootstrap"]
ARTIFACTS = ROOTS["artifacts"]
DELIVERY = f"{TF}/modules/delivery"
COMPUTE = f"{TF}/modules/compute"
PROVIDER_SOURCE = "hashicorp/aws"
PROVIDER_VERSION = "6.64.0"
GITHUB_REPOSITORY = "chamsrut/firmbatch"
GITHUB_REPOSITORY_ID = "1349512121"
PLAN_WORKFLOW = ".github/workflows/staging-plan.yml"
APPLY_WORKFLOW = ".github/workflows/staging-apply.yml"
PUBLISH_WORKFLOW = ".github/workflows/artifact-publish.yml"
CI_WORKFLOW = ".github/workflows/ci.yml"
DEPLOYMENT_EVIDENCE = "docs/evidence/m3/aws-staging/"

FORBIDDEN_RESOURCE_TYPES = {
    "aws_secretsmanager_secret_version": "secret values are written by the bootstrap task, never by Terraform",
    "aws_ssm_parameter": "no parameter values in Terraform",
    "random_password": "a generated password would live in state",
    "random_string": "a generated secret would live in state",
    "tls_private_key": "a private key would live in state",
    "aws_iam_access_key": "no permanent AWS access keys",
    "aws_iam_user": "no IAM users; humans use SSO and CI uses OIDC",
    "aws_iam_user_login_profile": "no IAM users",
    "aws_cognito_identity_pool": "no Cognito Identity Pools",
    "aws_cognito_user_group": "Cognito groups are never Firmbatch authorization",
    "aws_cognito_user": "Terraform never creates users",
    "aws_cognito_identity_provider": "no social or external identity providers in protected staging",
    "aws_instance": "no EC2 instances; compute is Fargate",
    "aws_spot_instance_request": "no GPU or spot capacity in this deployment",
    "aws_spot_fleet_request": "no GPU or spot capacity in this deployment",
    "aws_launch_template": "no EC2 compute",
    "aws_cloudfront_distribution": "CloudFront is deferred",
    "aws_sqs_queue": "the outbox dispatcher and payload plane are not part of M3.3",
    "aws_db_proxy": "RDS Proxy is deferred",
    "aws_rds_cluster": "one RDS PostgreSQL instance",
    "aws_security_group_rule": "use the per-rule VPC security group resources",
    "null_resource": "no escape hatch for commands",
}
FORBIDDEN_RESOURCE_PREFIXES = ("postgresql_", "random_", "local_", "external")
SECRET_ATTRIBUTE_NAMES = {
    "password", "master_password", "password_wo", "secret_string", "secret_binary", "secret_key",
    "access_key", "client_secret", "token",
}
NEVER_COMMITTED = re.compile(r"\.tfvars(\.json)?$|(^|/)terraform\.tfstate|\.tfstate(\.|$)|\.tfplan$|(^|/)crash(\.[0-9]+)?\.log$")
PLAN_ROLE_WRITES = ("s3:PutObject", "s3:DeleteObject", "kms:Encrypt", "kms:GenerateDataKey", "kms:Decrypt")
CREDENTIAL_NAME = re.compile(r"SECRET|PASSWORD|TOKEN|CREDENTIAL|ACCESS_KEY|PRIVATE_KEY|DATABASE_URL")
# The authority split (ADR 0012 decision 5): the trust-anchor resource types the pipeline never
# changes, the workload and budget types it does apply, and the apply boundary's denies.
HUMAN_APPLIED_PREFIXES = {"aws_iam_", "aws_kms_", "aws_secretsmanager_", "aws_ecr_", "aws_s3_", "aws_budgets_budget_action"}
PIPELINE_APPLIED_TYPES = ("aws_ecs_task_definition", "aws_ecs_service", "aws_ecs_cluster", "aws_budgets_budget", "aws_db_instance")
# The plan boundary's denies: what an attached side door still cannot reach through the plan role.
PLAN_BOUNDARY_DENIES = (
    "DenyPlanRoleSecretValuesAndParameters",
    "DenyPlanRoleDecryptOutsideStateAndReleaseRecords",
    "DenyPlanRoleReleaseKeyOutsideS3",
    "DenyPlanRoleEncryptOutsideStateAndSavedPlans",
    "DenyPlanRoleSavedPlanReadsHistoryAndRetentionBypass",
    "DenyPlanRoleStateWrites",
    "DenyPlanRoleS3OutsideStateSavedPlansAndReleaseRecords",
)
APPLY_BOUNDARY_DENIES = (
    "DenyPassingAnyRoleButThePreCreatedWorkloadRoles",
    "DenyPassingRolesToAnythingButEcsTasks",
    "DenyIdentityAndAccountAdministration",
    "DenySecretValuesAndContainerChanges",
    "DenySecretCreationExceptRdsManagedMasterSecret",
    "DenyKeyAdministrationAndNonServiceGrants",
    "DenyDecryptOutsideStatePlansAndReleaseRecords",
    "DenyOneOffTasksAndEcsExec",
    "DenyTaskDefinitionDeregistrationAndDeletion",
    "DenyServiceChangesOutsideTheTwoServices",
    "DenyTheWebApiServiceAnyOtherFamily",
    "DenyTheIdentityBrokerServiceAnyOtherFamily",
    "DenyEcsExecOnAnyService",
    "DenyImagePublicationAndRegistryChanges",
    "DenyDataExportAndLogReads",
    "DenyPurchasesBudgetActionsAndAlarmSuppression",
    "DenyReleaseRecordChanges",
    "DenySavedPlanWritesAndRetentionBypass",
)
APPLY_ROLE_NEVER = {
    "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret",
    "ecs:RunTask", "ecs:StartTask", "ecs:ExecuteCommand", "ecs:CreateTaskSet", "ecs:DeregisterTaskDefinition", "ecs:DeleteTaskDefinitions",
    "ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:CompleteLayerUpload", "ecr:BatchDeleteImage", "ecr:PutImageTagMutability",
    "ecr:GetAuthorizationToken", "kms:PutKeyPolicy", "kms:CreateKey", "budgets:CreateBudgetAction", "budgets:ExecuteBudgetAction", "*",
}
# The ECS grants the apply role holds only inside the delivery contract, and the resource each names.
APPLY_ROLE_CONTRACT_GRANTS = {
    "ecs:RegisterTaskDefinition": ("local.task_definition_arns",),
    "ecs:CreateService": ("local.service_arns.web_api", "local.service_arns.identity_broker"),
    "ecs:UpdateService": ("local.service_arns.web_api", "local.service_arns.identity_broker"),
    "ecs:DeleteService": ("local.service_arn_list",),
    "iam:PassRole": ("local.workload_role_arns",),
}
ECR_PUSH_ACTIONS = ("ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage")
# The only IAM actions the apply boundary's ceiling may admit, besides iam:PassRole on the workload roles.
IAM_READS = {
    "iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListRoleTags",
    "iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions", "iam:GetOpenIDConnectProvider",
}
PUBLISH_MAY = {
    "ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", *ECR_PUSH_ACTIONS, "ecr:BatchGetImage", "ecr:DescribeImages",
    "ecr:GetDownloadUrlForLayer", "s3:PutObject", "s3:GetObject", "kms:GenerateDataKey", "kms:Decrypt", "sts:GetCallerIdentity",
}

# Workflows. The one guard every credential-bearing job must carry, exactly; the permissions each job
# may hold; the environments reserved to their own workflow files; the private runner directory.
CREDENTIAL_JOB_GUARD = (
    f"github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.repository_id == '{GITHUB_REPOSITORY_ID}'"
)
READ_PREFLIGHT = {"contents": "read", "actions": "read", "pull-requests": "read"}
WORKFLOW_JOB_PERMISSIONS = {
    # publish reads its own attempt's jobs (check-publish-attempt) before its OIDC token.
    PUBLISH_WORKFLOW: {
        "preflight": READ_PREFLIGHT,
        "verify": {"contents": "read"},
        "publish": {"contents": "read", "actions": "read", "id-token": "write"},
    },
    PLAN_WORKFLOW: {"preflight": READ_PREFLIGHT, "plan": {**READ_PREFLIGHT, "id-token": "write"}},
    APPLY_WORKFLOW: {"preflight": READ_PREFLIGHT, "apply": {**READ_PREFLIGHT, "id-token": "write"}},
}
RESERVED_ENVIRONMENTS = {"artifact-publish": PUBLISH_WORKFLOW, "staging-plan": PLAN_WORKFLOW, "staging-apply": APPLY_WORKFLOW}
PRIVATE_DIR_VALUE = "${{ runner.temp }}/firmbatch-private"
TF_DATA_DIR_VALUE = "${{ runner.temp }}/firmbatch-private/terraform-data"
PRIVATE_DIR_CREATION = 'umask 077\nmkdir -m 700 "$PRIVATE_DIR"'
TERRAFORM_LEFTOVERS = (
    "rm -f -- infra/terraform/environments/staging/errored.tfstate infra/terraform/environments/staging/crash.log "
    "infra/terraform/environments/staging/crash.*.log"
)
CLEANUP_SCRIPTS = {
    "publish": (
        'docker logout "$ARTIFACT_REGISTRY_ACCOUNT_ID.dkr.ecr.$ARTIFACT_REGISTRY_REGION.amazonaws.com" > /dev/null 2>&1 || true\n'
        'rm -rf -- "$PRIVATE_DIR"'
    ),
    "plan": f'rm -rf -- "$PRIVATE_DIR"\n{TERRAFORM_LEFTOVERS}',
    "apply": f'rm -rf -- "$PRIVATE_DIR"\n{TERRAFORM_LEFTOVERS}',
}
APPLY_INPUTS = (
    "plan_key", "plan_version_id", "plan_sha256", "release_commit", "release_image", "release_record_version_id", "release_record_sha256",
)
PROVENANCE_LABELS = (
    "org.opencontainers.image.source", "org.opencontainers.image.revision", "org.opencontainers.image.created",
    "io.firmbatch.release.provenance", "io.firmbatch.release.repository-id", "io.firmbatch.release.workflow-ref",
    "io.firmbatch.release.run-id", "io.firmbatch.release.run-attempt",
)
UNTRUSTED_TRIGGERS = {"pull_request", "pull_request_target", "push", "workflow_run", "schedule", "issue_comment", "pull_request_review"}
STATUS_FUNCTION = re.compile(r"\b(always|failure|cancelled|success)\s*\(")


class Tree:
    """Repository files the rules read, keyed by repository-relative POSIX path."""

    def __init__(self, files: dict[str, str], listed: list[str] | None = None):
        self.files = dict(files)
        # Paths that exist without their contents mattering: tracked and untracked-unignored.
        self.listed = sorted(set(listed if listed is not None else files))
        self._parsed: dict[str, hcl.Block] = {}

    @classmethod
    def from_repository(cls, root: pathlib.Path = REPO) -> "Tree":
        files: dict[str, str] = {}
        wanted = [root / "infra", root / ".github"]
        for base in wanted:
            for path in base.rglob("*"):
                if not path.is_file() or ".terraform" in path.parts or "__pycache__" in path.parts:
                    continue
                files[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8", errors="replace")
        for name in ("Dockerfile", ".dockerignore"):
            if (root / name).is_file():
                files[name] = (root / name).read_text(encoding="utf-8")
        evidence = root / DEPLOYMENT_EVIDENCE
        if evidence.is_dir():
            for path in evidence.rglob("*"):
                if path.is_file():
                    files[path.relative_to(root).as_posix()] = ""
        listed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard"],
            capture_output=True, text=True, check=True,
        ).stdout.splitlines()
        return cls(files, listed + list(files))

    def text(self, path: str) -> str:
        return self.files.get(path, "")

    def exists(self, path: str) -> bool:
        return path in self.files

    def hcl(self, path: str) -> hcl.Block:
        if path not in self._parsed:
            self._parsed[path] = hcl.parse(self.files[path])
        return self._parsed[path]

    def under(self, prefix: str, suffix: str = "") -> list[str]:
        return sorted(p for p in self.files if p.startswith(prefix) and p.endswith(suffix))

    def blocks(self, prefix: str, block_type: str, *labels: str) -> list[tuple[str, hcl.Block]]:
        found = []
        for path in self.under(prefix, ".tf"):
            for block in self.hcl(path).children(block_type, *labels):
                found.append((path, block))
        return found

    def resource(self, prefix: str, resource_type: str, name: str | None = None) -> list[tuple[str, hcl.Block]]:
        labels = (resource_type,) if name is None else (resource_type, name)
        return self.blocks(prefix, "resource", *labels)

    def locals(self, prefix: str) -> dict:
        merged: dict = {}
        for _, block in self.blocks(prefix, "locals"):
            merged.update(block.attributes)
        return merged


# ---------------------------------------------------------------------- helpers


def _nested(block: hcl.Block, *path: str) -> list[hcl.Block]:
    current = [block]
    for step in path:
        current = [child for b in current for child in b.children(step)]
    return current


def _actions(statement: dict) -> list[str]:
    action = statement.get("Action")
    if isinstance(action, str):
        return [action]
    if isinstance(action, tuple):
        return [a for a in action if isinstance(a, str)]
    return []


def _statements(policy) -> list[dict]:
    """Literal statement objects of a jsonencode({ Statement = ... }) policy expression."""
    if not isinstance(policy, Call) or policy.name != "jsonencode" or not policy.args:
        return []
    document = policy.args[0]
    statements = document.get("Statement") if isinstance(document, dict) else None
    collected: list[dict] = []

    def gather(value):
        if isinstance(value, dict):
            collected.append(value)
        elif isinstance(value, tuple):
            for item in value:
                gather(item)
        elif isinstance(value, Call) and value.name == "concat":
            for argument in value.args:
                gather(argument)

    gather(statements)
    return collected


def _runs(job: dict) -> list[str]:
    return [step.get("run", "") for step in job.get("steps", []) if isinstance(step, dict) and isinstance(step.get("run"), str)]


def _sids(statements: list[dict]) -> dict:
    return {s.get("Sid"): s for s in statements}


# ---------------------------------------------------------------------- IAM policy semantics


class PolicyUnresolved(ValueError):
    """A policy value the evaluator has no binding for, or a construct it does not model."""


IAM_CONDITION_OPERATORS = frozenset({
    "StringEquals", "StringNotEquals", "StringEqualsIfExists", "StringNotEqualsIfExists", "StringLike", "ArnEquals", "ArnLike",
    "ArnLikeIfExists", "ArnNotEquals", "ArnNotLike", "Bool", "Null", "ForAnyValue:StringEquals", "ForAllValues:StringNotEquals",
})
SYNTHETIC_ACCOUNT = "111111111111"
SYNTHETIC_REGION = "eu-central-1"
SYNTHETIC_PREFIX = "firmbatch-staging"
_ECS = f"arn:aws:ecs:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}"
_WORKLOAD_FAMILIES = ("bootstrap", "identity-binding", "identity-broker", "migrate", "web-api")
# What each bootstrap-root reference means for evaluation. A policy that gains a reference with no
# binding here fails the check rather than being evaluated on a guess.
BOOTSTRAP_BINDINGS = {
    "local.account_id": SYNTHETIC_ACCOUNT,
    "var.region": SYNTHETIC_REGION,
    "var.artifact_registry_account_id": SYNTHETIC_ACCOUNT,
    "var.artifact_registry_region": SYNTHETIC_REGION,
    "var.name_prefix": SYNTHETIC_PREFIX,
    "var.release_name_prefix": "firmbatch",
    "var.rds_instance_class": "db.t4g.micro",
    "var.route53_zone_id": "Z0SYNTHETIC",
    "local.state_bucket_arn": "arn:aws:s3:::synthetic-state",
    "local.plan_bucket_arn": "arn:aws:s3:::synthetic-plans",
    "local.plan_object_prefix": "plans/",
    "local.github_role_arn_pattern": f"arn:aws:iam::{SYNTHETIC_ACCOUNT}:role/{SYNTHETIC_PREFIX}-github-*",
    "local.github_plan_role_arn": f"arn:aws:iam::{SYNTHETIC_ACCOUNT}:role/{SYNTHETIC_PREFIX}-github-plan",
    "local.github_apply_role_arn": f"arn:aws:iam::{SYNTHETIC_ACCOUNT}:role/{SYNTHETIC_PREFIX}-github-apply",
    "local.publish_role_arn": f"arn:aws:iam::{SYNTHETIC_ACCOUNT}:role/firmbatch-artifact-publish",
    "local.state_key": "staging/terraform.tfstate",
    "local.state_object_arn": "arn:aws:s3:::synthetic-state/staging/terraform.tfstate",
    "local.lock_object_arn": "arn:aws:s3:::synthetic-state/staging/terraform.tfstate.tflock",
    "local.environment_plans_arn": "arn:aws:s3:::synthetic-plans/plans/staging/*",
    "local.cluster_arn": f"{_ECS}:cluster/{SYNTHETIC_PREFIX}",
    "local.workload_role_arns": sorted(
        f"arn:aws:iam::{SYNTHETIC_ACCOUNT}:role/{SYNTHETIC_PREFIX}-{family}-{kind}"
        for family in _WORKLOAD_FAMILIES for kind in ("execution", "task")
    ),
    "local.task_definition_arns": sorted(f"{_ECS}:task-definition/{SYNTHETIC_PREFIX}-{family}:*" for family in _WORKLOAD_FAMILIES),
    "local.service_arns.web_api": f"{_ECS}:service/{SYNTHETIC_PREFIX}/{SYNTHETIC_PREFIX}-web-api",
    "local.service_arns.identity_broker": f"{_ECS}:service/{SYNTHETIC_PREFIX}/{SYNTHETIC_PREFIX}-identity-broker",
    "local.service_arn_list": sorted(f"{_ECS}:service/{SYNTHETIC_PREFIX}/{SYNTHETIC_PREFIX}-{s}" for s in ("web-api", "identity-broker")),
    "local.service_task_definition_arns.web_api": f"{_ECS}:task-definition/{SYNTHETIC_PREFIX}-web-api:*",
    "local.service_task_definition_arns.identity_broker": f"{_ECS}:task-definition/{SYNTHETIC_PREFIX}-identity-broker:*",
    "local.release_repository_arn": f"arn:aws:ecr:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:repository/firmbatch/control-plane",
    "local.release_objects_arn": "arn:aws:s3:::synthetic-releases/releases/*",
    "local.release_manifest_objects_arn": "arn:aws:s3:::synthetic-releases/releases/*/release-manifest.json",
    "aws_kms_key.state.arn": f"arn:aws:kms:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:key/00000000-0000-4000-8000-00000000000a",
    "aws_kms_key.plans.arn": f"arn:aws:kms:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:key/00000000-0000-4000-8000-00000000000b",
    "aws_kms_key.release.arn": f"arn:aws:kms:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:key/00000000-0000-4000-8000-0000000000e1",
}


def _resolve(value, bindings: dict | None):
    """A parsed HCL policy value with its references replaced by bindings.

    With ``bindings`` None, an unknown reference becomes an inert placeholder: enough to read a
    statement's shape, never to decide a request it names.
    """
    if value is None or isinstance(value, (bool, int, float)):
        return value

    def binding(reference: str):
        reference = reference.strip()
        if bindings is None:
            return f"<{reference}>"
        if reference not in bindings:
            raise PolicyUnresolved(f"no evaluation binding for {reference}")
        return bindings[reference]

    if isinstance(value, hcl.Raw):
        return binding(str(value))
    if isinstance(value, str):
        return re.sub(r"\$\{([^}]*)\}", lambda m: str(binding(m.group(1))), value)
    if isinstance(value, tuple):
        resolved = []
        for item in value:
            item = _resolve(item, bindings)
            resolved.extend(item) if isinstance(item, list) else resolved.append(item)
        return resolved
    if isinstance(value, dict):
        return {(_resolve(k, bindings) if isinstance(k, str) else k): _resolve(v, bindings) for k, v in value.items()}
    if bindings is None:
        return f"<{value!r}>"
    raise PolicyUnresolved(f"a policy expression the evaluator does not model: {value!r}")


def _local_value(tree: Tree, prefix: str, reference: str):
    """A `local.name` or `local.name.key` reference, read from the prefix's locals blocks."""
    parts = reference.split(".")
    value = tree.locals(prefix).get(parts[1]) if len(parts) >= 2 and parts[0] == "local" else None
    for key in parts[2:]:
        value = value.get(key) if isinstance(value, dict) else None
    return value


def _raw_policy_statements(tree: Tree, prefix: str, policy) -> list[dict]:
    """Statements of a jsonencode policy: literal statements, a statement or statement list held in
    a local, and a concat of any of them."""
    if not isinstance(policy, Call) or policy.name != "jsonencode" or not policy.args or not isinstance(policy.args[0], dict):
        raise PolicyUnresolved("a policy that is not a literal jsonencode document")
    collected: list[dict] = []

    def gather(part):
        if isinstance(part, hcl.Raw) and str(part).startswith("local."):
            part = _local_value(tree, prefix, str(part))
        if isinstance(part, dict):
            collected.append(part)
        elif isinstance(part, tuple):
            for item in part:
                gather(item)
        elif isinstance(part, Call) and part.name == "concat":
            for argument in part.args:
                gather(argument)
        else:
            raise PolicyUnresolved("a policy statement list the evaluator cannot read")

    gather(policy.args[0].get("Statement"))
    return collected


def policy_statements(tree: Tree, prefix: str, resource_type: str, name: str, bindings: dict | None) -> list[dict]:
    found = tree.resource(prefix, resource_type, name)
    if len(found) != 1:
        raise PolicyUnresolved(f"{prefix}: exactly one {resource_type}.{name}")
    return [_resolve(s, bindings) for s in _raw_policy_statements(tree, prefix, found[0][1].attributes.get("policy"))]


def _listify(value) -> list:
    return value if isinstance(value, list) else [value]


def _wildcard(pattern, value: str, ignore_case: bool = False) -> bool:
    regex = "".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in str(pattern))
    return re.fullmatch(regex, value, re.IGNORECASE if ignore_case else 0) is not None


# Keys AWS attaches to every request. Each synthetic request carries them, so a condition on one is
# decided as AWS would decide it -- a deny conditioned on aws:SecureTransport = true applies to every
# HTTPS request, not to none.
GLOBAL_REQUEST_CONTEXT = {"aws:SecureTransport": ["true"], "aws:RequestedRegion": [SYNTHETIC_REGION]}
# Service keys a request legitimately may not carry: the evaluator decides an absent one by the
# operator's own rule. Any other key absent from a request is one the evaluator does not model, and a
# statement that applies to that request conditioned on it fails closed rather than being decided on a
# guess.
OPTIONAL_CONDITION_KEYS = frozenset({
    "aws:CalledVia", "ecs:cluster", "ecs:enable-execute-command", "ecs:task-definition", "iam:PassedToService",
    "kms:GrantIsForAWSResource", "kms:ViaService", "rds:DatabaseClass", "s3:if-none-match", "s3:prefix",
})


def _condition_holds(operator: str, key: str, wanted, context: dict) -> bool:
    if operator not in IAM_CONDITION_OPERATORS:
        raise PolicyUnresolved(f"condition operator {operator}")
    if key not in context and key not in OPTIONAL_CONDITION_KEYS:
        raise PolicyUnresolved(f"condition key {key}, which no synthetic request models")
    present = key in context
    values = context.get(key, [])
    wants = [str(w) for w in _listify(wanted)]
    equal = any(v in wants for v in values)
    like = any(_wildcard(w, v) for v in values for w in wants)
    if operator in ("StringEquals", "Bool", "ForAnyValue:StringEquals"):
        return present and equal
    if operator in ("StringNotEquals", "ForAllValues:StringNotEquals"):
        return not present or not equal
    if operator == "StringEqualsIfExists":
        return not present or equal
    if operator == "StringNotEqualsIfExists":
        return not present or not equal
    if operator in ("StringLike", "ArnEquals", "ArnLike"):
        return present and like
    if operator == "ArnLikeIfExists":
        return not present or like
    if operator in ("ArnNotEquals", "ArnNotLike"):
        return not present or not like
    return (wants[0] == "true") != present  # Null


def statement_applies(statement: dict, request: dict) -> bool:
    action, resource = request["action"], request["resource"]
    context = {**GLOBAL_REQUEST_CONTEXT, **request.get("context", {})}
    if "Action" in statement:
        acts = any(_wildcard(p, action, ignore_case=True) for p in _listify(statement["Action"]))
    elif "NotAction" in statement:
        acts = not any(_wildcard(p, action, ignore_case=True) for p in _listify(statement["NotAction"]))
    else:
        raise PolicyUnresolved("a statement with neither Action nor NotAction")
    if "Resource" in statement:
        applies_to = any(_wildcard(p, resource) for p in _listify(statement["Resource"]))
    elif "NotResource" in statement:
        applies_to = not any(_wildcard(p, resource) for p in _listify(statement["NotResource"]))
    else:
        applies_to = True
    if not (acts and applies_to):
        return False
    conditions = statement.get("Condition") or {}
    return all(_condition_holds(op, key, wanted, context) for op, entries in conditions.items() for key, wanted in entries.items())


def effective(identity: list[dict], boundary: list[dict] | None, request: dict) -> bool:
    """Allowed by the identity policy and by the boundary (when there is one), and denied by neither."""
    identity_hits = [s["Effect"] for s in identity if statement_applies(s, request)]
    boundary_hits = [s["Effect"] for s in boundary if statement_applies(s, request)] if boundary is not None else ["Allow"]
    return "Allow" in identity_hits and "Allow" in boundary_hits and "Deny" not in identity_hits + boundary_hits


def _request(action: str, resource: str, region: str = SYNTHETIC_REGION, **context) -> dict:
    keys = {"aws:RequestedRegion": [region]}
    keys.update({k.replace("__", ":").replace("_", "-"): _listify(v) for k, v in context.items()})
    return {"action": action, "resource": resource, "context": keys}


_S3_STATE = "arn:aws:s3:::synthetic-state/staging/terraform.tfstate"
_PLAN_OBJECT = f"arn:aws:s3:::synthetic-plans/plans/staging/{'a' * 40}/{'c' * 64}.tfplan"
_RECORD = f"arn:aws:s3:::synthetic-releases/releases/{'a' * 40}/release-manifest.json"
_REPOSITORY = BOOTSTRAP_BINDINGS["local.release_repository_arn"]
_CLUSTER = BOOTSTRAP_BINDINGS["local.cluster_arn"]
_SERVICE = f"{_ECS}:service/{SYNTHETIC_PREFIX}/{SYNTHETIC_PREFIX}-"
_TASK = f"{_ECS}:task-definition/{SYNTHETIC_PREFIX}-"
_ROLE = f"arn:aws:iam::{SYNTHETIC_ACCOUNT}:role/"
_KEY = BOOTSTRAP_BINDINGS["aws_kms_key.release.arn"]

# Representative requests: what the apply role must be able to do, and what it must never do.
APPLY_REQUIRED = (
    _request("s3:GetObject", _S3_STATE),
    _request("s3:PutObject", _S3_STATE),
    _request("s3:GetObjectVersion", _PLAN_OBJECT),
    _request("kms:Decrypt", BOOTSTRAP_BINDINGS["aws_kms_key.plans.arn"]),
    _request("ec2:CreateVpc", f"arn:aws:ec2:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:vpc/*"),
    _request("ec2:AuthorizeSecurityGroupIngress", f"arn:aws:ec2:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:security-group/sg-1"),
    _request("rds:CreateDBInstance", f"arn:aws:rds:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:db:x", rds__DatabaseClass="db.t4g.micro"),
    _request("rds:ModifyDBInstance", f"arn:aws:rds:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:db:x", rds__DatabaseClass="db.t4g.micro"),
    _request("ecs:RegisterTaskDefinition", f"{_TASK}web-api:8"),
    {**_request("ecs:UpdateService", f"{_SERVICE}web-api"), "context": {
        "aws:RequestedRegion": [SYNTHETIC_REGION], "ecs:cluster": [_CLUSTER], "ecs:task-definition": [f"{_TASK}web-api:8"],
        "ecs:enable-execute-command": ["false"],
    }},
    {**_request("ecs:UpdateService", f"{_SERVICE}identity-broker"), "context": {
        "aws:RequestedRegion": [SYNTHETIC_REGION], "ecs:cluster": [_CLUSTER],
    }},
    {**_request("ecs:CreateService", f"{_SERVICE}identity-broker"), "context": {
        "aws:RequestedRegion": [SYNTHETIC_REGION], "ecs:cluster": [_CLUSTER], "ecs:task-definition": [f"{_TASK}identity-broker:1"],
        "ecs:enable-execute-command": ["false"],
    }},
    {**_request("iam:PassRole", f"{_ROLE}{SYNTHETIC_PREFIX}-web-api-execution"), "context": {
        "aws:RequestedRegion": [SYNTHETIC_REGION], "iam:PassedToService": ["ecs-tasks.amazonaws.com"],
    }},
    _request("logs:CreateLogGroup", f"arn:aws:logs:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:log-group:/ecs/{SYNTHETIC_PREFIX}/web-api"),
    _request("cloudwatch:PutMetricAlarm", f"arn:aws:cloudwatch:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:alarm:{SYNTHETIC_PREFIX}-x"),
    _request("sns:CreateTopic", f"arn:aws:sns:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:{SYNTHETIC_PREFIX}-alerts"),
    _request("budgets:ModifyBudget", f"arn:aws:budgets::{SYNTHETIC_ACCOUNT}:budget/{SYNTHETIC_PREFIX}-monthly", region="us-east-1"),
    _request("ecr:DescribeImageScanFindings", _REPOSITORY),
    _request("s3:GetObjectVersion", _RECORD),
    {**_request("kms:Decrypt", _KEY), "context": {
        "aws:RequestedRegion": [SYNTHETIC_REGION], "kms:ViaService": [f"s3.{SYNTHETIC_REGION}.amazonaws.com"],
    }},
)
APPLY_PROHIBITED = (
    _request("iam:CreateRole", f"{_ROLE}replacement", region="us-east-1"),
    _request("iam:PutRolePolicy", f"{_ROLE}{SYNTHETIC_PREFIX}-github-apply", region="us-east-1"),
    _request("iam:AttachRolePolicy", f"{_ROLE}{SYNTHETIC_PREFIX}-web-api-task", region="us-east-1"),
    _request("iam:UpdateAssumeRolePolicy", f"{_ROLE}{SYNTHETIC_PREFIX}-github-apply", region="us-east-1"),
    _request("iam:DeleteRolePermissionsBoundary", f"{_ROLE}{SYNTHETIC_PREFIX}-github-apply", region="us-east-1"),
    _request(
        "iam:CreatePolicyVersion", f"arn:aws:iam::{SYNTHETIC_ACCOUNT}:policy/{SYNTHETIC_PREFIX}-github-apply-boundary", region="us-east-1",
    ),
    {**_request("iam:PassRole", f"{_ROLE}administrator"), "context": {
        "aws:RequestedRegion": [SYNTHETIC_REGION], "iam:PassedToService": ["ecs-tasks.amazonaws.com"],
    }},
    {**_request("iam:PassRole", f"{_ROLE}{SYNTHETIC_PREFIX}-web-api-task"), "context": {
        "aws:RequestedRegion": [SYNTHETIC_REGION], "iam:PassedToService": ["lambda.amazonaws.com"],
    }},
    _request("ecs:DeregisterTaskDefinition", f"{_TASK}web-api:7"),
    {**_request("ecs:UpdateService", f"{_SERVICE}web-api"), "context": {
        "aws:RequestedRegion": [SYNTHETIC_REGION], "ecs:cluster": [_CLUSTER], "ecs:task-definition": [f"{_TASK}bootstrap:3"],
    }},
    {**_request("ecs:UpdateService", f"{_SERVICE}identity-broker"), "context": {
        "aws:RequestedRegion": [SYNTHETIC_REGION], "ecs:cluster": [_CLUSTER], "ecs:enable-execute-command": ["true"],
    }},
    _request("ecs:RunTask", f"{_TASK}bootstrap:3"),
    _request("ecr:PutImage", _REPOSITORY),
    _request("s3:PutObject", _RECORD),
    _request("secretsmanager:GetSecretValue", f"arn:aws:secretsmanager:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:secret:{SYNTHETIC_PREFIX}/x"),
    _request("ec2:CreateVpc", f"arn:aws:ec2:us-west-2:{SYNTHETIC_ACCOUNT}:vpc/*", region="us-west-2"),
    _request(
        "budgets:CreateBudgetAction", f"arn:aws:budgets::{SYNTHETIC_ACCOUNT}:budget/{SYNTHETIC_PREFIX}-monthly/action/*",
        region="us-east-1",
    ),
)
_VIA_S3 = {"kms:ViaService": [f"s3.{SYNTHETIC_REGION}.amazonaws.com"]}
PUBLISH_REQUIRED = (
    {"action": "ecr:GetAuthorizationToken", "resource": "*", "context": {}},
    {"action": "ecr:PutImage", "resource": _REPOSITORY, "context": {}},
    {"action": "ecr:BatchGetImage", "resource": _REPOSITORY, "context": {}},
    {"action": "ecr:GetDownloadUrlForLayer", "resource": _REPOSITORY, "context": {}},
    {"action": "ecr:DescribeImages", "resource": _REPOSITORY, "context": {}},
    {"action": "s3:PutObject", "resource": _RECORD, "context": {}},
    {"action": "s3:GetObject", "resource": _RECORD, "context": {}},
    {"action": "kms:GenerateDataKey", "resource": _KEY, "context": _VIA_S3},
    {"action": "kms:Decrypt", "resource": _KEY, "context": _VIA_S3},
    {"action": "sts:GetCallerIdentity", "resource": "*", "context": {}},
)
PUBLISH_PROHIBITED = (
    {"action": "ecr:BatchDeleteImage", "resource": _REPOSITORY, "context": {}},
    {"action": "ecr:PutImageTagMutability", "resource": _REPOSITORY, "context": {}},
    {"action": "ecr:PutImage", "resource": _REPOSITORY.replace("firmbatch/control-plane", "firmbatch-staging"), "context": {}},
    {"action": "s3:PutObject", "resource": _PLAN_OBJECT, "context": {}},
    {"action": "s3:DeleteObject", "resource": _RECORD, "context": {}},
    {"action": "kms:Decrypt", "resource": _KEY, "context": {}},
    {"action": "kms:Encrypt", "resource": _KEY, "context": {"kms:ViaService": [f"ecr.{SYNTHETIC_REGION}.amazonaws.com"]}},
    {"action": "iam:PassRole", "resource": f"{_ROLE}{SYNTHETIC_PREFIX}-web-api-task", "context": {
        "iam:PassedToService": ["ecs-tasks.amazonaws.com"],
    }},
    {"action": "sts:AssumeRole", "resource": f"{_ROLE}{SYNTHETIC_PREFIX}-github-apply", "context": {}},
    {"action": "ecs:UpdateService", "resource": f"{_SERVICE}web-api", "context": {}},
    {
        "action": "secretsmanager:GetSecretValue", "resource": f"arn:aws:secretsmanager:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:secret:x",
        "context": {},
    },
)
_SECRET = f"arn:aws:secretsmanager:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:secret:{SYNTHETIC_PREFIX}/application-database-url-AbCdEf"
_PLANS_KEY = BOOTSTRAP_BINDINGS["aws_kms_key.plans.arn"]
_STATE_KEY = BOOTSTRAP_BINDINGS["aws_kms_key.state.arn"]
# The plan role has no boundary, so its own policy is the whole of what it can do: refresh reads,
# state and a new saved plan, release verification -- and never a secret value, a saved plan's
# contents or history, a state write, a push, a role, a rollout or a one-off task.
PLAN_REQUIRED = (
    _request("s3:GetObject", _S3_STATE),
    _request("s3:PutObject", f"{_S3_STATE}.tflock"),
    _request("s3:PutObject", _PLAN_OBJECT),
    _request("kms:GenerateDataKey", _PLANS_KEY),
    _request("kms:Decrypt", _STATE_KEY),
    _request("ec2:DescribeVpcs", "*"),
    _request("ecs:DescribeServices", f"{_SERVICE}web-api"),
    _request("secretsmanager:DescribeSecret", _SECRET),
    _request("iam:GetRole", f"{_ROLE}{SYNTHETIC_PREFIX}-web-api-task", region="us-east-1"),
    _request("ecr:DescribeImages", _REPOSITORY),
    _request("ecr:DescribeImageScanFindings", _REPOSITORY),
    _request("s3:GetObject", _RECORD),
    {**_request("kms:Decrypt", _KEY), "context": _VIA_S3},
    _request("sts:GetCallerIdentity", "*"),
)
PLAN_PROHIBITED = (
    _request("secretsmanager:GetSecretValue", _SECRET),
    _request("secretsmanager:BatchGetSecretValue", "*"),
    _request("s3:GetObject", _PLAN_OBJECT),
    _request("s3:GetObjectVersion", _PLAN_OBJECT),
    _request("s3:ListBucketVersions", "arn:aws:s3:::synthetic-plans"),
    _request("s3:BypassGovernanceRetention", _PLAN_OBJECT),
    _request("s3:PutObject", _S3_STATE),
    _request("s3:PutObject", _RECORD),
    _request("kms:Decrypt", _PLANS_KEY),
    _request("kms:Decrypt", _KEY),
    {
        **_request("iam:PassRole", f"{_ROLE}{SYNTHETIC_PREFIX}-web-api-task"),
        "context": {"iam:PassedToService": ["ecs-tasks.amazonaws.com"]},
    },
    _request("sts:AssumeRole", f"{_ROLE}{SYNTHETIC_PREFIX}-github-apply", region="us-east-1"),
    _request("ecs:UpdateService", f"{_SERVICE}web-api"),
    _request("ecs:RegisterTaskDefinition", f"{_TASK}web-api:8"),
    _request("ecs:RunTask", f"{_TASK}bootstrap:3"),
    _request("ecr:PutImage", _REPOSITORY),
    _request("ecr:GetAuthorizationToken", "*"),
    _request("ec2:CreateVpc", f"arn:aws:ec2:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:vpc/*"),
    _request("cognito-idp:ListUsers", f"arn:aws:cognito-idp:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:userpool/x"),
    _request("logs:GetLogEvents", f"arn:aws:logs:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:log-group:/ecs/x:log-stream:y"),
)
# Actions no NotAction deny may catch in the staging region: if one does, the statement denies
# everything but a short allow-list rather than the service it is meant to narrow.
NOT_ACTION_PROBES = (
    "s3:GetObject", "ec2:CreateVpc", "rds:ModifyDBInstance", "ecs:UpdateService",
    "logs:CreateLogGroup", "kms:Decrypt", "ecr:DescribeImages",
)
POLICY_RESOURCE_TYPES = (
    "aws_iam_role_policy", "aws_iam_policy", "aws_s3_bucket_policy", "aws_ecr_repository_policy", "aws_kms_key", "aws_sns_topic_policy",
)
# Resources whose `policy` attribute is not an IAM policy document. Any other resource carrying a policy
# of a type outside POLICY_RESOURCE_TYPES is refused rather than skipped.
NON_IAM_POLICY_TYPES = frozenset({"aws_ecr_lifecycle_policy"})


def _policy_documents(tree: Tree, prefix: str, block: hcl.Block) -> list:
    """Every jsonencode document a resource's `policy` can hold: a literal; a local holding one; or, for a
    for_each resource whose policy is each.value, every value of the local map it iterates. Anything else
    is refused, never skipped: a policy this check cannot read is a policy it cannot judge."""
    policy = block.attributes.get("policy")
    if isinstance(policy, Call):
        return [policy]
    reference = str(policy) if isinstance(policy, hcl.Raw) else ""
    if reference.startswith("local."):
        value = _local_value(tree, prefix, reference)
        if isinstance(value, Call):
            return [value]
    if reference == "each.value":
        for_each = block.attributes.get("for_each")
        iterated = str(for_each) if isinstance(for_each, hcl.Raw) else ""
        values = _local_value(tree, prefix, iterated) if iterated.startswith("local.") else None
        if isinstance(values, dict) and values and all(isinstance(v, Call) for v in values.values()):
            return list(values.values())
    raise PolicyUnresolved(
        "a policy that is neither a literal jsonencode document, a local holding one, nor each.value over a local map of them"
    )


def broad_not_action_denies(statements: list[dict]) -> list[str]:
    """The Sids of statements that deny, or allow, everything except a short allow-list.

    A NotAction or NotResource statement is judged by what it does, not refused for its shape: a
    NotAction deny passes only when, for requests in the staging region, it applies to none of the
    probe actions -- as a deny narrowed to other regions does; a NotResource deny passes only when it
    names the actions it denies, service by service; a NotAction or NotResource allow never passes.
    """
    broad = []
    for statement in statements:
        sid = statement.get("Sid", "<no Sid>")
        if "NotAction" in statement:
            if statement.get("Effect") != "Deny":
                broad.append(sid)
                continue
            resources = _listify(statement.get("Resource", "*"))
            resource = "*" if "*" in resources else str(resources[0])
            if any(statement_applies(statement, _request(action, resource)) for action in NOT_ACTION_PROBES):
                broad.append(sid)
        elif "NotResource" in statement:
            actions = _listify(statement.get("Action", "*"))
            if statement.get("Effect") != "Deny" or any(a == "*" or ":" not in str(a) for a in actions):
                broad.append(sid)
    return broad


# ---------------------------------------------------------------------- layout and versions


def rule_layout(tree: Tree) -> list[str]:
    findings = []
    present = sorted({p.split("/")[3] for p in tree.under(f"{TF}/modules/", ".tf")})
    if present != sorted(MODULES):
        findings.append(f"infra/terraform/modules must hold exactly {', '.join(MODULES)}; found {', '.join(present) or 'none'}")
    for name, root in ROOTS.items():
        for required in ("versions.tf", "providers.tf", ".terraform.lock.hcl"):
            if not tree.exists(f"{root}/{required}"):
                findings.append(f"{root}/{required} is missing")
        if not tree.under(f"{root}/tests/", ".tftest.hcl"):
            findings.append(f"the {name} root has no mocked Terraform test")
    production = tree.under(f"{TF}/environments/production/")
    if production != [f"{TF}/environments/production/README.md"]:
        findings.append("environments/production holds only README.md; production is not created by Milestone 3")
    stray = [p for p in tree.under(TF, ".tftest.hcl") if not any(p.startswith(f"{r}/tests/") for r in ROOTS.values())]
    if stray:
        findings.append(f"Terraform tests outside a root's tests directory cannot be proven mocked: {stray}")
    json_tests = tree.under(TF, ".tftest.json") + [p for p in tree.listed if p.endswith(".tftest.json")]
    if json_tests:
        findings.append(f"JSON Terraform tests are not read by the mocked-provider check: {sorted(set(json_tests))}")
    paths = sorted(set(tree.files) | set(tree.listed))
    # Terraform merges every *.tf.json file and every override file into a root, where the checks here
    # -- which read HCL -- would never see what they change.
    tf_json = [p for p in paths if p.startswith("infra/") and p.endswith(".tf.json")]
    if tf_json:
        findings.append(f"JSON-syntax Terraform configuration is never read by these checks and is refused: {tf_json}")
    overrides = [
        p for p in paths if p.startswith("infra/") and re.search(r"(^|/)([^/]*_)?override\.tf(\.json)?$", p)
    ]
    if overrides:
        findings.append(f"Terraform override files replace reviewed configuration invisibly and are refused: {overrides}")
    override_directories = [
        p for p in paths if p.startswith("infra/")
        and any(part in ("override", "overrides", "terraform.d") or part.endswith("_override") for part in p.split("/")[:-1])
    ]
    cli_configuration = [p for p in paths if p.split("/")[-1] in (".terraformrc", "terraform.rc")]
    if override_directories or cli_configuration:
        findings.append(
            "Terraform override directories, plugin mirrors and CLI configuration can substitute providers and are refused: "
            f"{sorted(set(override_directories + cli_configuration))}"
        )
    return findings


def rule_versions(tree: Tree) -> list[str]:
    findings = []
    pinned = tree.text(f"{TF}/.terraform-version").strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", pinned):
        return [f"{TF}/.terraform-version must hold one exact Terraform version"]
    for path in tree.under(TF, ".tf"):
        for block in tree.hcl(path).children("terraform"):
            if block.attributes.get("required_version") != pinned:
                findings.append(f"{path}: required_version must be exactly {pinned}")
            providers = [p for rp in block.children("required_providers") for p in rp.attributes.items()]
            for name, spec in providers:
                exact = isinstance(spec, dict) and spec.get("source") == PROVIDER_SOURCE and spec.get("version") == PROVIDER_VERSION
                if name != "aws" or not exact:
                    findings.append(f"{path}: the only provider is {PROVIDER_SOURCE} pinned exactly to {PROVIDER_VERSION}; found {name}")
        for provider in tree.hcl(path).children("provider"):
            if provider.labels != ["aws"]:
                findings.append(f"{path}: provider {provider.labels} is not allowed")
            if path.startswith(f"{TF}/modules/"):
                # A module's own provider configuration escapes its root's allowed_account_ids, region and
                # the mocked-provider check, which reads only roots.
                findings.append(f"{path}: a module configures no provider; it receives its root's")
    for root in ROOTS.values():
        lock = tree.text(f"{root}/.terraform.lock.hcl")
        if lock.count('provider "registry.terraform.io/') != 1 or f'version     = "{PROVIDER_VERSION}"' not in lock:
            findings.append(f"{root}/.terraform.lock.hcl must lock exactly {PROVIDER_SOURCE} {PROVIDER_VERSION}")
        if len(re.findall(r'"h1:[A-Za-z0-9+/=]+"', lock)) < 2:
            findings.append(f"{root}/.terraform.lock.hcl must carry h1 hashes for linux_amd64 and darwin_arm64")
    return findings


def rule_backends_and_workspaces(tree: Tree) -> list[str]:
    findings = []
    keys = {}
    for name, root in ROOTS.items():
        backends = [b for _, t in tree.blocks(root, "terraform") for b in t.children("backend")]
        if len(backends) != 1 or backends[0].labels != ["s3"]:
            findings.append(f"the {name} root must have exactly one s3 backend")
            continue
        backend = backends[0]
        if backend.attributes.get("use_lockfile") is not True or backend.attributes.get("encrypt") is not True:
            findings.append(f"the {name} backend must set use_lockfile = true and encrypt = true")
        for forbidden in ("dynamodb_table", "workspace_key_prefix", "access_key", "secret_key", "profile"):
            if forbidden in backend.attributes:
                findings.append(f"the {name} backend must not set {forbidden}")
        keys[name] = backend.attributes.get("key")
    if keys.get("bootstrap") != "bootstrap/terraform.tfstate":
        findings.append("the bootstrap root's state key must be bootstrap/terraform.tfstate")
    if keys.get("artifacts") != "artifacts/terraform.tfstate":
        findings.append("the artifacts root's state key must be artifacts/terraform.tfstate")
    if keys.get("staging") != "staging/terraform.tfstate" or tree.locals(ROOTS["staging"]).get("state_key") != keys.get("staging"):
        findings.append("the staging state key must be staging/terraform.tfstate and equal local.state_key")
    if tree.locals(BOOTSTRAP).get("state_key") != "${var.environment}/terraform.tfstate":
        findings.append("the bootstrap root confines the delivery identities to the staging root's own state key")
    if len(set(keys.values())) != len(keys):
        findings.append("each root has its own state key")
    for path in tree.under(TF, ".tf"):
        if "terraform.workspace" in tree.text(path):
            findings.append(f"{path}: Terraform workspaces are not used for environment isolation")
        if path.startswith(f"{TF}/modules/") and any(t.children("backend") for t in tree.hcl(path).children("terraform")):
            findings.append(f"{path}: a module declares no backend")
    return findings


def rule_account_and_region(tree: Tree) -> list[str]:
    findings = []
    for name, root in ROOTS.items():
        providers = tree.blocks(root, "provider", "aws")
        if not providers:
            findings.append(f"the {name} root configures no aws provider")
        aliases = set()
        for path, provider in providers:
            if provider.raw_attributes.get("allowed_account_ids") != "[var.expected_account_id]":
                findings.append(f"{path}: every aws provider must set allowed_account_ids = [var.expected_account_id]")
            alias = provider.attributes.get("alias")
            aliases.add(alias)
            if alias == "us_east_1" and provider.attributes.get("region") != "us-east-1":
                findings.append(f"{path}: the us_east_1 alias must use region us-east-1")
        expected = {None, "us_east_1"} if name == "staging" else {None}
        if aliases != expected:
            findings.append(f"the {name} root must configure provider aliases {sorted(a or 'default' for a in expected)}")
        identities = tree.blocks(root, "data", "aws_caller_identity")
        conditions = [
            c.raw_attributes.get("condition", "")
            for _, d in identities for c in _nested(d, "lifecycle", "postcondition")
        ]
        if not any("var.expected_account_id" in c for c in conditions):
            findings.append(f"the {name} root must postcondition aws_caller_identity on var.expected_account_id")
    return findings


# ---------------------------------------------------------------------- forbidden constructs


def rule_forbidden_constructs(tree: Tree) -> list[str]:
    findings = []
    for path in tree.under(TF, ".tf") + tree.under(TF, ".tftest.hcl"):
        root = tree.hcl(path)
        for block in root.walk():
            if block.type in ("provisioner", "connection"):
                findings.append(f"{path}: {block.type} blocks are not allowed")
            if block.type in ("authenticate_cognito", "authenticate_oidc") or any(
                value in ("authenticate-cognito", "authenticate-oidc") for value in block.attributes.values()
            ):
                findings.append(f"{path}: no ALB authentication; Cognito authenticates behind the broker")
            if block.type in ("captcha", "challenge"):
                findings.append(f"{path}: no CAPTCHA or challenge action on the managed-login paths")
            if any(isinstance(v, str) and re.search(r"\b(local-exec|remote-exec)\b", v) for v in block.attributes.values()):
                findings.append(f"{path}: Terraform never runs commands")
            if block.type in ("resource", "data") and block.labels:
                kind = block.labels[0]
                if kind in FORBIDDEN_RESOURCE_TYPES:
                    findings.append(f"{path}: {kind} is not allowed -- {FORBIDDEN_RESOURCE_TYPES[kind]}")
                elif kind.startswith(FORBIDDEN_RESOURCE_PREFIXES) or not (kind.startswith("aws_") or kind == "terraform_data"):
                    findings.append(f"{path}: {block.type} type {kind} is outside the aws provider")
            if block.type == "dynamic":
                findings.append(
                    f"{path}: dynamic {block.labels} blocks generate nested blocks these checks cannot see (an open "
                    "dynamic ingress, say); write each block out"
                )
            if block.type == "import":
                # Importing adopts existing infrastructure -- a delivery identity or another security principal among
                # it -- into state under whatever this configuration says. M3.3b commits no import workflow; adoption
                # is an explicit, separately reviewed human operation.
                findings.append(
                    f"{path}: an import block adopts existing infrastructure into state; no import is committed under infra/terraform"
                )
            if block.type == "module":
                # Resolved as Terraform resolves it: against the calling configuration's directory -- for a
                # test file, the root under test, not tests/. ../../modules from the staging root or from a
                # module is infra/terraform/modules, but from the bootstrap or artifacts root it is infra/modules.
                source = block.attributes.get("source")
                base = posixpath.dirname(path)
                if path.endswith(".tftest.hcl"):
                    base = posixpath.dirname(base)
                resolved = posixpath.normpath(posixpath.join(base, source)) if isinstance(source, str) else ""
                if not (isinstance(source, str) and source.startswith("../") and resolved in {f"{TF}/modules/{m}" for m in MODULES}):
                    findings.append(f"{path}: modules come only from the repository's own infra/terraform/modules, by relative path")
        for provider in (b for b in root.walk() if b.type == "required_providers"):
            for name in provider.attributes:
                if name != "aws":
                    findings.append(f"{path}: provider {name} is not allowed")
    if tree.resource(f"{TF}/modules/edge", "aws_wafv2_web_acl_association") or tree.resource(f"{TF}/modules/edge", "aws_wafv2_web_acl"):
        findings.append("modules/edge: no WAF is added to the ALB in M3.3")
    return findings


def rule_no_secret_values(tree: Tree) -> list[str]:
    findings = []
    paths = tree.under(TF, ".tf") + tree.under(TF, ".tftest.hcl") + tree.under(TF, ".tfvars.example") + tree.under("infra/delivery/")
    for path in paths:
        text = tree.text(path)
        if re.search(r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY", text):
            findings.append(f"{path}: contains credential material")
        if not path.endswith((".tf", ".tftest.hcl", ".tfvars.example")):
            continue
        for block in tree.hcl(path).walk():
            for name, value in block.attributes.items():
                if name in SECRET_ATTRIBUTE_NAMES and value is not None:
                    label = ".".join(block.labels)
                    findings.append(f"{path}: {block.type} {label} sets {name}; no secret value is ever written in Terraform")
            secret_named = block.labels and re.search(r"password|secret|token|credential|private_key", block.labels[0])
            if block.type == "variable" and secret_named and "default" in block.attributes:
                findings.append(f"{path}: variable {block.labels[0]} carries a default value")
            if block.type == "output" and re.search(r"client_secret|password|secret_string", block.raw_attributes.get("value", "")):
                findings.append(f"{path}: output {block.labels} exposes a secret")
    return findings


def rule_no_valued_tfvars(tree: Tree) -> list[str]:
    findings = []
    for path in tree.listed:
        if NEVER_COMMITTED.search(path):
            findings.append(f"{path}: valued tfvars, state, plans and crash logs are never in the repository")
    for path in tree.under(TF, ".tfvars.example"):
        text = re.sub(r"#.*", "", tree.text(path))
        if re.search(r"\b[0-9]{12}\b|arn:aws|[0-9a-f.:]+/[0-9]{1,3}\b|@[a-z0-9-]+\.|sha256:[0-9a-f]", text):
            findings.append(f"{path}: an example tfvars file must hold no deployment value")
    return findings


# ---------------------------------------------------------------------- the reach of tests


def rule_tests_are_mocked(tree: Tree) -> list[str]:
    """Fail if any Terraform test could configure a real AWS provider."""
    findings = []
    for name, root in ROOTS.items():
        required = {p.attributes.get("alias") for _, p in tree.blocks(root, "provider", "aws")}
        for path in tree.under(f"{root}/tests/", ".tftest.hcl"):
            document = tree.hcl(path)
            mocked = set()
            for mock in document.children("mock_provider"):
                if mock.labels != ["aws"]:
                    findings.append(f"{path}: mock_provider {mock.labels} names a provider this root does not use")
                mocked.add(mock.attributes.get("alias"))
            missing = required - mocked
            if missing:
                names = sorted(a or "default" for a in missing)
                findings.append(f"{path}: provider configuration(s) {names} are not mocked and could reach AWS")
            if document.children("provider"):
                findings.append(f"{path}: a test file configures a real provider block")
            for run in document.children("run"):
                if run.raw_attributes.get("command") != "plan":
                    findings.append(f"{path}: run {run.labels} must use command = plan")
                mapping = run.attributes.get("providers")
                mocks_only = isinstance(mapping, dict) and all(str(v) in ("aws", "aws.us_east_1") for v in mapping.values())
                if mapping is not None and not mocks_only:
                    findings.append(f"{path}: run {run.labels} maps a provider to something other than a mock")
    return findings


# ---------------------------------------------------------------------- compute, database, network


def rule_compute(tree: Tree) -> list[str]:
    findings = []
    services = tree.resource(COMPUTE, "aws_ecs_service")
    if not services:
        findings.append("modules/compute defines no ECS service")
    for path, service in services:
        if service.attributes.get("enable_execute_command") is not False:
            findings.append(f"{path}: ECS Exec stays disabled (enable_execute_command = false)")
        networks = _nested(service, "network_configuration")
        if not networks or any(n.attributes.get("assign_public_ip") is not False for n in networks):
            findings.append(f"{path}: ECS tasks never receive a public IP (assign_public_ip = false)")
        breakers = _nested(service, "deployment_circuit_breaker")
        if not breakers or any(b.attributes.get("rollback") is not True for b in breakers):
            findings.append(f"{path}: the deployment circuit breaker rolls back")
    for path, cluster in tree.resource(COMPUTE, "aws_ecs_cluster"):
        if _nested(cluster, "configuration", "execute_command_configuration"):
            findings.append(f"{path}: the cluster configures ECS Exec")
    definitions = tree.resource(COMPUTE, "aws_ecs_task_definition")
    for path, definition in definitions:
        if definition.attributes.get("skip_destroy") is not True:
            findings.append(f"{path}: every task definition is skip_destroy, so a rollout never deregisters the revision a rollback needs")
    for path in tree.under(TF, ".tf"):
        if re.search(r'image\s*=\s*"[^"]*:(latest|[A-Za-z0-9._-]+)"', tree.text(path)) or ":latest" in tree.text(path):
            findings.append(f"{path}: images are referenced by digest, never by tag")
    local = tree.locals(COMPUTE)
    if local.get("image") != "var.image":
        findings.append("modules/compute: local.image must be the verified release reference, var.image")
    image_rules = [
        v.raw_attributes.get("condition", "")
        for _, var in tree.blocks(COMPUTE, "variable", "image") for v in var.children("validation")
    ]
    if not any("@sha256:[0-9a-f]{64}$" in c for c in image_rules):
        findings.append("modules/compute: image must be validated as a full <repository>@sha256:<64 hex> reference")
    if not any('startswith(var.image, "${var.approved_image_repository_url}@sha256:")' in c for c in image_rules):
        findings.append("modules/compute: image must be validated against the approved release repository")
    main = tree.text(f"{COMPUTE}/main.tf")
    hardening = {
        r"readonlyRootFilesystem\s*=\s*true": "a read-only root filesystem",
        r"privileged\s*=\s*false": "an unprivileged container",
        r'user\s*=\s*"10001:10001"': "a numeric non-root user",
        r'drop\s*=\s*\["ALL"\]': "every capability dropped",
        r'network_mode\s*=\s*"awsvpc"': "awsvpc networking",
        r'requires_compatibilities\s*=\s*\["FARGATE"\]': "Fargate only",
    }
    for pattern, property_ in hardening.items():
        if not re.search(pattern, main):
            findings.append(f"modules/compute: every task definition has {property_}")
    if re.search(r"\badd\s*=|\bvolume\s*\{|mountPoints|pid_mode|ipc_mode", main):
        findings.append("modules/compute: no added capability, volume, mount or shared host namespace")
    for path, definition in definitions + services:
        conditions = [p.raw_attributes.get("condition", "") for p in _nested(definition, "lifecycle", "precondition")]
        if "var.runtime_contract_reviewed" not in conditions:
            findings.append(f"{path}: {definition.labels} must refuse to plan until runtime_contract_reviewed")
    tasks = local.get("tasks") if isinstance(local.get("tasks"), dict) else {}

    def secret_names(task: str) -> set[str]:
        secrets = tasks.get(task, {}).get("secrets") if isinstance(tasks.get(task), dict) else None
        if isinstance(secrets, Call) and secrets.name == "tomap" and secrets.args and isinstance(secrets.args[0], dict):
            return set(secrets.args[0])
        return {"<unreadable>"}

    expectations = {
        "web_api": {"FIRMBATCH_DATABASE_URL"},
        "identity_broker": {"FIRMBATCH_AUTHENTICATOR_DATABASE_URL", "FIRMBATCH_COGNITO_CLIENT_SECRET"},
        "migrate": {"FIRMBATCH_MIGRATION_DATABASE_URL"},
        "bootstrap": {"FIRMBATCH_RDS_MASTER_SECRET"},
        "identity_binding": {"FIRMBATCH_IDENTITY_BINDING_DATABASE_URL"},
    }
    for task, expected in expectations.items():
        if secret_names(task) != expected:
            findings.append(f"modules/compute: the {task} container must receive exactly {sorted(expected)}")
    return findings


def rule_database(tree: Tree) -> list[str]:
    findings = []
    database = f"{TF}/modules/database"
    instances = tree.resource(TF, "aws_db_instance")
    if len(instances) != 1:
        findings.append("exactly one RDS instance is defined")
    required = {
        "publicly_accessible": False, "storage_encrypted": True, "deletion_protection": True,
        "skip_final_snapshot": False, "manage_master_user_password": True, "multi_az": False,
        "engine": "postgres", "auto_minor_version_upgrade": False,
    }
    for path, instance in instances:
        for name, value in required.items():
            if instance.attributes.get(name) != value:
                findings.append(f"{path}: aws_db_instance must set {name} = {json.dumps(value)}")
        retention = instance.raw_attributes.get("backup_retention_period")
        if retention != "local.backup_retention_days" or tree.locals(database).get("backup_retention_days") != 7:
            findings.append(f"{path}: backups are retained for seven days")
        if "final_snapshot_identifier" not in instance.attributes:
            findings.append(f"{path}: a final snapshot identifier is required")
    parameters = [
        p for _, group in tree.resource(database, "aws_db_parameter_group") for p in group.children("parameter")
    ]
    if not any(p.attributes.get("name") == "rds.force_ssl" and p.attributes.get("value") == "1" for p in parameters):
        findings.append("modules/database: the parameter group must set rds.force_ssl = 1")
    if not any(
        "^16\\\\.[0-9]+$" in v.raw_attributes.get("condition", "")
        for _, var in tree.blocks(database, "variable", "engine_version") for v in var.children("validation")
    ):
        findings.append("modules/database: engine_version must be validated as an explicit 16.x minor")
    return findings


def rule_network_ingress(tree: Tree) -> list[str]:
    findings = []
    for path, group in tree.resource(TF, "aws_security_group") + tree.resource(TF, "aws_default_security_group"):
        if group.children("ingress") or group.children("egress"):
            findings.append(f"{path}: inline security-group rules are not used; every rule is its own reviewed resource")
    for path, rule in tree.resource(TF, "aws_vpc_security_group_ingress_rule"):
        for attribute in ("cidr_ipv4", "cidr_ipv6"):
            if attribute not in rule.attributes:
                continue
            value = rule.raw_attributes[attribute]
            if value in ('"0.0.0.0/0"', '"::/0"'):
                findings.append(f"{path}: {rule.labels[1]} admits the whole internet")
            elif not (path == f"{TF}/modules/edge/main.tf" and rule.labels[1] == "reviewer" and "each.value.cidr" in value):
                findings.append(f"{path}: ingress from a CIDR comes only from the validated reviewer allow-list")
    for path, subnet in tree.resource(TF, "aws_subnet"):
        if subnet.attributes.get("map_public_ip_on_launch") is not False:
            findings.append(f"{path}: subnets never map public IPs on launch")
    for path, balancer in tree.resource(f"{TF}/modules/edge", "aws_lb"):
        if balancer.attributes.get("internal") is not False or balancer.attributes.get("drop_invalid_header_fields") is not True:
            findings.append(f"{path}: the ALB is internet-facing and drops invalid header fields")
        if balancer.children("access_logs"):
            findings.append(f"{path}: ALB access logs stay disabled for M3.3")
    for path, listener in tree.resource(f"{TF}/modules/edge", "aws_lb_listener"):
        if listener.attributes.get("port") == 80:
            actions = listener.children("default_action")
            if len(actions) != 1 or actions[0].attributes.get("type") != "redirect":
                findings.append(f"{path}: port 80 does nothing but redirect to HTTPS")
    routes = {block.labels[1]: block for _, block in tree.resource(f"{TF}/modules/edge", "aws_lb_listener_rule")}
    expected_routes = {
        "identity_broker": ('aws_lb_target_group.service["identity_broker"].arn', "/auth/*"),
        "web_api": ('aws_lb_target_group.service["web_api"].arn', "/v1/*"),
        "web_api_default": ('aws_lb_target_group.service["web_api"].arn', None),
    }
    for name, (target, path_pattern) in expected_routes.items():
        rule = routes.get(name)
        actions = rule.children("action") if rule else []
        paths = [p.attributes.get("values") for c in (rule.children("condition") if rule else []) for p in c.children("path_pattern")]
        if len(actions) != 1 or actions[0].raw_attributes.get("target_group_arn") != target:
            findings.append(f"modules/edge: listener rule {name} must forward to {target}")
        if path_pattern and paths != [(path_pattern,)]:
            findings.append(f"modules/edge: listener rule {name} must match exactly {path_pattern}")
    reviewer_variable = tree.blocks(f"{TF}/modules/edge", "variable", "reviewer_cidrs")
    if len(reviewer_variable) != 1 or len(reviewer_variable[0][1].children("validation")) < 8:
        findings.append("modules/edge: reviewer_cidrs must carry the structural validations")
    return findings


def rule_identity(tree: Tree) -> list[str]:
    findings = []
    identity = f"{TF}/modules/identity"
    pools = tree.resource(identity, "aws_cognito_user_pool")
    for path, pool in pools:
        if pool.attributes.get("mfa_configuration") != "ON":
            findings.append(f"{path}: MFA is required")
        if not any(c.attributes.get("allow_admin_create_user_only") is True for c in pool.children("admin_create_user_config")):
            findings.append(f"{path}: the pool is invite-only")
        if not any(c.attributes.get("enabled") is True for c in pool.children("software_token_mfa_configuration")):
            findings.append(f"{path}: TOTP is enabled")
    clients = tree.resource(identity, "aws_cognito_user_pool_client")
    if len(pools) != 1 or len(clients) != 1:
        findings.append("modules/identity: one user pool and one app client")
    for path, client in clients:
        if client.attributes.get("allowed_oauth_flows") != ("code",):
            findings.append(f"{path}: the authorization-code grant only")
        if client.attributes.get("allowed_oauth_scopes") != ("openid", "email"):
            findings.append(f"{path}: scopes openid and email only")
        if client.attributes.get("generate_secret") is not True:
            findings.append(f"{path}: a confidential client")
        for name in ("callback_urls", "logout_urls"):
            if "*" in client.raw_attributes.get(name, "*"):
                findings.append(f"{path}: {name} are exact")
    for path, domain in tree.resource(identity, "aws_cognito_user_pool_domain"):
        if domain.attributes.get("managed_login_version") != 2:
            findings.append(f"{path}: Managed Login v2")
    for path, certificate in tree.resource(identity, "aws_acm_certificate"):
        if certificate.raw_attributes.get("provider") != "aws.us_east_1":
            findings.append(f"{path}: the Cognito custom-domain certificate is issued in us-east-1")
    associations = tree.resource(identity, "aws_wafv2_web_acl_association")
    if not associations or not all("aws_cognito_user_pool." in a.raw_attributes.get("resource_arn", "") for _, a in associations):
        findings.append("modules/identity: the WAF is associated with the Cognito user pool")
    return findings


# ---------------------------------------------------------------------- delivery identities and plans


def rule_delivery_trust(tree: Tree) -> list[str]:
    """Every GitHub delivery identity lives in the human-applied bootstrap root, trusts exactly its
    own environment, and holds only what its part of the delivery contract needs."""
    findings = delivery_identity_adoption(tree)
    local = tree.locals(BOOTSTRAP)
    trust = str(local.get("trust_policy", ""))
    if '"${local.oidc_host}:aud" = "sts.amazonaws.com"' not in trust:
        findings.append("bootstrap: the OIDC trust requires audience sts.amazonaws.com exactly")
    if '"${local.oidc_host}:sub" = "repo:${local.github_repository}:environment:${environment}"' not in trust:
        findings.append("bootstrap: the OIDC trust names the exact repository and environment")
    if "StringLike" in trust or "ForAnyValue" in trust or re.search(r":sub\"\s*=\s*\"[^\"]*\*", trust):
        findings.append("bootstrap: the OIDC subject is never a wildcard")
    named = tuple(local.get(name) for name in ("github_repository", "plan_environment", "apply_environment", "publish_environment"))
    if named != (GITHUB_REPOSITORY, "${var.environment}-plan", "${var.environment}-apply", "artifact-publish"):
        findings.append(
            "bootstrap: the trust names chamsrut/firmbatch and the staging-plan, staging-apply and artifact-publish environments exactly"
        )
    environment_rules = " ".join(
        v.raw_attributes.get("condition", "")
        for _, var in tree.blocks(BOOTSTRAP, "variable", "environment") for v in var.children("validation")
    )
    if 'var.environment == "staging"' not in environment_rules:
        findings.append("bootstrap: the delivery identities serve the staging environment only")

    roles = {block.labels[1]: (path, block) for path, block in tree.resource(BOOTSTRAP, "aws_iam_role")}
    if set(roles) != {"github_plan", "github_apply", "artifact_publish"}:
        return findings + ["bootstrap: exactly the distinct github_plan, github_apply and artifact_publish roles"]
    expected_trust = {
        "github_plan": "local.trust_policy[local.plan_environment]",
        "github_apply": "local.trust_policy[local.apply_environment]",
        "artifact_publish": "local.trust_policy[local.publish_environment]",
    }
    for name, raw in expected_trust.items():
        if roles[name][1].raw_attributes.get("assume_role_policy") != raw:
            findings.append(f"{roles[name][0]}: the {name} role is assumable only through its own environment")
    boundaries = {
        "github_plan": "aws_iam_policy.plan_boundary.arn",
        "github_apply": "aws_iam_policy.apply_boundary.arn",
        "artifact_publish": "aws_iam_policy.artifact_publish_boundary.arn",
    }
    for name, boundary in boundaries.items():
        if roles[name][1].raw_attributes.get("permissions_boundary") != boundary:
            findings.append(f"{roles[name][0]}: the {name} role's permissions boundary is {boundary or 'none'}")
    # The plan boundary: its denies present, its ceiling enumerated, and that ceiling admitting every action
    # the plan role's own policy grants -- so it constrains a side door without breaking planning.
    plan_boundary = [
        s for _, b in tree.resource(BOOTSTRAP, "aws_iam_policy", "plan_boundary") for s in _statements(b.attributes.get("policy"))
    ]
    plan_boundary_sids = _sids(plan_boundary)
    for required in PLAN_BOUNDARY_DENIES:
        if plan_boundary_sids.get(required, {}).get("Effect") != "Deny":
            findings.append(f"bootstrap: the plan permissions boundary must include the {required} deny")
    plan_ceiling = [a for s in plan_boundary if s.get("Effect") == "Allow" for a in _actions(s)]
    if not plan_ceiling or any(a == "*" or a.endswith(":*") for a in plan_ceiling) or any(
        "NotAction" in s for s in plan_boundary if s.get("Effect") == "Allow"
    ):
        findings.append("bootstrap: the plan boundary's ceiling enumerates the plan role's actions; no wildcard service or NotAction")
    plan_identity = [
        s for _, p in tree.resource(BOOTSTRAP, "aws_iam_role_policy", "github_plan") for s in _statements(p.attributes.get("policy"))
    ] + [s for s in local.get("state_statements", ()) if isinstance(s, dict)]
    uncovered = sorted({
        a for s in plan_identity if s.get("Effect") == "Allow" for a in _actions(s)
        if not any(_wildcard(pattern, a, ignore_case=True) for pattern in plan_ceiling)
    })
    if uncovered:
        findings.append(
            f"bootstrap: the plan boundary's ceiling does not admit the plan role's own actions {uncovered}; planning would break"
        )
    for path, block in tree.resource(TF, "aws_iam_role"):
        federated = "token.actions.githubusercontent.com" in block.raw_attributes.get("assume_role_policy", "")
        if not path.startswith(f"{BOOTSTRAP}/") and (block.labels[1] in expected_trust or federated):
            findings.append(f"{path}: every GitHub delivery identity lives in the human-applied bootstrap root")
    providers = tree.resource(TF, "aws_iam_openid_connect_provider")
    if len(providers) != 1 or not providers[0][0].startswith(f"{BOOTSTRAP}/"):
        findings.append("the account's one GitHub OIDC provider lives in the human-applied bootstrap root")
    for _, provider in providers:
        if provider.attributes.get("client_id_list") != ("sts.amazonaws.com",):
            findings.append("the OIDC provider's only audience is sts.amazonaws.com")

    policies = {block.labels[1]: block for _, block in tree.resource(BOOTSTRAP, "aws_iam_role_policy")}

    def allowed(policy_name: str) -> list[dict]:
        policy = policies.get(policy_name, hcl.Block("", [])).attributes.get("policy")
        return [s for s in _statements(policy) if s.get("Effect") == "Allow"]

    plan_allow = allowed("github_plan")
    apply_allow = allowed("github_apply")
    shared = [s for s in local.get("state_statements", ()) if isinstance(s, dict) and s.get("Effect") == "Allow"]
    if not plan_allow or not apply_allow:
        findings.append("bootstrap: the plan and apply role policies must be readable literal statements")
    history = {
        "s3:GetObjectVersion", "s3:ListBucketVersions", "s3:BypassGovernanceRetention",
        "s3:PutObjectRetention", "s3:PutObjectLegalHold", "s3:DeleteObjectVersion",
    }
    for statement in plan_allow + shared:
        for action in _actions(statement):
            verb = action.split(":", 1)[-1]
            secret_value = action.lower().startswith("secretsmanager:") and ("secretvalue" in verb.lower() or "*" in verb)
            if action in history or action.startswith("iam:Pass") or action == "*" or verb == "*" or secret_value:
                findings.append(f"bootstrap: the plan role may not {action}")
            elif not (verb.startswith(("Describe", "Get", "List", "View")) or action in PLAN_ROLE_WRITES):
                findings.append(f"bootstrap: the plan role is read-oriented; {action} is not")
            writes_elsewhere = statement.get("Resource") not in ("local.environment_plans_arn", "local.lock_object_arn")
            if action in ("s3:PutObject", "s3:DeleteObject") and writes_elsewhere:
                sid = statement.get("Sid")
                findings.append(f"bootstrap: the plan role writes only new saved plans and the state lockfile, not via {sid}")
    for statement in apply_allow:
        for action in _actions(statement):
            if action in history - {"s3:GetObjectVersion"}:
                findings.append(f"bootstrap: the apply role may not {action}")
            readable_versions = ("local.environment_plans_arn", "local.release_manifest_objects_arn")
            if action == "s3:GetObjectVersion" and statement.get("Resource") not in readable_versions:
                findings.append("bootstrap: the apply role reads plan versions under the plan prefix, and release-record versions, only")
            service, _, verb = action.partition(":")
            contract_resources = APPLY_ROLE_CONTRACT_GRANTS.get(action)
            if contract_resources is not None:
                if statement.get("Resource") not in contract_resources:
                    findings.append(f"bootstrap: the apply role holds {action} only on {' or '.join(contract_resources)}")
                condition = statement.get("Condition") if isinstance(statement.get("Condition"), dict) else {}
                passed_to = (condition.get("StringEquals") or {}).get("iam:PassedToService")
                if action == "iam:PassRole" and passed_to != "ecs-tasks.amazonaws.com":
                    findings.append("bootstrap: the apply role passes the workload roles to ecs-tasks.amazonaws.com only")
                if action in ("ecs:CreateService", "ecs:UpdateService"):
                    family = str(statement.get("Resource", "")).replace("local.service_arns.", "local.service_task_definition_arns.")
                    if (
                        (condition.get("ArnLikeIfExists") or {}).get("ecs:task-definition") != family
                        or (condition.get("StringEqualsIfExists") or {}).get("ecs:enable-execute-command") != "false"
                        or (condition.get("ArnEquals") or {}).get("ecs:cluster") != "local.cluster_arn"
                    ):
                        findings.append(f"bootstrap: {action} on each service requires its own family, the one cluster and no ECS Exec")
            elif service == "iam" and not verb.startswith(("Get", "List")):
                findings.append(f"bootstrap: IAM changes are human-applied; the apply role may not {action}")
            if action in APPLY_ROLE_NEVER or verb == "*" and service in ("iam", "kms", "secretsmanager", "ecs", "ecr", "budgets"):
                findings.append(
                    f"bootstrap: {action} is a trust anchor, a secret value, a one-off task, a deregistration or image publication; "
                    "the apply role may not hold it"
                )
    plan_policy = policies.get("github_plan", hcl.Block("", [])).attributes.get("policy")
    plan_denied = {a for s in _statements(plan_policy) if s.get("Effect") == "Deny" for a in _actions(s)}
    if not set(ECR_PUSH_ACTIONS) | {"ecr:GetAuthorizationToken", "ecr:BatchDeleteImage", "ecr:PutImageTagMutability"} <= plan_denied:
        findings.append("bootstrap: the plan role is denied every image push, re-tag and deletion outright")

    boundary = [s for _, b in tree.resource(BOOTSTRAP, "aws_iam_policy", "apply_boundary") for s in _statements(b.attributes.get("policy"))]
    sids = _sids(boundary)
    for required in APPLY_BOUNDARY_DENIES:
        if sids.get(required, {}).get("Effect") != "Deny":
            findings.append(f"bootstrap: the apply permissions boundary must include the {required} deny")
    if "DenyEveryIamChange" in sids:
        findings.append("bootstrap: DenyEveryIamChange -- a NotAction deny of everything but IAM reads -- denied every non-IAM operation; "
                        "IAM is kept out of the boundary by its ceiling instead")
    for statement in boundary:
        if statement.get("Effect") != "Allow":
            continue
        actions = _actions(statement)
        for action in actions:
            if action == "*" or action.lower().startswith("iam:") and action not in IAM_READS | {"iam:PassRole"}:
                findings.append(
                    f"bootstrap: the apply boundary's ceiling admits {action}; only exact IAM reads and iam:PassRole are within it"
                )
        if "iam:PassRole" in actions:
            condition = statement.get("Condition") if isinstance(statement.get("Condition"), dict) else {}
            if (
                actions != ["iam:PassRole"] or statement.get("Resource") != "local.workload_role_arns"
                or (condition.get("StringEquals") or {}).get("iam:PassedToService") != "ecs-tasks.amazonaws.com"
            ):
                findings.append(
                    "bootstrap: the apply boundary admits iam:PassRole only on the ten workload roles, to ecs-tasks.amazonaws.com"
                )
        if "NotAction" in statement:
            findings.append("bootstrap: the apply boundary's ceiling never uses NotAction")
    if sids.get("DenyPassingAnyRoleButThePreCreatedWorkloadRoles", {}).get("NotResource") != "local.workload_role_arns":
        findings.append("bootstrap: the apply boundary confines iam:PassRole to the pre-created workload roles")
    pass_to = sids.get("DenyPassingRolesToAnythingButEcsTasks", {}).get("Condition")
    if not isinstance(pass_to, dict) or (pass_to.get("StringNotEquals") or {}).get("iam:PassedToService") != "ecs-tasks.amazonaws.com":
        findings.append("bootstrap: the apply boundary confines iam:PassRole to ecs-tasks.amazonaws.com")
    registry_denied = set(_actions(sids.get("DenyImagePublicationAndRegistryChanges", {})))
    if not set(ECR_PUSH_ACTIONS) | {"ecr:BatchDeleteImage", "ecr:PutImageTagMutability"} <= registry_denied:
        findings.append("bootstrap: the apply boundary denies every image push, re-tag and deletion")
    if sids.get("DenyServiceChangesOutsideTheTwoServices", {}).get("NotResource") != "local.service_arn_list":
        findings.append("bootstrap: the apply boundary confines service changes to the two services")
    deregistration = set(_actions(sids.get("DenyTaskDefinitionDeregistrationAndDeletion", {})))
    if not {"ecs:DeregisterTaskDefinition", "ecs:DeleteTaskDefinitions"} <= deregistration:
        findings.append("bootstrap: the apply boundary denies deregistering or deleting any task-definition revision")
    family_denies = (("DenyTheWebApiServiceAnyOtherFamily", "web_api"), ("DenyTheIdentityBrokerServiceAnyOtherFamily", "identity_broker"))
    for sid, service in family_denies:
        condition = sids.get(sid, {}).get("Condition") if isinstance(sids.get(sid, {}).get("Condition"), dict) else {}
        if (
            sids.get(sid, {}).get("Resource") != f"local.service_arns.{service}"
            or (condition.get("Null") or {}).get("ecs:task-definition") != "false"
            or (condition.get("ArnNotLike") or {}).get("ecs:task-definition") != f"local.service_task_definition_arns.{service}"
        ):
            findings.append(f"bootstrap: the apply boundary refuses any task definition but its own family on the {service} service")
    exec_condition = sids.get("DenyEcsExecOnAnyService", {}).get("Condition")
    if not isinstance(exec_condition, dict) or (exec_condition.get("StringNotEquals") or {}).get("ecs:enable-execute-command") != "false":
        findings.append("bootstrap: the apply boundary refuses ECS Exec on any service change")

    # artifact-publish: exact trust above; publication only here.
    publish_allow = [
        s for _, p in tree.resource(BOOTSTRAP, "aws_iam_role_policy", "artifact_publish") for s in _statements(p.attributes.get("policy"))
        if s.get("Effect") == "Allow"
    ]
    if not publish_allow:
        findings.append("bootstrap: the artifact-publish policy must be readable literal statements")
    for statement in publish_allow:
        for action in _actions(statement):
            if action not in PUBLISH_MAY:
                findings.append(f"bootstrap: artifact-publish may not {action}; it publishes and does nothing else")
            repository_scoped = statement.get("Resource") == "local.release_repository_arn"
            if action.startswith("ecr:") and action != "ecr:GetAuthorizationToken" and not repository_scoped:
                findings.append("bootstrap: artifact-publish reaches the release repository only")
            if action.startswith("s3:") and statement.get("Resource") != "local.release_objects_arn":
                findings.append("bootstrap: artifact-publish reads and writes release records only")
            if action.startswith("kms:"):
                condition = statement.get("Condition") if isinstance(statement.get("Condition"), dict) else {}
                if (condition.get("StringEquals") or {}).get("kms:ViaService") != "s3.${var.artifact_registry_region}.amazonaws.com":
                    findings.append(
                        "bootstrap: artifact-publish uses the release key through S3 in the declared registry region only; "
                        "ECR encrypts layers under its own grant"
                    )
    # The canonical registry is declared, never derived from this root's own account or region.
    declared_arn = (
        "arn:aws:ecr:${var.artifact_registry_region}:${var.artifact_registry_account_id}:repository/${var.release_repository_name}"
    )
    if local.get("release_repository_arn") != declared_arn:
        findings.append(
            "bootstrap: the release repository ARN is built from the declared artifact_registry_* variables, "
            "never this account or region"
        )
    policy_blocks = tree.resource(BOOTSTRAP, "aws_iam_role_policy") + tree.resource(BOOTSTRAP, "aws_iam_policy")
    via_release = [
        s for _, p in policy_blocks for s in _statements(p.attributes.get("policy")) if isinstance(s.get("Condition"), dict)
        for operator in s["Condition"].values() if isinstance(operator, dict) and "kms:ViaService" in operator
        if str(operator["kms:ViaService"]).startswith("s3.")
    ]
    if not via_release or any(s["Condition"] and "s3.${var.region}." in str(s["Condition"]) for s in via_release):
        findings.append("bootstrap: release records are decrypted through S3 in the declared artifact_registry_region only")
    registry_rules = " ".join(
        v.raw_attributes.get("condition", "")
        for name in ("artifact_registry_account_id", "artifact_registry_region")
        for _, var in tree.blocks(BOOTSTRAP, "variable", name) for v in var.children("validation")
    )
    for fragment in ("var.artifact_registry_account_id == var.expected_account_id", "var.artifact_registry_region == var.region"):
        if fragment not in registry_rules:
            findings.append(
                "bootstrap: a registry declared outside this root's account or region is refused, because this root creates the "
                f"publisher and release key beside it ({fragment})"
            )
    publish_boundary = _sids([
        s for _, b in tree.resource(BOOTSTRAP, "aws_iam_policy", "artifact_publish_boundary")
        for s in _statements(b.attributes.get("policy"))
    ])
    publish_denied = set(_actions(publish_boundary.get("DenyInfrastructureDeploymentRolesAndSecrets", {})))
    if not {"iam:*", "sts:AssumeRole", "ecs:*", "secretsmanager:*"} <= publish_denied:
        findings.append("bootstrap: the artifact-publish boundary denies every infrastructure, deployment, role and secret action")
    if publish_boundary.get("DenyImageDeletionRetaggingAndRegistryChanges", {}).get("Effect") != "Deny":
        findings.append("bootstrap: the artifact-publish boundary denies deletion, re-tagging and registry changes")

    script = tree.text("infra/delivery/delivery.py")
    block = re.search(r"HUMAN_APPLIED_TYPE_PREFIXES = \((.*?)\n\)", script, re.S)
    prefixes = set(re.findall(r'"([a-z0-9_]+)"', block.group(1))) if block else set()
    if not HUMAN_APPLIED_PREFIXES <= prefixes:
        findings.append(
            "infra/delivery/delivery.py HUMAN_APPLIED_TYPE_PREFIXES must cover IAM, KMS, Secrets Manager, "
            "ECR, S3 and budget actions"
        )
    blocking = sorted(t for t in PIPELINE_APPLIED_TYPES if any(t.startswith(p) for p in prefixes))
    if blocking:
        findings.append(f"infra/delivery/delivery.py HUMAN_APPLIED_TYPE_PREFIXES refuses the pipeline's own changes: {blocking}")
    return findings


# ---------------------------------------------------------------------- the delivery identities' whole policy graph

DELIVERY_ROLES = ("github_plan", "github_apply", "artifact_publish")
# The intended policy graph of the delivery identities, exactly: each identity has one inline policy and one
# permissions boundary, each a literal document in the bootstrap root. Anything else that could give a
# delivery identity a policy -- another inline policy, a managed-policy or exclusive attachment,
# managed_policy_arns or inline_policy on a role, a policy built by for_each or held in a local -- is refused,
# never evaluated on a guess, and names are never trusted alone: every admitted document is read in full.
DELIVERY_POLICY_GRAPH = {
    ("aws_iam_role_policy", "github_plan"): ("github_plan", "identity"),
    ("aws_iam_role_policy", "github_apply"): ("github_apply", "identity"),
    ("aws_iam_role_policy", "artifact_publish"): ("artifact_publish", "identity"),
    ("aws_iam_policy", "plan_boundary"): ("github_plan", "boundary"),
    ("aws_iam_policy", "apply_boundary"): ("github_apply", "boundary"),
    ("aws_iam_policy", "artifact_publish_boundary"): ("artifact_publish", "boundary"),
}
# Every resource type of the pinned provider that creates, attaches or pins an IAM policy for a role.
IAM_ROLE_POLICY_TYPES = (
    "aws_iam_role_policy", "aws_iam_policy", "aws_iam_role_policy_attachment", "aws_iam_policy_attachment",
    "aws_iam_role_policies_exclusive", "aws_iam_role_policy_attachments_exclusive",
)
_ROLE_REFERENCE = re.compile(r"aws_iam_role\.([a-z0-9_]+)(?:\[[^\]]+\])?\.(?:id|name)")
_DELIVERY_ROLE_TEXT = re.compile(r"github[-_]?(plan|apply)|artifact[-_]publish", re.I)
# What a delivery identity's own policy never grants, whatever its boundary: a secret value, a parameter
# (decryptable SecureString or not), or -- checked separately -- decryption beyond the three bootstrap keys.
DELIVERY_FORBIDDEN_ACTIONS = (
    "secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue",
    "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "ssm:GetParameterHistory",
)
_DELIVERY_KEYS = frozenset(BOOTSTRAP_BINDINGS[f"aws_kms_key.{key}.arn"] for key in ("state", "plans", "release"))
_OTHER_KEY = f"arn:aws:kms:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:key/00000000-0000-4000-8000-0000000000ff"
_PARAMETER = f"arn:aws:ssm:{SYNTHETIC_REGION}:{SYNTHETIC_ACCOUNT}:parameter/{SYNTHETIC_PREFIX}"
# Requests no delivery identity may make, evaluated through its identity policy and its boundary.
DELIVERY_NEVER = (
    _request("secretsmanager:GetSecretValue", _SECRET),
    _request("secretsmanager:BatchGetSecretValue", "*"),
    _request("ssm:GetParameter", f"{_PARAMETER}/database-url"),
    _request("ssm:GetParametersByPath", _PARAMETER),
    _request("kms:Decrypt", _OTHER_KEY),
    {**_request("kms:Decrypt", _OTHER_KEY), "context": _VIA_S3},
)
# A side door: any policy attached to the role beside its own. Each boundary alone must still refuse these.
SIDE_DOOR = {"Sid": "SideDoor", "Effect": "Allow", "Action": "*", "Resource": "*"}
BOUNDARY_SIDE_DOOR_PROBES = {
    "plan": (*DELIVERY_NEVER, _request("s3:GetObject", _PLAN_OBJECT), _request("s3:PutObject", _S3_STATE), _request("kms:Decrypt", _KEY)),
    "apply": DELIVERY_NEVER[:4],
    "artifact-publish": DELIVERY_NEVER[:4],
}


def _root_of(path: str) -> str:
    if path.startswith(f"{TF}/modules/"):
        return "/".join(path.split("/")[:4])
    return next((root for root in ROOTS.values() if path.startswith(f"{root}/")), posixpath.dirname(path))


# ---------------------------------------------------------------------- who may declare or adopt a delivery identity

# The only IAM roles outside the bootstrap root, by address and exact name expression: the workload roles. Any
# other role outside it, or one of these renamed or given a name_prefix, is a reviewed change to this list first.
NON_DELIVERY_ROLES = {
    (f"{TF}/modules/compute", "execution"): '"${var.name_prefix}-${each.value.family}-execution"',
    (f"{TF}/modules/compute", "task"): '"${var.name_prefix}-${each.value.family}-task"',
}
# Every GitHub delivery identity's name ends in one of these (bootstrap/main.tf). IAM role names are unique
# case-insensitively, so names are compared lowercased.
DELIVERY_ROLE_SUFFIXES = ("-github-plan", "-github-apply", "-artifact-publish")
# Text a root variable supplies at plan time: any string, whatever the variable's default.
_PLAN_TIME = "\x00"
_INTERPOLATION = re.compile(r"\$\{([^}]*)\}")
_MAX_NAME_CANDIDATES = 256


def _module_calls(tree: Tree, module_prefix: str) -> list[tuple[str, hcl.Block]]:
    """Every module block, in any root or module, whose source resolves to `module_prefix`."""
    calls = []
    for path, block in tree.blocks(TF, "module"):
        source = block.attributes.get("source")
        if isinstance(source, str) and posixpath.normpath(posixpath.join(posixpath.dirname(path), source)) == module_prefix:
            calls.append((_root_of(path), block))
    return calls


def _variable_candidates(tree: Tree, prefix: str, name: str, depth: int) -> list[str] | None:
    """What var.<name> can be at `prefix`: its default, and every value a module call supplies -- or, for a
    root variable, anything tfvars supplies."""
    candidates: list[str] = []
    defaults = [block.attributes["default"] for _, block in tree.blocks(prefix, "variable", name) if "default" in block.attributes]
    for default in defaults:
        resolved = _name_candidates(tree, prefix, default, None, depth + 1)
        if resolved is None:
            return None
        candidates += resolved
    if not prefix.startswith(f"{TF}/modules/"):
        return candidates + [_PLAN_TIME]
    calls = _module_calls(tree, prefix)
    for caller, block in calls:
        if name in block.attributes:
            resolved = _name_candidates(tree, caller, block.attributes[name], None, depth + 1)
            if resolved is None:
                return None
            candidates += resolved
        elif not defaults:
            return None
    return candidates if calls or defaults else candidates + [_PLAN_TIME]


def _name_candidates(tree: Tree, prefix: str, value, each: tuple | None, depth: int = 0) -> list[str] | None:
    """Every string a role's name or name_prefix can take at `prefix`, resolving literals, interpolation, locals,
    variables and the current for_each entry, with _PLAN_TIME for plan-time text. None when it cannot be read."""
    if depth > 8:
        return None
    if isinstance(value, hcl.Raw):
        text = "${" + str(value).strip() + "}"
    elif isinstance(value, str):
        text = str(value)
    else:
        return None
    if "%{" in text or "$${" in text:
        return None
    candidates = [""]
    position = 0
    for match in _INTERPOLATION.finditer(text):
        reference = match.group(1).strip()
        if reference.startswith("local."):
            local = _local_value(tree, prefix, reference)
            parts = None if local is None else _name_candidates(tree, prefix, local, each, depth + 1)
        elif re.fullmatch(r"var\.[a-z0-9_]+", reference):
            parts = _variable_candidates(tree, prefix, reference[4:], depth)
        elif each is not None and reference == "each.key":
            parts = [str(each[0])]
        elif each is not None and re.fullmatch(r"each\.value\.[a-z0-9_]+", reference) and isinstance(each[1], dict):
            field = each[1].get(reference.split(".")[2])
            parts = None if field is None else _name_candidates(tree, prefix, field, None, depth + 1)
        else:
            parts = None
        if parts is None:
            return None
        candidates = [c + text[position:match.start()] + p for c in candidates for p in parts]
        if len(candidates) > _MAX_NAME_CANDIDATES:
            return None
        position = match.end()
    return [c + text[position:] for c in candidates]


def _delivery_name_verdict(candidate: str) -> str:
    """'reserved' when the name or prefix ends in a delivery identity's suffix; 'unproven' when plan-time text
    before its literal tail could complete one; otherwise 'clear'."""
    lowered = candidate.lower()
    tail = lowered.rsplit(_PLAN_TIME, 1)[-1]
    if any(tail.endswith(suffix) for suffix in DELIVERY_ROLE_SUFFIXES):
        return "reserved"
    if _PLAN_TIME in lowered and any(suffix.endswith(tail) for suffix in DELIVERY_ROLE_SUFFIXES):
        return "unproven"
    return "clear"


def delivery_identity_adoption(tree: Tree) -> list[str]:
    """Only the bootstrap root declares or adopts a GitHub delivery identity. Every role outside it must be an
    allow-listed workload role, and its effective name and name_prefix -- not its resource label -- must be proven
    not to be a delivery identity's; what cannot be proven fails closed."""
    findings: list[str] = []
    for path, block in tree.resource(TF, "aws_iam_role"):
        if path.startswith(f"{BOOTSTRAP}/"):
            continue
        prefix, label = _root_of(path), block.labels[1]
        where = f"{path}: aws_iam_role.{label}"
        reviewed = NON_DELIVERY_ROLES.get((prefix, label))
        unproven = "cannot be proven not to be a delivery identity's; failing closed"
        if reviewed is None or block.raw_attributes.get("name") != reviewed or "name_prefix" in block.attributes:
            findings.append(
                f"{where} is not an allow-listed workload role with its reviewed name; only the bootstrap root declares delivery identities"
            )
        entries: list = [None]
        if "count" in block.attributes:
            findings.append(f"{where}: its count cannot be read, so its names {unproven}")
            continue
        if "for_each" in block.attributes:
            iterated = block.raw_attributes["for_each"]
            values = _local_value(tree, prefix, iterated) if iterated.startswith("local.") else None
            if not isinstance(values, dict) or not values:
                findings.append(f"{where}: its for_each cannot be read, so its names {unproven}")
                continue
            entries = list(values.items())
        for attribute in ("name", "name_prefix"):
            if attribute not in block.attributes:
                continue
            candidates: list[str] | None = []
            for entry in entries:
                resolved = _name_candidates(tree, prefix, block.attributes[attribute], entry)
                if resolved is None:
                    candidates = None
                    break
                candidates += resolved
            if candidates is None or len(candidates) > _MAX_NAME_CANDIDATES:
                findings.append(f"{where}: its effective {attribute} cannot be resolved, so it {unproven}")
                continue
            verdicts = {_delivery_name_verdict(candidate) for candidate in candidates}
            if "reserved" in verdicts:
                findings.append(
                    f"{where}: its effective {attribute} is a GitHub delivery identity's "
                    "(-github-plan, -github-apply or -artifact-publish); only the bootstrap root declares or adopts one"
                )
            elif "unproven" in verdicts:
                findings.append(
                    f"{where}: plan-time text in its effective {attribute} could complete a delivery identity's name; failing closed"
                )
    return findings


def delivery_policy_graph(tree: Tree) -> list[str]:
    """Every resource anywhere that could give a delivery identity a policy, against the intended graph."""
    findings: list[str] = []
    for path, block in tree.blocks(TF, "resource"):
        kind, name = (block.labels + ["", ""])[:2]
        where = f"{path}: {kind}.{name}"
        if kind == "aws_iam_role":
            if "managed_policy_arns" in block.attributes or block.children("inline_policy"):
                findings.append(f"{where} declares managed_policy_arns or inline_policy, which these checks would not read; failing closed")
            dynamic = "for_each" in block.attributes or "count" in block.attributes
            if path.startswith(f"{BOOTSTRAP}/") and name in DELIVERY_ROLES and dynamic:
                findings.append(f"{where} is a delivery identity created with for_each or count; failing closed")
        if kind not in IAM_ROLE_POLICY_TYPES:
            continue
        if path.startswith(f"{BOOTSTRAP}/"):
            intended = DELIVERY_POLICY_GRAPH.get((kind, name))
            if intended is None:
                findings.append(f"{where} is outside the delivery identities' intended policy graph; failing closed")
                continue
            if "for_each" in block.attributes or "count" in block.attributes:
                findings.append(f"{where} is created with for_each or count; a delivery identity's policy is one literal document")
            policy = block.attributes.get("policy")
            if not (isinstance(policy, Call) and policy.name == "jsonencode" and policy.args and isinstance(policy.args[0], dict)):
                findings.append(
                    f"{where} is not a literal jsonencode document; a delivery identity's policy is never a local, each.value or reference"
                )
            if intended[1] == "identity" and block.raw_attributes.get("role") != f"aws_iam_role.{intended[0]}.id":
                findings.append(f"{where} attaches to {block.raw_attributes.get('role')!r}, not exactly aws_iam_role.{intended[0]}.id")
            continue
        if kind == "aws_iam_policy":
            continue  # a managed policy outside the bootstrap root attaches to nothing by itself
        # Outside the bootstrap root a policy may attach only to an allow-listed workload role declared beside it,
        # named by reference -- never by a name, a variable or a role whose effective name is unproven.
        root = _root_of(path)
        listed = {label for (listed_root, label) in NON_DELIVERY_ROLES if listed_root == root}
        declared = {b.labels[1] for _, b in tree.resource(root, "aws_iam_role")} & listed
        targets = [block.raw_attributes[a] for a in ("role", "roles", "role_name") if a in block.raw_attributes]
        items = [item.strip() for target in targets for item in target.strip().strip("[]").split(",") if item.strip()]
        proven = bool(items) and all(
            (match := _ROLE_REFERENCE.fullmatch(item)) is not None and match.group(1) in declared for item in items
        )
        if not proven or any(_DELIVERY_ROLE_TEXT.search(target) for target in targets):
            findings.append(
                f"{where} attaches a policy to a role not proven to be an allow-listed workload role declared beside it, "
                "possibly a delivery identity; failing closed"
            )
    return findings


def delivery_grant_findings(role: str, statements: list[dict]) -> list[str]:
    """What a delivery identity's own policy grants, judged statement by statement in full."""
    findings = []
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        where = f"bootstrap: the {role} role's statement {statement.get('Sid', '<no Sid>')}"
        actions = [str(a) for a in _listify(statement.get("Action", []))]
        if "*" in actions:
            findings.append(f"{where} grants every action")
        for forbidden in DELIVERY_FORBIDDEN_ACTIONS:
            if any(_wildcard(action, forbidden, ignore_case=True) for action in actions):
                findings.append(f"{where} grants {forbidden}")
        if any(_wildcard(action, "kms:Decrypt", ignore_case=True) for action in actions):
            resources = [str(r) for r in _listify(statement.get("Resource", "*"))]
            if "NotResource" in statement or any(resource not in _DELIVERY_KEYS for resource in resources):
                findings.append(f"{where} grants kms:Decrypt beyond the state, plan and release keys")
    return findings


def rule_policy_semantics(tree: Tree) -> list[str]:
    """The delivery identities' whole policy graph is exactly the intended one; each identity's policy and
    boundary decide representative requests correctly, grant nothing forbidden, and the boundary alone
    refuses what a side door could grant; and no NotAction or NotResource statement anywhere denies or
    allows everything but a short allow-list."""
    findings = delivery_policy_graph(tree)
    evaluations = (
        ("apply", ("aws_iam_role_policy", "github_apply"), ("aws_iam_policy", "apply_boundary"), APPLY_REQUIRED, APPLY_PROHIBITED),
        (
            "artifact-publish", ("aws_iam_role_policy", "artifact_publish"), ("aws_iam_policy", "artifact_publish_boundary"),
            PUBLISH_REQUIRED, PUBLISH_PROHIBITED,
        ),
        ("plan", ("aws_iam_role_policy", "github_plan"), ("aws_iam_policy", "plan_boundary"), PLAN_REQUIRED, PLAN_PROHIBITED),
    )
    for role, identity_ref, boundary_ref, required, prohibited in evaluations:
        try:
            identity = policy_statements(tree, BOOTSTRAP, *identity_ref, BOOTSTRAP_BINDINGS)
            boundary = policy_statements(tree, BOOTSTRAP, *boundary_ref, BOOTSTRAP_BINDINGS)
            findings.extend(delivery_grant_findings(role, identity))
            for request in required:
                if not effective(identity, boundary, request):
                    findings.append(
                        f"bootstrap: the {role} role cannot {request['action']} on {request['resource']}, which its delivery work needs"
                    )
            for request in (*prohibited, *DELIVERY_NEVER):
                if effective(identity, boundary, request):
                    findings.append(f"bootstrap: the {role} role can {request['action']} on {request['resource']}, which it must never do")
            # The boundary alone, against a side door alone: the identity policy's own denies are not counted, so
            # the boundary still refuses if a later change removed them.
            for request in BOUNDARY_SIDE_DOOR_PROBES[role]:
                if effective([SIDE_DOOR], boundary, request):
                    findings.append(
                        f"bootstrap: the {role} boundary does not stop {request['action']} on {request['resource']}, "
                        "which a side-door policy attached to the role could grant"
                    )
        except PolicyUnresolved as exc:
            findings.append(f"bootstrap: the {role} policies could not be evaluated ({exc}); failing closed")
    for prefix in [*ROOTS.values(), *(f"{TF}/modules/{m}" for m in MODULES)]:
        for path, block in tree.blocks(prefix, "resource"):
            kind, name = (block.labels + ["", ""])[:2]
            if "policy" not in block.attributes or kind in NON_IAM_POLICY_TYPES:
                continue
            if kind not in POLICY_RESOURCE_TYPES:
                findings.append(f"{path}: {kind}.{name} carries a policy of a type the evaluator does not read; failing closed")
                continue
            try:
                bindings = BOOTSTRAP_BINDINGS if prefix == BOOTSTRAP else None
                statements = [
                    _resolve(s, bindings)
                    for document in _policy_documents(tree, prefix, block) for s in _raw_policy_statements(tree, prefix, document)
                ]
                broad = broad_not_action_denies(statements)
            except PolicyUnresolved as exc:
                findings.append(f"{path}: {kind}.{name} could not be read for NotAction and NotResource semantics ({exc}); failing closed")
                continue
            for sid in broad:
                findings.append(
                    f"{path}: {kind}.{name} statement {sid} denies or allows everything except a short allow-list; "
                    "deny the intended service's actions instead"
                )
    return findings


def rule_saved_plans_and_state(tree: Tree) -> list[str]:
    findings = []
    buckets = {block.labels[1]: block for _, block in tree.resource(BOOTSTRAP, "aws_s3_bucket")}
    if set(buckets) != {"state", "plans"}:
        return ["the bootstrap root defines exactly the state bucket and the separate plans bucket"]
    plans_locked = buckets["plans"].attributes.get("object_lock_enabled") is True
    state_unlocked = buckets["state"].attributes.get("object_lock_enabled") is False
    if not plans_locked or not state_unlocked:
        findings.append("the plan bucket, and only the plan bucket, has Object Lock enabled")
    configurations = tree.resource(BOOTSTRAP, "aws_s3_bucket_object_lock_configuration")
    locks = [r for _, c in configurations for r in _nested(c, "rule", "default_retention")]
    lock = locks[0] if len(locks) == 1 else None
    if lock is None or lock.attributes.get("mode") != "GOVERNANCE" or lock.raw_attributes.get("days") != "var.plan_retention_days":
        findings.append("saved plans carry GOVERNANCE retention of var.plan_retention_days")
    if tree.locals(BOOTSTRAP).get("plan_object_prefix") != "plans/":
        findings.append("saved plans live under plans/")
    for path, lifecycle in tree.resource(TF, "aws_s3_bucket_lifecycle_configuration"):
        bucket = lifecycle.raw_attributes.get("bucket", "")
        rules = lifecycle.children("rule")
        if "aws_s3_bucket.state" in bucket:
            if any(r.children("expiration") for r in rules):
                findings.append(f"{path}: no lifecycle rule expires current state or its delete markers")
        elif "aws_s3_bucket.plans" in bucket:
            for rule in rules:
                filters = rule.children("filter")
                if len(filters) != 1 or filters[0].raw_attributes.get("prefix") != "local.plan_object_prefix":
                    findings.append(f"{path}: rule {rule.attributes.get('id')} must be confined to the plans/ prefix")
            expirations = [e for r in rules for e in r.children("expiration")]
            if not any(e.raw_attributes.get("days") == "var.plan_retention_days" for e in expirations):
                findings.append(f"{path}: current plan versions expire after the retention")
            noncurrent = [n for r in rules for n in r.children("noncurrent_version_expiration")]
            if not any(n.raw_attributes.get("noncurrent_days") == "var.plan_retention_days" for n in noncurrent):
                findings.append(f"{path}: noncurrent plan versions expire after the retention")
            if not any(e.attributes.get("expired_object_delete_marker") is True for e in expirations):
                findings.append(f"{path}: plan delete markers expire")
        elif "aws_s3_bucket.releases" in bucket:
            if any(r.children("expiration") or r.children("noncurrent_version_expiration") for r in rules):
                findings.append(f"{path}: no lifecycle rule expires a release record")
        else:
            findings.append(f"{path}: a lifecycle configuration on an unexpected bucket")
    statements = _sids([
        s for _, p in tree.resource(BOOTSTRAP, "aws_s3_bucket_policy", "plans") for s in _statements(p.attributes.get("policy"))
    ])
    overwrite = statements.get("DenyOverwriteByPipelineRoles", {})
    condition = overwrite.get("Condition", {}) if isinstance(overwrite.get("Condition"), dict) else {}
    requires_if_none_match = condition.get("Null", {}).get("s3:if-none-match") == "true"
    if overwrite.get("Effect") != "Deny" or overwrite.get("Action") != "s3:PutObject" or not requires_if_none_match:
        findings.append("the plan bucket policy must refuse any pipeline-role PutObject without If-None-Match")
    bypass = set(_actions(statements.get("DenyRetentionBypassByPipelineRoles", {})))
    for action in ("s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:DeleteObjectVersion", "s3:ListBucketVersions"):
        if action not in bypass:
            findings.append(f"the plan bucket policy must deny {action} to the pipeline roles")
    if "s3:GetObjectVersion" not in _actions(statements.get("DenyPlanReadsByPlanRole", {})):
        findings.append("the plan bucket policy must deny the plan role any saved-plan read")
    writers = statements.get("OnlyThePlanRoleCreatesSavedPlans", {})
    writer_condition = writers.get("Condition") if isinstance(writers.get("Condition"), dict) else {}
    if (
        writers.get("Effect") != "Deny" or writers.get("Principal") != "*" or writers.get("Action") != "s3:PutObject"
        or set(writer_condition) != {"ArnNotEquals"}
        or (writer_condition.get("ArnNotEquals") or {}).get("aws:PrincipalArn") != "local.github_plan_role_arn"
    ):
        findings.append(
            "the plan bucket policy must deny saved-plan writes to every principal but the exact plan role, other staging roles included"
        )
    return findings


# ---------------------------------------------------------------------- workflows


_SHA_PIN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
# `terraform [-chdir=DIR] <subcommand>` as a command, not the word inside a path or a flag.
_TERRAFORM_COMMAND = r"(?:^|[\s;|&(!])terraform\s+(?:-chdir=\S+\s+)?{}\b"
# Anything that builds, tags, pushes, deletes or logs in to a registry.
_IMAGE_COMMAND = r"\bdocker\b|\bbuildx\b|\bpodman\b|\bcrane\b|\bskopeo\b|ecr\s+put-image|ecr\s+batch-delete-image|get-login-password"
# `terraform show` output may only flow into the sanitized summary.
_SUMMARY_PIPE = re.compile(r"\|\s*python3\s+\S*delivery\.py\"?\s+plan-summary\b")


def _load_workflow(tree: Tree, path: str, findings: list[str]):
    if not tree.exists(path):
        findings.append(f"{path} is missing")
        return None
    try:
        document = yaml_subset.parse(tree.text(path))
    except yaml_subset.YamlError as exc:
        findings.append(f"{path}: outside the checked YAML subset ({exc}); failing closed")
        return None
    if not isinstance(document, dict) or not isinstance(document.get("jobs"), dict):
        findings.append(f"{path}: no jobs")
        return None
    return document


def workflow_triggers(document) -> set[str] | None:
    """The trigger names, however `on` is spelled -- a scalar, a list or a mapping -- or None."""
    triggers = document.get("on") if isinstance(document, dict) else None
    if isinstance(triggers, str) and triggers:
        return {triggers}
    if isinstance(triggers, list) and triggers and all(isinstance(t, str) and t for t in triggers):
        return set(triggers)
    if isinstance(triggers, dict) and triggers:
        return set(triggers)
    return None


def job_environment(job: dict) -> str | None:
    environment = job.get("environment")
    if environment is None:
        return None
    if isinstance(environment, str):
        return environment
    if isinstance(environment, dict) and isinstance(environment.get("name"), str):
        return environment["name"]
    return "<unreadable environment>"


def _permission_values(document: dict) -> list[tuple[str, object]]:
    found = [("top level", document.get("permissions"))] if "permissions" in document else []
    for name, job in (document.get("jobs") or {}).items():
        if isinstance(job, dict) and "permissions" in job:
            found.append((f"job {name}", job["permissions"]))
    return found


def _steps(job) -> list[dict]:
    return [step for step in job.get("steps", []) if isinstance(step, dict)] if isinstance(job, dict) else []


def rule_ci_workflow(tree: Tree) -> list[str]:
    findings: list[str] = []
    document = _load_workflow(tree, CI_WORKFLOW, findings)
    if document is None:
        return findings
    text = tree.text(CI_WORKFLOW)
    if document.get("permissions") != {"contents": "read"}:
        findings.append(f"{CI_WORKFLOW}: top-level permissions are contents: read")
    triggers = workflow_triggers(document)
    if triggers is None or "workflow_call" not in triggers:
        findings.append(f"{CI_WORKFLOW}: artifact-publish reuses this workflow as its required verification (workflow_call)")
    if triggers is None or "pull_request_target" in triggers:
        findings.append(f"{CI_WORKFLOW}: never triggered by pull_request_target")
    for where, value in _permission_values(document):
        if not isinstance(value, dict) or any(v not in ("read", "none") for v in value.values()):
            findings.append(f"{CI_WORKFLOW}: {where} holds only read permissions")
    if any(job_environment(job) for job in document["jobs"].values() if isinstance(job, dict)):
        findings.append(f"{CI_WORKFLOW}: static checks hold no environment")
    # ci.yml is the full required verification artifact-publish's gates reuse: a job or step that
    # continues on error, or runs only conditionally, would report success for a check that failed or
    # never ran.
    for name, job in document["jobs"].items():
        if not isinstance(job, dict):
            findings.append(f"{CI_WORKFLOW}: job {name} is unreadable; failing closed")
            continue
        if "continue-on-error" in job or any("continue-on-error" in step for step in _steps(job)):
            findings.append(f"{CI_WORKFLOW}: job {name} continues on error; a failed check must fail the verification")
        if "if" in job or any("if" in step for step in _steps(job)):
            findings.append(f"{CI_WORKFLOW}: job {name} runs a job or step conditionally; every check runs")
    if re.search(r"id-token|\$\{\{\s*secrets\.|aws-actions/", text):
        findings.append(f"{CI_WORKFLOW}: static checks hold no environment, OIDC token, secret or AWS credential")
    pinned = tree.text(f"{TF}/.terraform-version").strip()
    terraform_steps = [
        step for job in document["jobs"].values() for step in _steps(job)
        if str(step.get("uses", "")).startswith("hashicorp/setup-terraform@")
    ]
    if not terraform_steps or any(
        not isinstance(step.get("with"), dict)
        or step["with"].get("terraform_version") != pinned
        or step["with"].get("terraform_wrapper") != "false"
        or not _SHA_PIN.match(step.get("uses", ""))
        for step in terraform_steps
    ):
        findings.append(f"{CI_WORKFLOW}: setup-terraform is SHA-pinned, installs exactly {pinned} and disables the wrapper")
    container = document["jobs"].get("container")
    runs = " ".join(_runs(container)) if isinstance(container, dict) else ""
    if "docker build" not in runs:
        findings.append(f"{CI_WORKFLOW}: a container job builds the production image")
    if re.search(r"docker\s+(push|login)|ecr\s+get-login|buildx\s+.*--push", text):
        findings.append(f"{CI_WORKFLOW}: the container check never logs in to a registry or pushes")
    if "bash ./scripts/verify-repository.sh" not in text:
        findings.append(f"{CI_WORKFLOW}: CI still calls the one verification script")
    return findings


def _deployment_workflow(tree: Tree, path: str, environment: str, mode: str) -> list[str]:
    findings: list[str] = []
    document = _load_workflow(tree, path, findings)
    if document is None:
        return findings
    text = tree.text(path)
    if workflow_triggers(document) != {"workflow_dispatch"}:
        findings.append(f"{path}: triggered by workflow_dispatch only -- never by push, pull request, schedule or another workflow")
    if document.get("permissions") != {}:
        findings.append(f"{path}: top-level permissions are empty")
    if (document.get("defaults") or {}).get("run", {}).get("shell") != "bash":
        findings.append(f"{path}: every step runs under bash -eo pipefail (defaults.run.shell: bash), so a failed pipe fails the step")
    if "concurrency" not in document:
        findings.append(f"{path}: plan and apply never run concurrently")
    if "continue-on-error" in text:
        findings.append(f"{path}: no job or step continues on error")
    jobs = document["jobs"]
    preflight = jobs.get("preflight")
    if not isinstance(preflight, dict) or "environment" in preflight:
        findings.append(f"{path}: a preflight job that references no environment")
    elif not any(f"infra/delivery/delivery.py preflight --workflow {mode}" in r for r in _runs(preflight)):
        findings.append(f"{path}: the preflight job runs delivery.py preflight --workflow {mode}")
    allowed_permissions = WORKFLOW_JOB_PERMISSIONS[path]
    if set(jobs) != set(allowed_permissions):
        findings.append(f"{path}: exactly the jobs {sorted(allowed_permissions)}")
    bound = 0
    for name, job in jobs.items():
        if not isinstance(job, dict):
            findings.append(f"{path}: job {name} is unreadable")
            continue
        if "continue-on-error" in job or any("continue-on-error" in step for step in _steps(job)):
            findings.append(f"{path}: job {name} continues on error")
        if job.get("permissions") != allowed_permissions.get(name):
            findings.append(f"{path}: job {name} holds exactly the permissions {allowed_permissions.get(name)}, parsed")
        job_environment_name = job_environment(job)
        condition = job.get("if")
        if job_environment_name is not None:
            bound += 1
            if job_environment_name != environment:
                findings.append(f"{path}: job {name} may bind only the {environment} environment")
            needs = job.get("needs")
            if needs != "preflight" and not (isinstance(needs, list) and "preflight" in needs):
                findings.append(f"{path}: job {name} runs only after the preflight job")
            if condition != CREDENTIAL_JOB_GUARD:
                findings.append(f"{path}: job {name} must be guarded by exactly `{CREDENTIAL_JOB_GUARD}`")
            findings.extend(_credential_job(path, name, job, mode))
        else:
            if condition is not None:
                findings.append(f"{path}: job {name} carries an `if`; only the credential-bearing job is guarded, exactly")
            for step in _steps(job):
                if "if" in step:
                    # A conditional preflight step could skip a refusal and let the job succeed.
                    findings.append(f"{path}: job {name} step {step.get('name')!r} carries an `if`; every preflight step runs")
            if (job.get("permissions") or {}).get("id-token") if isinstance(job.get("permissions"), dict) else False:
                findings.append(f"{path}: job {name} requests an OIDC token without a protected environment")
        for step in _steps(job):
            uses = step.get("uses")
            if uses is not None and not _SHA_PIN.match(str(uses)):
                findings.append(f"{path}: action {uses} is not pinned to a commit SHA")
            if str(uses or "").startswith("actions/checkout@"):
                with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
                if with_.get("persist-credentials") != "false":
                    findings.append(f"{path}: job {name}'s checkout sets persist-credentials: false (parsed, not a comment)")
        job_uses = job.get("uses")
        if job_uses is not None and not (mode == "publish" and name == "verify" and job_uses == "./.github/workflows/ci.yml"):
            findings.append(f"{path}: job {name} reuses {job_uses}; only artifact-publish's verify job reuses ci.yml")
    if bound != 1:
        findings.append(f"{path}: exactly one environment-bound job")
    if re.search(r"actions/upload-artifact|actions/cache|download-artifact|upload-artifact:\s*true", text):
        findings.append(f"{path}: no plan, state or log is ever uploaded as an artifact or cached")
    if re.search(r"\$RUNNER_TEMP\b|\$\{RUNNER_TEMP\}", text):
        findings.append(f"{path}: files are written in the private directory, never directly in RUNNER_TEMP")
    for name, job in jobs.items():
        for run in _runs(job) if isinstance(job, dict) else []:
            if re.search(r"\$\{\{\s*(inputs|github\.event\.inputs|vars|secrets)\.", run):
                findings.append(f"{path}: job {name} interpolates an expression into a shell script; pass it through env")
            if re.search(r"set\s+-[a-z]*x|\btee\b|cat\s+[^|]*(\.log|tfplan|tfvars)", run):
                findings.append(f"{path}: job {name} could echo plan, state or variables into the log")
            writes_private = re.search(r'>\s*"\$PRIVATE_DIR|--out\s+"\$PRIVATE_DIR|-out="\$PLAN_FILE"|get-object[^\n]*"\$PRIVATE_DIR', run)
            if writes_private and not run.startswith("umask 077\n"):
                findings.append(f"{path}: job {name} writes into the private directory without umask 077 first")
            for line in run.splitlines():
                if re.search(_TERRAFORM_COMMAND.format("show"), line) and not _SUMMARY_PIPE.search(line):
                    findings.append(f"{path}: terraform show is only ever piped into the sanitized summary")
                if re.search(_TERRAFORM_COMMAND.format("(plan|apply|init)"), line) and not re.search(r'>\s*"\$PRIVATE_DIR/', line):
                    findings.append(f"{path}: Terraform init, plan and apply output goes to a private runner file, never the log")
                if re.search(_TERRAFORM_COMMAND.format("(output|console|state|import|destroy|force-unlock|refresh|taint|untaint)"), line):
                    findings.append(f"{path}: job {name} runs a Terraform command outside init, plan, show and apply")
    image_lines = [
        line for job in jobs.values() if isinstance(job, dict) for run in _runs(job) for line in run.splitlines()
        if re.search(_IMAGE_COMMAND, line)
    ]
    image_actions = re.findall(r"uses:\s*(anchore/sbom-action|docker/[A-Za-z-]+|aws-actions/amazon-ecr-login)@", text)
    if mode in ("plan", "apply") and (image_lines or image_actions):
        findings.append(f"{path}: {mode} never builds, tags, pushes or deletes an image; it promotes a recorded digest")
    inputs = (document.get("on") or {}).get("workflow_dispatch") if isinstance(document.get("on"), dict) else None
    input_names = set((inputs or {}).get("inputs") or {}) if isinstance(inputs, dict) else set()
    if any(re.search(r"exception|admission|policy|waiver|override", name) for name in input_names):
        findings.append(f"{path}: an admission exception or policy can never be supplied through a workflow input")
    if mode == "apply":
        findings.extend(_apply_workflow(path, document, text, input_names))
    elif mode == "plan":
        findings.extend(_plan_workflow(path, _job_runs(document)))
        # The plan-time variables re-declare the registry; they are checked against the environment's
        # declaration before the OIDC token, not first when the file is written after it.
        plan_steps = _steps(jobs.get("plan"))
        checks = [
            index for index, step in enumerate(plan_steps)
            if "check-environment-variables --workflow plan" in str(step.get("run", ""))
            and (step.get("env") or {}).get("STAGING_TFVARS_JSON") == "${{ secrets.STAGING_TFVARS_JSON }}"
        ]
        oidc = [
            index for index, step in enumerate(plan_steps)
            if str(step.get("uses", "")).startswith("aws-actions/configure-aws-credentials@")
        ]
        if not checks or not oidc or checks[0] > oidc[0]:
            findings.append(f"{path}: the plan-time variables are checked against the declared registry before the OIDC token")
    else:
        findings.extend(_publish_workflow(path, document, _job_runs(document)))
    return findings


def _credential_job(path: str, name: str, job: dict, mode: str) -> list[str]:
    """The credential-bearing job: its private directory, and one cleanup step that always runs."""
    findings = []
    env = job.get("env") if isinstance(job.get("env"), dict) else {}
    if env.get("PRIVATE_DIR") != PRIVATE_DIR_VALUE:
        findings.append(f"{path}: job {name} keeps every file in PRIVATE_DIR={PRIVATE_DIR_VALUE}")
    if mode in ("plan", "apply") and env.get("TF_DATA_DIR") != TF_DATA_DIR_VALUE:
        findings.append(f"{path}: job {name} keeps Terraform's data directory in the private directory")
    steps = _steps(job)
    if len(steps) < 3 or steps[1].get("run") != PRIVATE_DIR_CREATION:
        findings.append(f"{path}: job {name} creates its private directory with umask 077 and mode 700 right after checkout")
    for index, step in enumerate(steps):
        condition = step.get("if")
        last = index == len(steps) - 1
        if condition is not None and not (last and condition == "always()"):
            findings.append(f"{path}: job {name} step {step.get('name')!r} carries an `if`; only the final cleanup step does")
        if isinstance(condition, str) and STATUS_FUNCTION.search(condition) and not last:
            findings.append(f"{path}: job {name} weakens a step with a status function")
    cleanup = steps[-1] if steps else {}
    if cleanup.get("if") != "always()" or cleanup.get("run") != CLEANUP_SCRIPTS[mode]:
        findings.append(
            f"{path}: job {name} ends with one cleanup step that always runs and removes every private and Terraform diagnostic file"
        )
    return findings


def _job_runs(document: dict) -> str:
    """Every run script of every job, joined: what a workflow executes, never what its comments say."""
    return "\n".join(run for job in (document.get("jobs") or {}).values() if isinstance(job, dict) for run in _runs(job))


def _apply_workflow(path: str, document: dict, text: str, input_names: set[str]) -> list[str]:
    findings = []
    text = _job_runs(document)
    if re.search(_TERRAFORM_COMMAND.format("plan"), text):
        findings.append(f"{path}: apply never generates a new plan")
    if input_names != set(APPLY_INPUTS):
        findings.append(f"{path}: apply is dispatched with exactly {', '.join(APPLY_INPUTS)}")
    run_name = str(document.get("run-name", ""))
    if any(f"${{{{ inputs.{name} }}}}" not in run_name for name in APPLY_INPUTS):
        findings.append(f"{path}: the run name -- and so the approval prompt -- shows every value of the deployment tuple")
    if '--expected-image "$RELEASE_IMAGE"' not in text:
        findings.append(f"{path}: apply refuses a plan that runs any image but the verified release_image")
    if not re.search(r'terraform[^\n]*\bapply\b[^\n]*"\$PLAN_FILE"', text):
        findings.append(f"{path}: apply consumes only the downloaded saved plan file")
    if re.search(r"-refresh-only|-replace=|-target=|-destroy", text):
        findings.append(f"{path}: apply takes no targeting, replacement, refresh-only or destroy option")
    for required in (
        "check-plan-object", "compare-lock", "check-terraform-version", "verify-checkout", "--version-id",
        "sha256sum --check --status", "plan-summary --mode apply", "check-deployment-authorization", "verify-release",
        '--expected-record-version-id "$RELEASE_RECORD_VERSION_ID"', '--expected-record-sha256 "$RELEASE_RECORD_SHA256"',
        "describe-image-scan-findings", "release-digest",
    ):
        if required not in text:
            findings.append(f"{path}: apply must run {required} before applying")
    steps = _steps((document.get("jobs") or {}).get("apply"))

    def first(predicate):
        return next((index for index, step in enumerate(steps) if predicate(step)), -1)

    order = [
        first(lambda step: "check-deployment-authorization" in str(step.get("run", ""))),
        first(lambda step: str(step.get("uses", "")).startswith("aws-actions/configure-aws-credentials@")),
        first(lambda step: "verify-release" in str(step.get("run", ""))),
        first(lambda step: re.search(r"terraform\s+apply\b", str(step.get("run", ""))) is not None),
    ]
    if -1 in order or order != sorted(order) or len(set(order)) != len(order):
        findings.append(f"{path}: the authorization is checked before any OIDC token, and the release re-verified before applying")
    return findings


def _plan_workflow(path: str, text: str) -> list[str]:
    findings = []
    if "--if-none-match" not in text:
        findings.append(f"{path}: the plan upload creates a new object only (--if-none-match)")
    if "write-tfvars" not in text:
        findings.append(f"{path}: plan-time variables pass through the fail-closed allow-list check")
    for required in ("release_commit", "release-digest", "imageDigest=$DIGEST", "verify-release", '--expected-image "$RELEASE_IMAGE"',
                     "release_record_version_id", "release_record_sha256"):
        if required not in text:
            findings.append(f"{path}: plan promotes a verified release by digest ({required})")
    if "imageTag=" in text or "--max-items" in text:
        findings.append(f"{path}: plan never resolves a release image by tag or reads a truncated scan")
    return findings


def _publish_workflow(path: str, document: dict, text: str) -> list[str]:
    findings = []
    jobs = document["jobs"]
    verify = jobs.get("verify")
    if not isinstance(verify, dict) or verify.get("uses") != "./.github/workflows/ci.yml" or verify.get("needs") != "preflight":
        findings.append(f"{path}: the full required verification (ci.yml) runs as its own job after the preflight")
    publish = jobs.get("publish") if isinstance(jobs.get("publish"), dict) else {}
    if not (isinstance(publish.get("needs"), list) and {"verify", "preflight"} <= set(publish["needs"])):
        findings.append(f"{path}: publication runs only after the full required verification passed")
    if (publish.get("env") or {}).get("APPROVAL_EVIDENCE") != "${{ needs.preflight.outputs.approval_evidence }}":
        findings.append(f"{path}: publication freezes the preflight's approval evidence into the release record")
    steps = _steps(publish)

    def first(predicate):
        return next((index for index, step in enumerate(steps) if predicate(step)), None)

    attempt = first(lambda step: "delivery.py check-publish-attempt" in str(step.get("run", "")))
    build = first(lambda step: "docker build" in str(step.get("run", "")))
    sbom = first(lambda step: str(step.get("uses", "")).startswith("anchore/sbom-action@"))
    draft = first(lambda step: "delivery.py release-draft" in str(step.get("run", "")))
    credentials = first(lambda step: str(step.get("uses", "")).startswith("aws-actions/configure-aws-credentials@"))
    publication = first(lambda step: "publication-mode" in str(step.get("run", "")))
    if None in (build, sbom, draft, credentials, publication) or not build < sbom < draft < credentials < publication:
        findings.append(f"{path}: the image is built, inspected, its SBOM generated and the release drafted before any credential exists")
    if attempt is None or build is None or not attempt < build:
        findings.append(f"{path}: this attempt's own gate jobs are checked (check-publish-attempt) before the build and any credential")
    else:
        attempt_env = steps[attempt].get("env") if isinstance(steps[attempt].get("env"), dict) else {}
        if attempt_env.get("GITHUB_TOKEN") != "${{ github.token }}":
            findings.append(f"{path}: check-publish-attempt reads this attempt's jobs with the job's own token")
    # The configuration digest the SBOM is addressed by comes from the build's own metadata, verified
    # against the local image by release-draft -- never from the local image ID, which an image store can
    # report as a manifest digest.
    build_runs = [str(step.get("run", "")) for step in steps if "docker build" in str(step.get("run", ""))]
    if not any('--metadata-file "$PRIVATE_DIR/build-metadata.json"' in run for run in build_runs):
        findings.append(f"{path}: the build records its configuration digest (--metadata-file) in the private directory")
    if '--build-metadata "$PRIVATE_DIR/build-metadata.json"' not in text or "draft-config-digest" not in text:
        findings.append(
            f"{path}: the draft verifies the build's configuration digest and the SBOM is addressed by it (draft-config-digest)"
        )
    if re.search(r"\{\{\s*\.Id\s*\}\}", text):
        findings.append(f"{path}: the SBOM is never addressed by the local image ID")
    builds = [step["run"] for step in steps if "docker build" in str(step.get("run", ""))]
    if len(builds) != 1 or len(re.findall(r"docker build", text)) != 1:
        findings.append(f"{path}: the image is built exactly once")
    for run in builds:
        flags = ("--provenance=false", "--sbom=false", "--platform linux/amd64")
        if re.search(r"--build-arg|--secret|--ssh", run) or not all(flag in run for flag in flags):
            findings.append(f"{path}: the release build takes no build argument or secret and adds no attestation manifest")
        for label in PROVENANCE_LABELS:
            if f'--label "{label}=' not in run:
                findings.append(f"{path}: the release build embeds its provenance label {label}")
    pushes = re.findall(r"docker push (\S+)", text)
    fresh = re.search(r'if \[ "\$MODE" = "fresh" \]; then\n(?P<body>.*?)\n\s*fi\n', text, re.S)
    body = fresh.group("body") if fresh else ""
    if 'TAG="git-$SOURCE_COMMIT"' not in text or pushes != ['"$REPOSITORY_URL:$TAG"'] or re.search(r":latest\b", text):
        findings.append(f"{path}: publication pushes exactly one tag, git-<full commit>")
    if "docker push" not in body or body.find("put_once") == -1 or body.find("put_once") > body.find("docker push"):
        findings.append(f"{path}: a push happens only when git-<commit> does not exist, after that image's SBOM is stored")
    if text.count("put-object") < 1 or text.count("put-object") != text.count("--if-none-match '*'"):
        findings.append(f"{path}: every release object is created once (--if-none-match)")
    for required in (
        "check-build-inputs", "release-draft", "publication-mode", "tag-digest", "batch-get-image", "image-config-digest",
        "get-download-url-for-layer", "registry-identity", "release-record", "compare-release-object", "object-metadata",
        "ImageNotFoundException", "docker logout",
    ):
        if required not in text:
            findings.append(f"{path}: publication must run {required}")
    if re.search(r"batch-delete-image|ecr\s+put-image|put-image-tag-mutability|delete-object|--force\b", text):
        findings.append(f"{path}: publication never deletes, re-tags, overwrites or forces anything")
    for step in steps:
        if str(step.get("uses", "")).startswith("anchore/sbom-action@"):
            with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
            if with_.get("upload-artifact") != "false" or with_.get("upload-release-assets") != "false":
                findings.append(f"{path}: the SBOM goes to the release record bucket, never to a GitHub artifact")
            if with_.get("output-file") != "${{ runner.temp }}/firmbatch-private/sbom.spdx.json":
                findings.append(f"{path}: the SBOM is written in the private directory")
    return findings


def rule_deployment_workflows(tree: Tree) -> list[str]:
    return (
        _deployment_workflow(tree, PUBLISH_WORKFLOW, "artifact-publish", "publish")
        + _deployment_workflow(tree, PLAN_WORKFLOW, "staging-plan", "plan")
        + _deployment_workflow(tree, APPLY_WORKFLOW, "staging-apply", "apply")
    )


def rule_codeowners(tree: Tree) -> list[str]:
    text = tree.text(".github/CODEOWNERS")
    owned = {line.split()[0] for line in text.splitlines() if line.strip() and not line.startswith("#")}
    required = {
        "/.github/", "/infra/", "/scripts/", "/.agents/", "/.claude/", "/.codex/",
        "/AGENTS.md", "/CLAUDE.md", "/Dockerfile", "/.dockerignore",
    }
    missing = sorted(required - owned)
    return [f".github/CODEOWNERS must own {', '.join(missing)}"] if missing else []


# ---------------------------------------------------------------------- build once, promote by digest


def rule_release_registry(tree: Tree) -> list[str]:
    """One canonical, immutable, retained release repository; only artifact-publish pushes; the
    artifacts root creates no identity or key and names only principals that already exist."""
    findings = []
    repositories = tree.resource(TF, "aws_ecr_repository")
    if len(repositories) != 1 or not repositories[0][0].startswith(f"{ARTIFACTS}/"):
        return ["exactly one ECR repository -- the canonical release repository -- in the human-applied artifacts root"]
    path, repository = repositories[0]
    if repository.attributes.get("image_tag_mutability") != "IMMUTABLE" or repository.children("image_tag_mutability_exclusion_filter"):
        findings.append(f"{path}: release tags are IMMUTABLE with no exclusion filter")
    if not any(c.attributes.get("scan_on_push") is True for c in repository.children("image_scanning_configuration")):
        findings.append(f"{path}: release images are scanned on push")
    encryption = repository.children("encryption_configuration")
    if not any(
        c.attributes.get("encryption_type") == "KMS" and c.raw_attributes.get("kms_key") == "var.release_kms_key_arn" for c in encryption
    ):
        findings.append(f"{path}: the release repository is KMS-encrypted under the bootstrap root's release key")
    if repository.attributes.get("force_delete") is not False:
        findings.append(f"{path}: the release repository is never force-deleted with its images")
    registry_wide = (
        "aws_ecr_replication_configuration", "aws_ecr_registry_policy",
        "aws_ecr_pull_through_cache_rule", "aws_ecr_repository_creation_template",
    )
    for kind in registry_wide:
        if tree.resource(TF, kind):
            findings.append(f"{kind} is not configured: replication and registry-wide changes are a later, explicit decision")
    for kind in ("aws_iam_role", "aws_iam_policy", "aws_iam_role_policy", "aws_kms_key", "aws_kms_alias"):
        if tree.resource(ARTIFACTS, kind):
            findings.append(f"{ARTIFACTS}: creates no {kind}; the release key and every delivery identity are the bootstrap root's")

    rules = []
    for _, lifecycle in tree.resource(ARTIFACTS, "aws_ecr_lifecycle_policy"):
        policy = lifecycle.attributes.get("policy")
        document = policy.args[0] if isinstance(policy, Call) and policy.name == "jsonencode" and policy.args else None
        rules.extend(document.get("rules", ()) if isinstance(document, dict) else [None])
    if not rules or any(not isinstance(r, dict) or (r.get("selection") or {}).get("tagStatus") != "untagged" for r in rules):
        findings.append(f"{ARTIFACTS}: the lifecycle policy expires untagged manifests only; deployed and rollback digests are retained")

    statements = _sids([
        s for _, p in tree.resource(ARTIFACTS, "aws_ecr_repository_policy") for s in _statements(p.attributes.get("policy"))
    ])
    push_deny = statements.get("OnlyTheArtifactPublishRolePushes", {})
    condition = push_deny.get("Condition") if isinstance(push_deny.get("Condition"), dict) else {}
    if (
        push_deny.get("Effect") != "Deny"
        or set(_actions(push_deny)) != set(ECR_PUSH_ACTIONS)
        or (condition.get("ArnNotEquals") or {}).get("aws:PrincipalArn") != "local.publish_role_arn"
    ):
        findings.append(f"{ARTIFACTS}: the repository policy denies every push to every principal but artifact-publish")
    delete_deny = statements.get("NoImageIsDeletedOrRetagged", {})
    if delete_deny.get("Effect") != "Deny" or "ecr:BatchDeleteImage" not in _actions(delete_deny) or "Condition" in delete_deny:
        findings.append(f"{ARTIFACTS}: no principal deletes or re-tags a release image")
    forbidden_grants = set(ECR_PUSH_ACTIONS + ("ecr:BatchDeleteImage",))
    if any(s.get("Effect") == "Allow" and set(_actions(s)) & forbidden_grants for s in statements.values()):
        findings.append(f"{ARTIFACTS}: the repository policy grants no push or deletion")

    if tree.locals(ARTIFACTS).get("publish_role_arn") != "var.artifact_publish_role_arn":
        findings.append(f"{ARTIFACTS}: the repository and record policies name the bootstrap root's artifact-publish role")
    lookups = tree.blocks(ARTIFACTS, "data", "aws_iam_role", "artifact_publish")
    conditions = " ".join(c.raw_attributes.get("condition", "") for _, d in lookups for c in _nested(d, "lifecycle", "postcondition"))
    if len(lookups) != 1 or not all(fragment in conditions for fragment in (
        "self.arn == var.artifact_publish_role_arn", "self.permissions_boundary", "repo:chamsrut/firmbatch:environment:artifact-publish",
    )):
        findings.append(
            f"{ARTIFACTS}: refuses to plan unless artifact-publish already exists, under its boundary, trusting exactly its environment"
        )
    if len(tree.blocks(ARTIFACTS, "data", "aws_iam_role", "release_readers")) != 1:
        findings.append(f"{ARTIFACTS}: reads every release reader role before any policy names it")
    for kind in ("aws_ecr_repository_policy", "aws_s3_bucket_policy"):
        for policy_path, block in tree.resource(ARTIFACTS, kind):
            depends = block.raw_attributes.get("depends_on", "")
            if "data.aws_iam_role.artifact_publish" not in depends or "data.aws_iam_role.release_readers" not in depends:
                findings.append(f"{policy_path}: {kind} names principals only after they are read and proven to exist")

    buckets = tree.resource(ARTIFACTS, "aws_s3_bucket", "releases")
    if len(buckets) != 1 or buckets[0][1].attributes.get("object_lock_enabled") is not True:
        findings.append(f"{ARTIFACTS}: release records live in an Object-Locked bucket")
    locks = [
        r for _, c in tree.resource(ARTIFACTS, "aws_s3_bucket_object_lock_configuration") for r in _nested(c, "rule", "default_retention")
    ]
    retention = locks[0].raw_attributes.get("days") if len(locks) == 1 else None
    if len(locks) != 1 or locks[0].attributes.get("mode") != "GOVERNANCE" or retention != "var.release_record_retention_days":
        findings.append(f"{ARTIFACTS}: release records carry GOVERNANCE retention of var.release_record_retention_days")
    records = _sids([
        s for _, p in tree.resource(ARTIFACTS, "aws_s3_bucket_policy", "releases") for s in _statements(p.attributes.get("policy"))
    ])
    overwrite = records.get("DenyOverwriteOfAReleaseRecord", {})
    record_condition = overwrite.get("Condition") if isinstance(overwrite.get("Condition"), dict) else {}
    if (
        overwrite.get("Effect") != "Deny" or overwrite.get("Action") != "s3:PutObject"
        or (record_condition.get("Null") or {}).get("s3:if-none-match") != "true" or set(record_condition) != {"Null"}
    ):
        findings.append(f"{ARTIFACTS}: every principal's release-record write must carry If-None-Match")
    return findings


def rule_publication_credentials(tree: Tree) -> list[str]:
    """Only artifact-publish.yml reaches publication; each reserved environment belongs to its own
    workflow file; nothing a pull request, push or fork starts gets a token."""
    findings = []
    for path in tree.under(".github/workflows/", ".yml") + tree.under(".github/workflows/", ".yaml"):
        text = tree.text(path)
        if path != PUBLISH_WORKFLOW and re.search(r"ARTIFACT_PUBLISH_ROLE_ARN|anchore/sbom-action|docker\s+push|get-login-password", text):
            findings.append(
                f"{path}: only {PUBLISH_WORKFLOW} references the artifact-publish role, an SBOM upload or a push"
            )
        for name, owner in RESERVED_ENVIRONMENTS.items():
            reference = rf"environment:[^\n]*['\"]?\b{re.escape(name)}\b|name:\s*['\"]?{re.escape(name)}['\"]?\s*$"
            # GitHub environment names are case-insensitive: Staging-Apply binds staging-apply.
            if path != owner and re.search(reference, text, re.M | re.I):
                findings.append(f"{path}: the {name} environment is reserved to {owner}")
        if re.search(r"\bwrite-all\b|\bread-all\b", text):
            findings.append(f"{path}: permissions are named scope by scope, never write-all or read-all")
        try:
            document = yaml_subset.parse(text)
        except yaml_subset.YamlError as exc:
            findings.append(f"{path}: outside the checked YAML subset ({exc}); failing closed")
            continue
        if not isinstance(document, dict):
            findings.append(f"{path}: not a workflow document; failing closed")
            continue
        triggers = workflow_triggers(document)
        if triggers is None:
            findings.append(f"{path}: its triggers cannot be read; failing closed")
            continue
        if "pull_request_target" in triggers:
            findings.append(f"{path}: pull_request_target runs with the base repository's secrets and token; it is never used")
        wants_token = False
        for where, value in _permission_values(document):
            if isinstance(value, str) and value not in ("",):
                findings.append(f"{path}: {where} permissions are a mapping of scopes, not {value!r}")
            elif isinstance(value, dict):
                wants_token = wants_token or value.get("id-token") == "write"
        for name, job in (document.get("jobs") or {}).items():
            environment = job_environment(job) if isinstance(job, dict) else None
            if environment is None:
                continue
            if "${{" in environment or environment == "<unreadable environment>":
                # An environment chosen at run time -- ${{ inputs.env }} -- can be dispatched as any
                # reserved environment, so no file-level reservation could hold.
                findings.append(
                    f"{path}: job {name} names its environment by an expression or unreadably; an environment is a literal name"
                )
                continue
            owner = next((o for reserved, o in RESERVED_ENVIRONMENTS.items() if reserved.casefold() == environment.casefold()), None)
            if owner is not None and path != owner:
                findings.append(f"{path}: job {name} binds {environment}, which is reserved to {owner}")
        if triggers & UNTRUSTED_TRIGGERS and wants_token:
            findings.append(f"{path}: a workflow a pull request, push or fork can start never requests an OIDC token")
    script = tree.text("infra/delivery/delivery.py")
    if re.search(r'add_argument\(\s*"--[a-z-]*(admission|exception|waiver|policy)', script):
        findings.append(
            "infra/delivery/delivery.py: the admission policy and its exceptions are read from the committed file only, "
            "never from an option"
        )
    return findings


def rule_ecs_contract_agreement(tree: Tree) -> list[str]:
    """delivery.py's ECS contract, the compute module, the staging root and the bootstrap root's
    delivery identities name the same workloads."""
    contract = None
    try:
        for node in ast.parse(tree.text("infra/delivery/delivery.py")).body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "ECS_CONTRACT" for t in node.targets):
                contract = ast.literal_eval(node.value)
    except (SyntaxError, ValueError):
        contract = None
    if not isinstance(contract, dict):
        return ["infra/delivery/delivery.py: ECS_CONTRACT must be a literal the policy check can read"]
    tasks = tree.locals(COMPUTE).get("tasks")
    if not isinstance(tasks, dict):
        return ["modules/compute: local.tasks is unreadable"]
    rendered = {}
    for task in tasks.values():
        secrets = task.get("secrets") if isinstance(task, dict) else None
        readable = isinstance(secrets, Call) and secrets.name == "tomap" and secrets.args and isinstance(secrets.args[0], dict)
        names = set(secrets.args[0]) if readable else None
        rendered[task.get("family") if isinstance(task, dict) else None] = (task.get("service") if isinstance(task, dict) else None, names)
    expected = {family: (spec["service"], set(spec["secrets"])) for family, spec in contract.items()}
    findings = []
    if rendered != expected:
        findings.append(
            "infra/delivery/delivery.py ECS_CONTRACT and modules/compute local.tasks disagree on families, services or secret references"
        )
    suffixes = tree.locals(ROOTS["staging"]).get("log_group_suffixes")
    if not isinstance(suffixes, dict) or set(suffixes.values()) != set(contract):
        findings.append("environments/staging: the workload families are exactly the delivery contract's")
    bootstrap = tree.locals(BOOTSTRAP)
    families = bootstrap.get("workload_families")
    services = bootstrap.get("service_families")
    if not isinstance(families, tuple) or set(families) != set(contract) or len(families) != len(contract):
        findings.append(
            "bootstrap: the families the apply role may register and whose roles it may pass are exactly the delivery contract's"
        )
    if not isinstance(services, dict) or set(services.values()) != {f for f, spec in contract.items() if spec["service"]}:
        findings.append("bootstrap: the services the apply role may roll out are exactly the delivery contract's")
    return findings


# ---------------------------------------------------------------------- container and evidence


def rule_container(tree: Tree) -> list[str]:
    findings = []
    dockerfile = tree.text("Dockerfile")
    if not dockerfile:
        return ["Dockerfile is missing"]
    joined = re.sub(r"\\\n", " ", dockerfile).splitlines()
    instructions = [line.strip() for line in joined if line.strip() and not line.lstrip().startswith("#")]
    froms = [line for line in instructions if line.upper().startswith("FROM ")]
    if not froms or any(not re.search(r"@sha256:[0-9a-f]{64}\b", line) for line in froms):
        findings.append("Dockerfile: every base image is pinned by digest")
    final_stage = instructions[instructions.index(froms[-1]):] if froms else []
    users = [line.split(None, 1)[1] for line in final_stage if line.upper().startswith("USER ")]
    if not users or not re.fullmatch(r"[1-9][0-9]*(:[1-9][0-9]*)?", users[-1]):
        findings.append("Dockerfile: the final stage runs as a numeric, non-root user")
    for line in instructions:
        upper = line.upper()
        if upper.startswith("ADD "):
            findings.append("Dockerfile: ADD is not used; COPY names each input")
        if upper.startswith(("ENV ", "ARG ")) and CREDENTIAL_NAME.search(upper):
            findings.append("Dockerfile: no credential is set in the image")
        if re.match(r"COPY\s+(--\S+\s+)*\.\s", line) or re.search(r"COPY\s+.*\.env\b", line):
            findings.append("Dockerfile: the whole context and environment files are never copied")
        if re.search(r"\b(curl|wget)\b", line):
            findings.append("Dockerfile: nothing is downloaded outside the pinned package managers")
    if "--require-hashes" not in dockerfile or "npm ci" not in dockerfile or re.search(r"npm\s+install", dockerfile):
        findings.append("Dockerfile: dependencies install only from the committed locks")
    commands = [line for line in instructions if line.upper().startswith(("CMD ", "ENTRYPOINT "))]
    if len(commands) != 1 or "firmbatch.control_plane.api" not in commands[0]:
        findings.append("Dockerfile: the default command is the existing web/API entry point")
    if re.search(r"broker|identity.binding|bootstrap", " ".join(commands)):
        findings.append("Dockerfile: the image claims no M3.3c program")
    ignore = [line.strip() for line in tree.text(".dockerignore").splitlines() if line.strip() and not line.startswith("#")]
    if not ignore or ignore[0] != "*" or not {"**/.env", "control_plane/tests"} <= set(ignore):
        findings.append(".dockerignore denies the whole context by default and never admits .env or tests")
    return findings


def rule_readiness_and_deployment_evidence(tree: Tree) -> list[str]:
    findings = []
    try:
        readiness = json.loads(tree.text("infra/delivery/readiness.json"))
    except ValueError:
        return ["infra/delivery/readiness.json is not valid JSON"]
    if readiness.get("schema_version") != 2:
        findings.append("readiness.json declares schema version 2")
    if readiness.get("github_repository") != GITHUB_REPOSITORY or readiness.get("github_repository_id") != GITHUB_REPOSITORY_ID:
        findings.append("readiness.json pins the repository name and ID")
    values = list((readiness.get("prerequisites") or {}).values())
    if not values or any(not isinstance(v, bool) for v in values):
        findings.append("readiness.json holds only boolean attestations")
    required = None
    try:
        for node in ast.parse(tree.text("infra/delivery/delivery.py")).body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "WORKFLOW_PREREQUISITES" for t in node.targets):
                required = ast.literal_eval(node.value)
    except (SyntaxError, ValueError):
        required = None
    if not isinstance(required, dict) or set(required) != {"publish", "plan", "apply"}:
        findings.append("infra/delivery/delivery.py: WORKFLOW_PREREQUISITES must be a literal naming each workflow's prerequisites")
    else:
        known = {name for names in required.values() for name in names}
        if set(readiness.get("prerequisites") or {}) != known:
            findings.append("readiness.json records exactly the prerequisites delivery.py's workflows require")
        if "human_applied_resources_applied_by_human" in required["publish"]:
            # Attested only after the first staging apply, which deploys a published release: requiring
            # it for publication makes the documented bootstrap order impossible without a false attestation.
            findings.append("artifact-publish cannot require human_applied_resources_applied_by_human, which follows publication")
        if any(set(required[w]) != known for w in ("plan", "apply")):
            findings.append("staging-plan and staging-apply require every readiness prerequisite")
    authorization = readiness.get("deployment_authorization")
    bound = isinstance(authorization, dict) and authorization.get("schema_version") == 1
    if not bound or not isinstance(authorization.get("authorizations"), list):
        findings.append("readiness.json records deployment authorizations as a list bound to exact plans and releases")
        authorized = False
    else:
        authorized = bool(authorization["authorizations"])
    evidence = [p for p in tree.files if p.startswith(DEPLOYMENT_EVIDENCE)]
    if evidence and not authorized:
        findings.append(f"{DEPLOYMENT_EVIDENCE} holds M3.3 AWS staging evidence before an authorized M3.3d deployment")
    return findings


RULES = (
    rule_layout,
    rule_versions,
    rule_backends_and_workspaces,
    rule_account_and_region,
    rule_forbidden_constructs,
    rule_no_secret_values,
    rule_no_valued_tfvars,
    rule_tests_are_mocked,
    rule_compute,
    rule_database,
    rule_network_ingress,
    rule_identity,
    rule_delivery_trust,
    rule_policy_semantics,
    rule_saved_plans_and_state,
    rule_ci_workflow,
    rule_deployment_workflows,
    rule_codeowners,
    rule_container,
    rule_readiness_and_deployment_evidence,
    rule_release_registry,
    rule_publication_credentials,
    rule_ecs_contract_agreement,
)


def run_rules(tree: Tree) -> list[str]:
    findings = []
    for rule in RULES:
        try:
            findings.extend(f"[{rule.__name__[5:]}] {f}" for f in rule(tree))
        except (hcl.HclError, yaml_subset.YamlError, PolicyUnresolved, KeyError, IndexError, TypeError, AttributeError) as exc:
            findings.append(f"[{rule.__name__[5:]}] could not be evaluated ({type(exc).__name__}: {exc}); failing closed")
    return findings


def main() -> int:
    findings = run_rules(Tree.from_repository())
    for finding in findings:
        print(f"policy: {finding}")
    if findings:
        print(f"policy: {len(findings)} finding(s) across {len(RULES)} rules")
        return 1
    print(f"policy: {len(RULES)} rules, no findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
