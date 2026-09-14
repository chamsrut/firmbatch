#!/usr/bin/env python3
"""Fail-closed checks for the manually dispatched publish, staging plan and staging apply workflows.

ADR 0011 decision 9 and ADR 0012: decision 5 (the authority split), decision 13 (build once and
promote by digest) and decision 15 (resumable publication, frozen approval, the exact publish
attempt, admission exceptions and security stops, deployment authorization bound to one plan and
one release). Each subcommand refuses unless it can positively establish what it checks, and exits
3 with a one-line reason when it cannot. None of them prints a Terraform plan, a state value, a
secret, a resource address or a reviewer CIDR.

    delivery.py preflight --workflow publish|plan|apply
    delivery.py verify-checkout
    delivery.py check-environment-variables --workflow publish|plan|apply
    delivery.py check-deployment-authorization
    delivery.py check-publish-attempt
    delivery.py check-build-inputs --dockerfile PATH
    delivery.py release-draft --image-inspect PATH --build-metadata PATH --sbom PATH --out PATH
    delivery.py publication-mode --draft PATH --repository-url URL --tag-json PATH
    delivery.py sbom-key --draft PATH
    delivery.py draft-config-digest --draft PATH
    delivery.py object-metadata --kind sbom|record --commit C --digest D --body PATH
    delivery.py image-config-digest --repository-url URL --images-json PATH --manifest-json PATH
    delivery.py registry-identity --draft PATH --mode fresh|resume --repository-url URL --images-json PATH
                                  --manifest-json PATH --config-blob PATH [--local-repo-digest REF] --out PATH
    delivery.py release-record --draft PATH --identity PATH --sbom-object PATH --sbom-head PATH --out PATH
    delivery.py compare-release-object --kind sbom|record --commit C --digest D --expected PATH --existing PATH --head PATH
    delivery.py verify-release --record PATH --record-head PATH --commit C --repository-json PATH --image-json PATH
                               --scan-json PATH [--expected-record-version-id ID --expected-record-sha256 SHA]
    delivery.py verify-destination-digest --source-image REF --destination-repository-url URL --image-json PATH
    delivery.py write-tfvars --out PATH
    delivery.py check-terraform-version --pinned-file PATH          < terraform version -json
    delivery.py check-plan-object --expected-version-id ID --max-age-hours N   < head-object JSON
    delivery.py compare-lock --plan PATH --lockfile PATH
    delivery.py plan-summary --mode plan|apply --terraform-version V --expected-image REF
                                                                   < terraform show -json

`preflight` runs in a job that references no GitHub environment and holds no OIDC token, so a
missing or unprotected environment, an unreviewed commit, a fork, a non-main ref, an unmet
readiness attestation or a missing deployment authorization stops the run before any
environment-bound job starts -- and so before GitHub could create an environment on first reference.

Standard library only.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from typing import Callable

REPO = pathlib.Path(__file__).resolve().parents[2]
READINESS_PATH = REPO / "infra" / "delivery" / "readiness.json"
READINESS_GIT_PATH = "infra/delivery/readiness.json"
# The admission policy is the live security overlay -- security stops, digest-scoped exceptions and
# their expiry, the finding maxima. Promotion and apply read it from origin/main at the moment they
# evaluate a release (security_overlay_from_main), never from the checked-out commit: at apply that
# commit is the plan's source commit, which can predate a stop or an exception's removal. No option,
# input or environment variable names another file or adds an exception. ADMISSION_POLICY_PATH is the
# same file in this checkout, read only by the tests that hold the committed default to fail closed.
ADMISSION_POLICY_PATH = REPO / "infra" / "delivery" / "admission-policy.json"
ADMISSION_POLICY_GIT_PATH = "infra/delivery/admission-policy.json"

REPOSITORY = "chamsrut/firmbatch"
REPOSITORY_ID = "1349512121"
DEFAULT_BRANCH = "main"
ENVIRONMENTS = {"publish": "artifact-publish", "plan": "staging-plan", "apply": "staging-apply"}
ROLE_NAMES = {
    "publish": "firmbatch-artifact-publish",
    "plan": "firmbatch-staging-github-plan",
    "apply": "firmbatch-staging-github-apply",
}
ROLE_VARIABLES = {
    "publish": "ARTIFACT_PUBLISH_ROLE_ARN",
    "plan": "STAGING_PLAN_ROLE_ARN",
    "apply": "STAGING_APPLY_ROLE_ARN",
}

PLAN_KEY = re.compile(r"^plans/staging/(?P<commit>[0-9a-f]{40})/(?P<sha256>[0-9a-f]{64})\.tfplan$")
VERSION_ID = re.compile(r"^[A-Za-z0-9._-]{1,1024}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
ACCOUNT = re.compile(r"^[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]{0,18}$")
LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
PULL_REQUEST_URL = re.compile(rf"^https://github\.com/{re.escape(REPOSITORY)}/pull/[1-9][0-9]*$")
LABEL_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

# ---------------------------------------------------------------------- the release contract

PUBLISH_WORKFLOW = ".github/workflows/artifact-publish.yml"
PUBLISH_WORKFLOW_REF = f"{REPOSITORY}/{PUBLISH_WORKFLOW}@refs/heads/{DEFAULT_BRANCH}"
SOURCE_URL = f"https://github.com/{REPOSITORY}"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_NAME = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$")
REPOSITORY_URL = re.compile(
    r"^(?P<account>[0-9]{12})\.dkr\.ecr\.(?P<region>[a-z0-9-]+)\.amazonaws\.com/(?P<name>[a-z0-9][a-z0-9._/-]*)$"
)
# A full, digest-qualified reference and nothing else: a tag, or a tag with a digest, fails.
IMAGE_REFERENCE = re.compile(
    r"^(?P<repository>[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9][a-z0-9._/-]*)@(?P<digest>sha256:[0-9a-f]{64})$"
)
PINNED_BASE_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$")
# One digest is one image: a single-image manifest, never an index whose children could differ, and
# the configuration media type each manifest type carries.
IMAGE_MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json": "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json": "application/vnd.docker.container.image.v1+json",
}

# The provenance every release image carries in its labels, set by the one build before any
# credential exists. It is enough to recover a publication an earlier attempt left incomplete: which
# repository, commit and workflow built it, and which run and attempt pushed it.
PROVENANCE_SCHEMA = "firmbatch.release-provenance.v1"
LABEL_SOURCE = "org.opencontainers.image.source"
LABEL_REVISION = "org.opencontainers.image.revision"
LABEL_CREATED = "org.opencontainers.image.created"
LABEL_PROVENANCE = "io.firmbatch.release.provenance"
LABEL_REPOSITORY_ID = "io.firmbatch.release.repository-id"
LABEL_WORKFLOW_REF = "io.firmbatch.release.workflow-ref"
LABEL_RUN_ID = "io.firmbatch.release.run-id"
LABEL_RUN_ATTEMPT = "io.firmbatch.release.run-attempt"

# The publication workflow an exact publish attempt must have run, the gate jobs it must show and the
# approval rules a frozen approval is validated by are part of each release-record version's contract
# (ReleaseContract, below; ADR 0012 decision 13), never module-wide constants at verification: renaming
# the workflow or a CI job, or changing an approval rule, is a new contract version, and a record is
# verified under the version it declares.

# Admission exceptions: exact vulnerability identifiers, for one exact digest, for a short time.
_GHSA_PART = "[23456789cfghjmpqrvwx]{4}"
VULNERABILITY_ID = re.compile(rf"^(CVE-[0-9]{{4}}-[0-9]{{4,7}}|GHSA-{_GHSA_PART}-{_GHSA_PART}-{_GHSA_PART})$")
MAX_EXCEPTION_IDS = 10
MAX_EXCEPTION_LIFETIME = dt.timedelta(days=30)
MAX_AUTHORIZATION_LIFETIME = dt.timedelta(hours=24)

# ---------------------------------------------------------------------- the authority split

# Resource types whose creation and every later change is a human's, with short-lived AWS
# SSO/MFA credentials (ADR 0012 decision 5): the trust anchors. IAM cannot limit what a trust
# policy says or what value a secret update carries, so the pipeline changes none of these: the
# apply boundary denies the calls, and plan-summary --mode apply refuses a saved plan that changes
# any of them before anything is applied. infra/terraform/policy/check.py asserts the list, and
# asserts it does NOT cover task definitions, services or the budget, which the pipeline applies.
HUMAN_APPLIED_TYPE_PREFIXES = (
    "aws_iam_",                   # the OIDC provider, every role, trust policy, permission policy and boundary
    "aws_kms_",                   # keys, key policies, grants and aliases
    "aws_secretsmanager_",        # secret containers, and anything that could carry a value
    "aws_ecr_",                   # the release registry, its lifecycle and repository policies
    "aws_s3_",                    # the state, saved-plan and release-record buckets
    "aws_budgets_budget_action",  # a budget action applies a policy under a role: an escalation path
)

# The ECS resource types the pipeline applies, each checked against ECS_CONTRACT.
ECS_PIPELINE_TYPES = ("aws_ecs_cluster", "aws_ecs_cluster_capacity_providers", "aws_ecs_task_definition", "aws_ecs_service")

# The ECS delivery contract, per task-definition family suffix: whether it is a service, and the
# only secret references its container may hold -- environment name to secret-container suffix.
# "rds!" is the RDS-managed master secret, whose name RDS chooses. The compute module must agree;
# infra/terraform/policy/check.py compares the two.
ECS_CONTRACT = {
    "web-api": {
        "service": True,
        "secrets": {"FIRMBATCH_DATABASE_URL": "application-database-url"},
    },
    "identity-broker": {
        "service": True,
        "secrets": {
            "FIRMBATCH_AUTHENTICATOR_DATABASE_URL": "authenticator-database-url",
            "FIRMBATCH_COGNITO_CLIENT_SECRET": "cognito-client-secret",
        },
    },
    "migrate": {
        "service": False,
        "secrets": {"FIRMBATCH_MIGRATION_DATABASE_URL": "migration-database-url"},
    },
    "bootstrap": {
        "service": False,
        "secrets": {"FIRMBATCH_RDS_MASTER_SECRET": "rds!"},
    },
    "identity-binding": {
        "service": False,
        "secrets": {"FIRMBATCH_IDENTITY_BINDING_DATABASE_URL": "identity-binding-database-url"},
    },
}
NON_ROOT_USER = re.compile(r"^[1-9][0-9]*(:[1-9][0-9]*)?$")


def human_applied(resource_type: str) -> bool:
    return any(resource_type.startswith(prefix) for prefix in HUMAN_APPLIED_TYPE_PREFIXES)


class Refusal(Exception):
    """A check could not be positively satisfied."""


# ---------------------------------------------------------------------- small readers


def _timestamp(value) -> dt.datetime:
    if not isinstance(value, str):
        raise Refusal("a timestamp is missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Refusal("a timestamp is malformed") from None
    if parsed.tzinfo is None:
        raise Refusal("a timestamp carries no timezone")
    return parsed


def _positive_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _json(data, what: str):
    try:
        return json.loads(data)
    except (TypeError, ValueError):
        raise Refusal(f"{what} is not JSON") from None


def _write_private(path: pathlib.Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


# ---------------------------------------------------------------------- context and readiness


def check_context(env: dict, event: dict) -> None:
    if env.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise Refusal("the workflow was not started by workflow_dispatch")
    if env.get("GITHUB_REF") != f"refs/heads/{DEFAULT_BRANCH}":
        raise Refusal("the workflow ref is not refs/heads/main")
    if env.get("GITHUB_REF_PROTECTED") != "true":
        raise Refusal("GitHub does not report refs/heads/main as protected")
    if env.get("GITHUB_REPOSITORY") != REPOSITORY or env.get("GITHUB_REPOSITORY_ID") != REPOSITORY_ID:
        raise Refusal("the repository name or pinned repository ID does not match")
    repository = event.get("repository") if isinstance(event, dict) else None
    if not isinstance(repository, dict):
        raise Refusal("the event payload carries no repository")
    if repository.get("fork") is not False:
        raise Refusal("the workflow is running in a fork")
    if str(repository.get("id")) != REPOSITORY_ID or repository.get("default_branch") != DEFAULT_BRANCH:
        raise Refusal("the event's repository ID or default branch does not match")


# The attestations readiness.json records, and which of them each workflow needs. Publication comes
# before the human's first staging apply -- that apply deploys a published release -- so publication
# never needs human_applied_resources_applied_by_human, which is attested only after that apply
# (runbooks/bootstrap.md): requiring it would make the documented order impossible to complete without
# a false attestation. infra/terraform/policy/check.py reads this literal.
WORKFLOW_PREREQUISITES = {
    "publish": (
        "state_plan_buckets_and_delivery_identities_bootstrapped_by_human",
        "release_registry_applied_by_human",
        "artifact_publish_environment_created_and_protected",
        "github_environments_created_and_protected",
        "main_branch_protected_with_code_owner_review",
        "second_qualified_reviewer_available",
        "m3_3c_programs_dependencies_and_image_reviewed",
    ),
    "plan": (
        "state_plan_buckets_and_delivery_identities_bootstrapped_by_human",
        "release_registry_applied_by_human",
        "artifact_publish_environment_created_and_protected",
        "human_applied_resources_applied_by_human",
        "github_environments_created_and_protected",
        "main_branch_protected_with_code_owner_review",
        "second_qualified_reviewer_available",
        "m3_3c_programs_dependencies_and_image_reviewed",
    ),
    "apply": (
        "state_plan_buckets_and_delivery_identities_bootstrapped_by_human",
        "release_registry_applied_by_human",
        "artifact_publish_environment_created_and_protected",
        "human_applied_resources_applied_by_human",
        "github_environments_created_and_protected",
        "main_branch_protected_with_code_owner_review",
        "second_qualified_reviewer_available",
        "m3_3c_programs_dependencies_and_image_reviewed",
    ),
}
KNOWN_PREREQUISITES = frozenset(name for names in WORKFLOW_PREREQUISITES.values() for name in names)


def check_readiness(readiness: dict, workflow: str) -> None:
    """Every prerequisite this workflow needs is attested true. readiness.json must record exactly the
    known prerequisites, each a boolean, so a renamed or missing attestation cannot drop out unnoticed."""
    if workflow not in WORKFLOW_PREREQUISITES:
        raise Refusal("an unknown workflow")
    if not isinstance(readiness, dict) or readiness.get("schema_version") != 2:
        raise Refusal("readiness.json is missing or has an unknown schema")
    if readiness.get("github_repository") != REPOSITORY or readiness.get("github_repository_id") != REPOSITORY_ID:
        raise Refusal("readiness.json names another repository")
    prerequisites = readiness.get("prerequisites")
    if not isinstance(prerequisites, dict) or set(prerequisites) != KNOWN_PREREQUISITES:
        raise Refusal("readiness.json does not record exactly the known prerequisites")
    if any(not isinstance(value, bool) for value in prerequisites.values()):
        raise Refusal("readiness.json records a prerequisite that is not a boolean attestation")
    unmet = sorted(name for name in WORKFLOW_PREREQUISITES[workflow] if prerequisites[name] is not True)
    if unmet:
        raise Refusal("readiness prerequisites not attested: " + ", ".join(unmet))


def _json_from_main(git_path: str, what: str, run=None):
    run = run or subprocess.run
    result = run(["git", "show", f"origin/{DEFAULT_BRANCH}:{git_path}"], cwd=REPO, capture_output=True, check=False)
    if result.returncode != 0:
        raise Refusal(f"{what} could not be read from origin/main")
    return _json(result.stdout, f"{what} on origin/main")


def readiness_from_main(run=None) -> dict:
    """readiness.json as protected main holds it now -- where a deployment authorization is recorded
    after the plan it authorizes -- rather than as the plan's own, earlier commit held it."""
    return _json_from_main(READINESS_GIT_PATH, "readiness.json", run)


def security_overlay_from_main(run=None) -> dict:
    """The admission policy as protected main holds it now: the live security overlay promotion and
    apply evaluate a release under.

    Never the checked-out commit's copy. At apply the checkout is the plan's source commit, so a security
    stop, or an exception's removal, merged to main after the plan would otherwise be ignored and the
    revoked digest applied. A release's historical contract -- its components, locks, workflow identity,
    publish attempt and frozen approval -- is read from the record under the contract of the version it
    declares; this overlay is evaluated beside it, independently, at the time of use. An overlay whose
    schema this checkout's code does not know is refused, never guessed, so an older plan cannot apply
    under a newer overlay it cannot read."""
    return _json_from_main(ADMISSION_POLICY_GIT_PATH, "the admission policy", run)


AUTHORIZATION_KEYS = frozenset({
    "environment", "plan_key", "plan_version_id", "plan_sha256", "release_commit", "release_image_digest",
    "release_record_version_id", "release_record_sha256", "authorized_by", "authorization_reference",
    "authorized_at", "expires_at",
})


def _check_authorization_entry(entry) -> None:
    if not isinstance(entry, dict) or set(entry) != AUTHORIZATION_KEYS:
        raise Refusal("a deployment authorization holds keys outside its schema")
    if entry["environment"] != "staging":
        raise Refusal("a deployment authorization names another environment")
    match = PLAN_KEY.fullmatch(entry["plan_key"] or "")
    if not match or match.group("sha256") != entry["plan_sha256"]:
        raise Refusal("a deployment authorization's plan key and SHA-256 disagree")
    if not VERSION_ID.fullmatch(entry["plan_version_id"] or "") or not VERSION_ID.fullmatch(entry["release_record_version_id"] or ""):
        raise Refusal("a deployment authorization's version IDs are malformed")
    if not COMMIT.fullmatch(entry["release_commit"] or "") or not DIGEST.fullmatch(entry["release_image_digest"] or ""):
        raise Refusal("a deployment authorization's release commit or digest is malformed")
    if not SHA256.fullmatch(entry["release_record_sha256"] or ""):
        raise Refusal("a deployment authorization's release-record SHA-256 is malformed")
    if not LOGIN.fullmatch(entry["authorized_by"] or "") or not PULL_REQUEST_URL.fullmatch(entry["authorization_reference"] or ""):
        raise Refusal("a deployment authorization names no authorizer or reviewed reference")
    authorized_at, expires_at = _timestamp(entry["authorized_at"]), _timestamp(entry["expires_at"])
    if not authorized_at < expires_at or expires_at - authorized_at > MAX_AUTHORIZATION_LIFETIME:
        raise Refusal("a deployment authorization lasts longer than 24 hours")


def check_deployment_authorization(readiness: dict, inputs: dict, now: dt.datetime) -> dict:
    """The one unexpired authorization naming exactly this plan and this release.

    It is bound to the plan object's key, version ID and SHA-256 and to the release commit, image
    digest and release-record version and SHA-256, and it expires within 24 hours: an authorization
    never authorizes another plan, another release or a later plan of the same release.
    """
    block = readiness.get("deployment_authorization") if isinstance(readiness, dict) else None
    if not isinstance(block, dict) or set(block) != {"schema_version", "authorizations"} or block.get("schema_version") != 1:
        raise Refusal("readiness.json records no deployment authorization in the expected schema")
    entries = block["authorizations"]
    if not isinstance(entries, list):
        raise Refusal("readiness.json's deployment authorizations are malformed")
    for entry in entries:
        _check_authorization_entry(entry)
    wanted = {
        "plan_key": inputs["plan_key"],
        "plan_version_id": inputs["plan_version_id"],
        "plan_sha256": inputs["plan_sha256"],
        "release_commit": inputs["release_commit"],
        "release_image_digest": inputs["release_digest"],
        "release_record_version_id": inputs["release_record_version_id"],
        "release_record_sha256": inputs["release_record_sha256"],
    }
    matches = [entry for entry in entries if all(entry[key] == value for key, value in wanted.items())]
    if len(matches) != 1:
        raise Refusal("no single deployment authorization names exactly this plan and this release")
    entry = matches[0]
    if not _timestamp(entry["authorized_at"]) <= now < _timestamp(entry["expires_at"]):
        raise Refusal("the deployment authorization for this plan and release is not in force")
    return entry


# ---------------------------------------------------------------------- GitHub API (read-only)


def github_api(path: str, token: str, base: str = "https://api.github.com"):
    request = urllib.request.Request(
        base.rstrip("/") + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "firmbatch-delivery-preflight",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise Refusal(f"the GitHub API answered {exc.code} for a read the check needs") from None
    except (urllib.error.URLError, TimeoutError, ValueError):
        raise Refusal("the GitHub API could not be read") from None


def _api_from_env(env: dict):
    token = env.get("GITHUB_TOKEN", "")
    if not token:
        raise Refusal("GITHUB_TOKEN is not available for the GitHub reads this check needs")
    return lambda path: github_api(path, token, env.get("GITHUB_API_URL", "https://api.github.com"))


def check_environment(api, name: str) -> None:
    environment = api(f"/repos/{REPOSITORY}/environments/{name}")
    if environment is None:
        raise Refusal(f"the {name} environment does not exist; refusing before any job references it")
    rules = environment.get("protection_rules") or []
    reviewers = [r for r in rules if r.get("type") == "required_reviewers"]
    if not reviewers or not any(r.get("reviewers") for r in reviewers):
        raise Refusal(f"the {name} environment requires no reviewer")
    if not all(r.get("prevent_self_review") is True for r in reviewers):
        raise Refusal(f"the {name} environment does not prevent self-review")
    if environment.get("can_admins_bypass") is not False:
        raise Refusal(f"administrators can bypass the {name} environment's protection")
    branch_policy = environment.get("deployment_branch_policy")
    if branch_policy != {"protected_branches": False, "custom_branch_policies": True}:
        raise Refusal(f"the {name} environment does not restrict deployments to named branches")
    policies = api(f"/repos/{REPOSITORY}/environments/{name}/deployment-branch-policies")
    names = sorted(
        (p.get("type", "branch"), p.get("name"))
        for p in (policies or {}).get("branch_policies", [])
    )
    if names != [("branch", DEFAULT_BRANCH)]:
        raise Refusal(f"the {name} environment admits a deployment ref other than main")


def _reviews(api, number) -> list:
    reviews: list = []
    for page in range(1, 51):
        batch = api(f"/repos/{REPOSITORY}/pulls/{number}/reviews?per_page=100&page={page}") or []
        if not isinstance(batch, list):
            raise Refusal("the source pull request's reviews could not be read")
        reviews.extend(batch)
        if len(batch) < 100:
            return reviews
    raise Refusal("the source pull request has more reviews than the check evaluates")


def approval_evidence(api, sha: str, contract: "ReleaseContract | None" = None) -> dict:
    """The approval that admits ``sha`` now, as evidence that can be frozen into a release record.

    ``sha`` must be the merge commit of exactly one pull request into main. Only reviews submitted
    before the merge count, and only from an account other than the author's whose association with
    the repository the review reports as owner, member or collaborator, and which holds write
    permission when this runs. The association is not proof of write access -- an organization member
    or a collaborator can hold read access -- and whether GitHub reports it as of the review or as of
    the read is unobserved; the permission read is what establishes write access. Among those
    reviewers, no latest review may request changes, and one must approve the pull request's final
    head. A later review never counts.

    This is the rule for a commit about to act: the commit being published, and the source commit a
    plan or apply runs Terraform from. Because the permission is read now, an approver whose write
    access has since been removed no longer admits that commit, and publication, plan -- a rollback
    included, which also plans from main -- and apply from it refuse until a newly approved merge lands
    on main. That is deliberate: a revoked account's approval does not run infrastructure changes. A
    release already published is unaffected: its record keeps the approval frozen at publication, which
    promotion validates by the record's own contract and never against anyone's current permission.
    """
    contract = contract or RELEASE_CONTRACTS[CURRENT_RELEASE_SCHEMA_VERSION]
    if not COMMIT.fullmatch(sha or ""):
        raise Refusal("the source commit is not a full 40-hex SHA")
    pulls = api(f"/repos/{REPOSITORY}/commits/{sha}/pulls") or []
    merged = [
        p for p in pulls
        if isinstance(p, dict) and p.get("merged_at") and (p.get("base") or {}).get("ref") == DEFAULT_BRANCH
        and p.get("merge_commit_sha") == sha
    ]
    if len(merged) != 1:
        raise Refusal("the source commit is not the merge of exactly one pull request into main")
    pull = merged[0]
    merged_at = _timestamp(pull.get("merged_at"))
    author = pull.get("user") or {}
    head = (pull.get("head") or {}).get("sha")
    if not _positive_int(pull.get("number")) or not _positive_int(author.get("id")) or not COMMIT.fullmatch(head or ""):
        raise Refusal("the source pull request's number, author or head could not be read")

    considered = []
    for review in _reviews(api, pull["number"]):
        if not isinstance(review, dict):
            continue
        user = review.get("user") or {}
        if not isinstance(user, dict) or not _positive_int(user.get("id")) or not isinstance(user.get("login"), str):
            continue
        if user["id"] == author["id"] or user["login"].lower() == str(author.get("login", "")).lower():
            continue
        if review.get("state") not in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED") or not review.get("submitted_at"):
            continue
        if _timestamp(review["submitted_at"]) > merged_at:
            continue  # submitted after the merge: it approved nothing that was merged
        if review.get("author_association") not in contract.qualifying_associations:
            continue  # the review reports no owner, member or collaborator association
        if not _positive_int(review.get("id")):
            continue
        considered.append(review)
    latest: dict[int, dict] = {}
    for review in sorted(considered, key=lambda r: (_timestamp(r["submitted_at"]), r["id"])):
        latest[review["user"]["id"]] = review

    permissions: dict[str, str] = {}
    for review in latest.values():
        login = review["user"]["login"]
        document = api(f"/repos/{REPOSITORY}/collaborators/{login}/permission") or {}
        permissions[login] = document.get("permission") if isinstance(document, dict) else None
    qualified = [r for r in latest.values() if permissions.get(r["user"]["login"]) in contract.write_permissions]
    if any(r["state"] == "CHANGES_REQUESTED" for r in qualified):
        raise Refusal("a qualified reviewer's latest review of the source pull request before the merge requests changes")
    approvals = [r for r in qualified if r["state"] == "APPROVED" and r.get("commit_id") == head]
    if not approvals:
        raise Refusal("no qualified reviewer other than the author approved the source pull request's final head before the merge")
    chosen = max(approvals, key=lambda r: (_timestamp(r["submitted_at"]), r["id"]))
    evidence = {
        "pull_request": pull["number"],
        "pull_request_author_id": author["id"],
        "pull_request_author_login": author.get("login"),
        "head_commit": head,
        "merge_commit": sha,
        "merged_at": pull["merged_at"],
        "approver_id": chosen["user"]["id"],
        "approver_login": chosen["user"]["login"],
        "review_id": chosen["id"],
        "review_submitted_at": chosen["submitted_at"],
        "review_commit": chosen["commit_id"],
        "reviewer_association": chosen["author_association"],
        "reviewer_permission": permissions[chosen["user"]["login"]],
    }
    return check_recorded_approval(evidence, sha, contract)


def check_commit_approved(api, sha: str) -> dict:
    """The deployment source commit a plan or apply runs from, approved now (approval_evidence):
    current write permission is required of its approver, unlike a published release's frozen approval."""
    return approval_evidence(api, sha)


def check_recorded_approval(approval, commit: str, contract: "ReleaseContract") -> dict:
    """A frozen approval, validated by the rules of the contract it was frozen under and never by
    anyone's current permission."""
    if not isinstance(approval, dict) or set(approval) != contract.approval_keys:
        raise Refusal("the recorded approval holds keys outside its schema")
    for key in ("pull_request", "pull_request_author_id", "approver_id", "review_id"):
        if not _positive_int(approval[key]):
            raise Refusal(f"the recorded approval's {key} is malformed")
    for key in ("pull_request_author_login", "approver_login"):
        if not isinstance(approval[key], str) or not LOGIN.fullmatch(approval[key]):
            raise Refusal(f"the recorded approval's {key} is malformed")
    if not COMMIT.fullmatch(commit or "") or approval["merge_commit"] != commit:
        raise Refusal("the recorded approval is for another merge commit")
    if not COMMIT.fullmatch(approval["head_commit"] or "") or approval["review_commit"] != approval["head_commit"]:
        raise Refusal("the recorded approval is not of the pull request's final head")
    if approval["approver_id"] == approval["pull_request_author_id"] or (
        approval["approver_login"].lower() == approval["pull_request_author_login"].lower()
    ):
        raise Refusal("the recorded approval is the author's own")
    qualified = approval["reviewer_association"] in contract.qualifying_associations
    if not qualified or approval["reviewer_permission"] not in contract.write_permissions:
        raise Refusal("the recorded approval is from an account without write access")
    if _timestamp(approval["review_submitted_at"]) > _timestamp(approval["merged_at"]):
        raise Refusal("the recorded approval was submitted after the merge")
    return approval


def verify_pull_request_facts(api, approval: dict, commit: str) -> None:
    """The recorded pull request's immutable facts still read as recorded. Its reviews and its
    reviewers' current permissions are deliberately not re-read: approval is historical."""
    pull = api(f"/repos/{REPOSITORY}/pulls/{approval['pull_request']}")
    if not isinstance(pull, dict):
        raise Refusal("the recorded pull request cannot be read")
    if pull.get("merge_commit_sha") != commit or (pull.get("base") or {}).get("ref") != DEFAULT_BRANCH:
        raise Refusal("the recorded pull request is not the merge of the release commit into main")
    head_changed = (pull.get("head") or {}).get("sha") != approval["head_commit"]
    if head_changed or (pull.get("user") or {}).get("id") != approval["pull_request_author_id"]:
        raise Refusal("the recorded pull request's head or author differs from the record")
    if not pull.get("merged_at") or _timestamp(pull["merged_at"]) != _timestamp(approval["merged_at"]):
        raise Refusal("the recorded pull request's merge time differs from the record")


def check_reachable(sha: str, run=subprocess.run) -> None:
    result = run(
        ["git", "merge-base", "--is-ancestor", sha, f"origin/{DEFAULT_BRANCH}"],
        cwd=REPO, capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise Refusal("the commit is not reachable from origin/main")


def _attempt_jobs(api, run_id: str, attempt: str) -> list:
    document = api(f"/repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    jobs = document.get("jobs") if isinstance(document, dict) else None
    if not isinstance(jobs, list) or document.get("total_count") != len(jobs):
        raise Refusal("the publish attempt's jobs cannot be read completely")
    return jobs


def _named_attempt_jobs(jobs: list, name: str, attempt: str) -> list:
    return [j for j in jobs if isinstance(j, dict) and j.get("name") == name and str(j.get("run_attempt")) == attempt]


def _require_gate_jobs(jobs: list, attempt: str, contract: "ReleaseContract") -> None:
    """The one predicate publication and promotion share: each of the contract's gate jobs appears
    exactly once under exactly this attempt, completed and succeeded."""
    for name in contract.publish_gate_jobs:
        found = _named_attempt_jobs(jobs, name, attempt)
        if len(found) != 1 or found[0].get("status") != "completed" or found[0].get("conclusion") != "success":
            raise Refusal("a required gate did not succeed in exactly this publish attempt")


def check_current_publish_attempt(api, env: dict) -> None:
    """In the publish job, before any credential: this run attempt's own preflight and verification
    jobs succeeded in THIS attempt -- the predicate promotion later applies to the attempt a release
    record names. A "re-run failed jobs" attempt whose carried-over gates GitHub lists under an earlier
    attempt is refused here, before anything is pushed, rather than publishing a release whose exact
    attempt promotion would refuse forever."""
    run_id, attempt = env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", "")
    if not POSITIVE_INTEGER.fullmatch(run_id) or not POSITIVE_INTEGER.fullmatch(attempt):
        raise Refusal("this publish run's ID or attempt is missing or malformed")
    contract = RELEASE_CONTRACTS[CURRENT_RELEASE_SCHEMA_VERSION]
    if env.get("GITHUB_WORKFLOW_REF") != contract.workflow_ref:
        raise Refusal("this is not the current contract's publication workflow on main")
    _require_gate_jobs(_attempt_jobs(api, run_id, attempt), attempt, contract)


def verify_publish_attempt(api, publication: dict, commit: str, contract: "ReleaseContract") -> None:
    """The exact artifact-publish run attempt a release names -- never the run's aggregate result.

    That attempt must be this repository's publish workflow, dispatched on main for the release
    commit, completed, with its preflight and every required verification job succeeded, and its
    publication job run -- the jobs as the release record's own contract names them. A later rerun of
    the same run, failed or not, is never consulted, so it cannot invalidate a release already
    published. The publication job itself may have failed after pushing: a later dispatch then resumed
    it, and the immutable release record is the proof that publication completed.
    """
    run_id, attempt = publication["run_id"], publication["run_attempt"]
    document = api(f"/repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}")
    if not isinstance(document, dict):
        raise Refusal("the release's exact publish attempt cannot be read")
    # The workflow the record's own contract names -- never the current module's -- so a later contract
    # that renames the publication workflow cannot reinterpret an earlier record's attempt.
    expected = {
        "id": run_id, "run_attempt": attempt, "path": contract.workflow, "head_sha": commit,
        "head_branch": DEFAULT_BRANCH, "event": "workflow_dispatch", "status": "completed",
    }
    if any(str(document.get(key)) != value for key, value in expected.items()):
        raise Refusal(
            "the release's exact publish attempt is not a completed main dispatch of its contract's publication workflow for its commit"
        )
    if str((document.get("repository") or {}).get("id")) != REPOSITORY_ID:
        raise Refusal("the release's publish attempt ran in another repository")
    jobs = _attempt_jobs(api, run_id, attempt)
    _require_gate_jobs(jobs, attempt, contract)
    publication_jobs = _named_attempt_jobs(jobs, contract.publish_job, attempt)
    if len(publication_jobs) != 1 or publication_jobs[0].get("conclusion") in (None, "skipped"):
        raise Refusal("the release's exact publish attempt never ran its publication job")


# ---------------------------------------------------------------------- inputs and variables


def validate_release_commit(env: dict) -> str:
    commit = env.get("RELEASE_COMMIT", "")
    if not COMMIT.fullmatch(commit):
        raise Refusal("release_commit is not a full 40-hex SHA")
    return commit


def validate_apply_inputs(env: dict) -> dict:
    """The dispatched tuple: the saved plan's key, version and SHA-256, and the release's commit,
    image and record version and SHA-256. Returns them with the source commit the key names."""
    key = env.get("PLAN_KEY", "")
    version_id = env.get("PLAN_VERSION_ID", "")
    sha256 = env.get("PLAN_SHA256", "")
    match = PLAN_KEY.fullmatch(key)
    if not match:
        raise Refusal("plan_key is not plans/staging/<40-hex commit>/<64-hex sha256>.tfplan")
    if not VERSION_ID.fullmatch(version_id) or version_id == "null":
        raise Refusal("plan_version_id is missing or malformed")
    if not SHA256.fullmatch(sha256):
        raise Refusal("plan_sha256 is not 64 lowercase hex digits")
    if match.group("sha256") != sha256:
        raise Refusal("plan_sha256 does not match the SHA-256 in plan_key")
    image = IMAGE_REFERENCE.fullmatch(env.get("RELEASE_IMAGE", ""))
    if not image:
        raise Refusal("release_image is not a full <repository>@sha256:<64 hex> reference; a tag is refused")
    release_commit = validate_release_commit(env)
    record_version = env.get("RELEASE_RECORD_VERSION_ID", "")
    if not VERSION_ID.fullmatch(record_version) or record_version == "null":
        raise Refusal("release_record_version_id is missing or malformed")
    if not SHA256.fullmatch(env.get("RELEASE_RECORD_SHA256", "")):
        raise Refusal("release_record_sha256 is not 64 lowercase hex digits")
    return {
        "source_commit": match.group("commit"),
        "plan_key": key,
        "plan_version_id": version_id,
        "plan_sha256": sha256,
        "release_commit": release_commit,
        "release_image": image.group(0),
        "release_digest": image.group("digest"),
        "release_record_version_id": record_version,
        "release_record_sha256": env["RELEASE_RECORD_SHA256"],
    }


def approved_repository_url(env: dict) -> str:
    """The canonical release repository the environment's configuration names."""
    account = env.get("ARTIFACT_REGISTRY_ACCOUNT_ID", "")
    region = env.get("ARTIFACT_REGISTRY_REGION", "")
    name = env.get("ARTIFACT_REPOSITORY_NAME", "")
    if not ACCOUNT.fullmatch(account):
        raise Refusal("ARTIFACT_REGISTRY_ACCOUNT_ID is not a twelve-digit account ID")
    if not REGION.fullmatch(region):
        raise Refusal("ARTIFACT_REGISTRY_REGION is not a region")
    if not REPOSITORY_NAME.fullmatch(name):
        raise Refusal("ARTIFACT_REPOSITORY_NAME is not a repository name")
    return f"{account}.dkr.ecr.{region}.amazonaws.com/{name}"


def check_environment_variables(env: dict, workflow: str) -> None:
    for name, value in env.items():
        if name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY") and value:
            raise Refusal("a permanent AWS access key is present in the job environment")
    # Each environment holds only its own role: the publisher never sees a deployment role, and
    # neither deployment environment sees the publisher's or the other's.
    for other, variable in ROLE_VARIABLES.items():
        if other != workflow and env.get(variable):
            raise Refusal(f"{variable} is visible to the {ENVIRONMENTS[workflow]} environment; each environment holds only its own role")
    repository_url = approved_repository_url(env)
    registry_account = env["ARTIFACT_REGISTRY_ACCOUNT_ID"]
    registry_region = env["ARTIFACT_REGISTRY_REGION"]
    if not BUCKET.fullmatch(env.get("ARTIFACT_RELEASE_BUCKET", "")):
        raise Refusal("ARTIFACT_RELEASE_BUCKET is not a bucket name")
    if workflow == "publish":
        if env.get("ARTIFACT_PUBLISH_ROLE_ARN") != f"arn:aws:iam::{registry_account}:role/{ROLE_NAMES['publish']}":
            raise Refusal("ARTIFACT_PUBLISH_ROLE_ARN is not the artifact-publish role in the registry account")
        key = env.get("ARTIFACT_RELEASE_KMS_KEY_ARN", "")
        if not re.fullmatch(rf"arn:aws:kms:{re.escape(registry_region)}:{registry_account}:key/[0-9a-f-]{{36}}", key):
            raise Refusal("ARTIFACT_RELEASE_KMS_KEY_ARN is not a KMS key in the registry account and region")
        for name in ("STAGING_STATE_BUCKET", "STAGING_PLAN_BUCKET", "STAGING_TFVARS_JSON"):
            if env.get(name):
                raise Refusal(f"{name} is visible to the artifact-publish environment, which holds no deployment configuration")
        return
    account = env.get("STAGING_AWS_ACCOUNT_ID", "")
    region = env.get("STAGING_AWS_REGION", "")
    if not ACCOUNT.fullmatch(account):
        raise Refusal("STAGING_AWS_ACCOUNT_ID is not a twelve-digit account ID")
    if not REGION.fullmatch(region) or region == "us-east-1":
        raise Refusal("STAGING_AWS_REGION is not a workload region")
    role_variable = ROLE_VARIABLES[workflow]
    if env.get(role_variable) != f"arn:aws:iam::{account}:role/{ROLE_NAMES[workflow]}":
        raise Refusal(f"{role_variable} is not this workflow's own role in the staging account")
    for name in ("STAGING_STATE_BUCKET", "STAGING_PLAN_BUCKET"):
        if not BUCKET.fullmatch(env.get(name, "")):
            raise Refusal(f"{name} is not a bucket name")
    if env["STAGING_STATE_BUCKET"] == env["STAGING_PLAN_BUCKET"]:
        raise Refusal("the state and plan buckets are the same bucket")
    for name in ("STAGING_STATE_KMS_KEY_ARN", "STAGING_PLAN_KMS_KEY_ARN"):
        if not re.fullmatch(rf"arn:aws:kms:{re.escape(region)}:{account}:key/[0-9a-f-]{{36}}", env.get(name, "")):
            raise Refusal(f"{name} is not a KMS key in the staging account and region")
    if workflow == "plan":
        # The plan-time variables are the Terraform inputs that declare the registry again; any
        # disagreement with the environment's declaration refuses here, before the OIDC token.
        staging_tfvars(env)
    if workflow == "apply":
        hours = env.get("STAGING_MAX_PLAN_AGE_HOURS", "")
        if not re.fullmatch(r"[0-9]{1,2}", hours) or not 1 <= int(hours) <= 24:
            raise Refusal("STAGING_MAX_PLAN_AGE_HOURS must be a whole number of hours from 1 to 24")
        match = IMAGE_REFERENCE.fullmatch(env.get("RELEASE_IMAGE", ""))
        if not match or match.group("repository") != repository_url:
            raise Refusal("release_image is not a digest in the approved release repository")


# The canonical registry is declared once, by a human, and every place that names it must agree:
# the environment's ARTIFACT_REGISTRY_* variables, the staging root's release_registry_* inputs, the
# release record's repository and the verified image. Nothing here derives it from the staging account
# or region; a registry in a dedicated artifact account passes unchanged when every place names it.
REGISTRY_DECLARATION = (
    ("release_registry_account_id", "ARTIFACT_REGISTRY_ACCOUNT_ID"),
    ("release_registry_region", "ARTIFACT_REGISTRY_REGION"),
    ("release_repository_name", "ARTIFACT_REPOSITORY_NAME"),
)


def staging_tfvars(env: dict) -> dict:
    """STAGING_TFVARS_JSON, refused unless it names the environment's staging account and region and
    exactly the declared canonical registry, sets no image and no secret-like key, and passes the
    independent reviewer allow-list check. Run before any credential and again when the file is written."""
    try:
        document = json.loads(env.get("STAGING_TFVARS_JSON", ""))
    except ValueError:
        raise Refusal("STAGING_TFVARS_JSON is not JSON") from None
    if not isinstance(document, dict) or not document:
        raise Refusal("STAGING_TFVARS_JSON is not a JSON object")
    if document.get("expected_account_id") != env.get("STAGING_AWS_ACCOUNT_ID"):
        raise Refusal("expected_account_id differs from STAGING_AWS_ACCOUNT_ID")
    if document.get("region") != env.get("STAGING_AWS_REGION"):
        raise Refusal("region differs from STAGING_AWS_REGION")
    if any(re.search(r"password|secret|token|credential|private_key", key, re.I) for key in document):
        raise Refusal("the staging variables name a secret-like key; secrets never travel as Terraform variables")
    # The image comes from the verified release record, never from environment configuration.
    for forbidden in ("release_image", "image_digest"):
        if forbidden in document:
            raise Refusal(f"the staging variables set {forbidden}; the image comes only from the verified release record")
    approved_repository_url(env)
    for key, variable in REGISTRY_DECLARATION:
        if document.get(key) != env.get(variable):
            raise Refusal(f"{key} differs from {variable}; the Terraform inputs and the declared registry disagree")
    sys.path.insert(0, str(REPO / "infra" / "terraform"))
    from policy import cidr_allowlist  # noqa: E402

    findings = cidr_allowlist.validate_tfvars(document)
    if findings:
        raise Refusal("the reviewer allow-list is refused: " + "; ".join(findings))
    return document


def write_tfvars(env: dict, out: pathlib.Path) -> None:
    document = staging_tfvars(env)
    image = IMAGE_REFERENCE.fullmatch(env.get("RELEASE_IMAGE", ""))
    if not image:
        raise Refusal("no verified release image reference is available; a tag is never accepted")
    if image.group("repository") != approved_repository_url(env):
        raise Refusal("the verified release image is not in the approved release repository")
    document["release_image"] = image.group(0)
    _write_private(out, json.dumps(document).encode("utf-8"))


# ---------------------------------------------------------------------- build once: inputs and provenance


def dockerfile_base_images(text: str) -> list[str]:
    """Every base image, each pinned by digest. A build argument of any kind is refused: a release
    is built once, identically for every environment, from the committed inputs alone."""
    joined = re.sub(r"\\\n", " ", text)
    images = []
    for raw in joined.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        instruction = line.split(None, 1)[0].upper()
        if instruction == "ARG":
            raise Refusal("the Dockerfile declares a build argument; a release build takes none")
        if instruction == "FROM":
            if "$" in line:
                raise Refusal("a FROM line is parameterised")
            words = [word for word in line.split()[1:] if not word.startswith("--")]
            if not words or not PINNED_BASE_IMAGE.fullmatch(words[0]):
                raise Refusal("a base image is not pinned by digest")
            images.append(words[0])
    if not images:
        raise Refusal("the Dockerfile has no base image")
    return sorted(set(images))


def read_provenance(labels, commit: str) -> dict:
    """The provenance a release image carries, required to be exactly this commit's release.

    Anything else -- another repository, commit, workflow or provenance schema -- is incompatible
    provenance under git-<commit>, and publication stops for explicit human recovery.
    """
    if not isinstance(labels, dict):
        raise Refusal("the image carries no provenance labels; explicit human recovery is required")
    fixed = {
        LABEL_SOURCE: SOURCE_URL,
        LABEL_REVISION: commit,
        LABEL_PROVENANCE: PROVENANCE_SCHEMA,
        LABEL_REPOSITORY_ID: REPOSITORY_ID,
        LABEL_WORKFLOW_REF: PUBLISH_WORKFLOW_REF,
    }
    if not COMMIT.fullmatch(commit or "") or any(labels.get(label) != value for label, value in fixed.items()):
        raise Refusal("the image's provenance is not this commit's release; explicit human recovery is required")
    run_id, attempt, created = labels.get(LABEL_RUN_ID), labels.get(LABEL_RUN_ATTEMPT), labels.get(LABEL_CREATED)
    if not all(isinstance(v, str) for v in (run_id, attempt, created)):
        raise Refusal("the image's provenance names no run, attempt or build time; explicit human recovery is required")
    if not POSITIVE_INTEGER.fullmatch(run_id) or not POSITIVE_INTEGER.fullmatch(attempt) or not LABEL_TIMESTAMP.fullmatch(created):
        raise Refusal("the image's provenance run, attempt or build time is malformed; explicit human recovery is required")
    return {"run_id": run_id, "run_attempt": attempt, "created": created}


def build_inputs(contract: ReleaseContract) -> dict:
    dockerfile = REPO / "Dockerfile"
    return {
        "dockerfile_sha256": sha256_file(dockerfile),
        "dependency_locks": {path: sha256_file(REPO / path) for path in contract.lock_files},
        "base_images": dockerfile_base_images(dockerfile.read_text(encoding="utf-8")),
        "build_arguments": [],
    }


def _check_spdx(data: bytes) -> None:
    document = _json(data, "the SBOM")
    if not isinstance(document, dict) or not str(document.get("spdxVersion", "")).startswith("SPDX-"):
        raise Refusal("the SBOM is not an SPDX JSON document")


DRAFT_SCHEMA = "firmbatch.release-draft"
DRAFT_KEYS = frozenset({"schema", "commit", "approval", "provenance", "local_config_digest", "sbom_sha256", "build"})
# The configuration digest BuildKit records for the image it built (docker build --metadata-file).
BUILD_CONFIG_DIGEST = "containerimage.config.digest"


def release_draft(image_inspect, sbom: bytes, env: dict, build_metadata) -> dict:
    """Everything publication needs that exists before any credential: the built image, inspected
    locally, with this attempt's provenance; its SBOM; the approval; the committed build inputs.

    The SBOM is later stored under the image's configuration digest and read back under the digest the
    registry's manifest names, so the digest recorded here must be the configuration digest. An image
    store that reports a manifest digest as the image ID -- Docker's containerd image store, which also
    reports a manifest descriptor -- would store the SBOM where no resumed publication looks for it, and
    only after an irreversible push. So the local ID must equal the configuration digest the build
    itself recorded, and a store reporting a descriptor is refused, both here, before any credential."""
    commit = env.get("SOURCE_COMMIT", "")
    if not COMMIT.fullmatch(commit) or commit != env.get("GITHUB_SHA"):
        raise Refusal("the source commit is not the dispatched commit")
    if env.get("GITHUB_WORKFLOW_REF") != PUBLISH_WORKFLOW_REF:
        raise Refusal("this is not the artifact-publish workflow on main")
    built = build_metadata.get(BUILD_CONFIG_DIGEST) if isinstance(build_metadata, dict) else None
    if not isinstance(built, str) or not DIGEST.fullmatch(built):
        raise Refusal("the build recorded no image configuration digest (containerimage.config.digest); refusing before any credential")
    if not isinstance(image_inspect, list) or len(image_inspect) != 1 or not isinstance(image_inspect[0], dict):
        raise Refusal("the local image could not be inspected as exactly one image")
    image = image_inspect[0]
    if image.get("Descriptor") is not None:
        raise Refusal(
            "the local image store reports a manifest descriptor, so its image ID is a manifest digest rather than the "
            "configuration digest the SBOM is addressed by; refusing before any credential"
        )
    if not DIGEST.fullmatch(image.get("Id") or "") or image["Id"] != built:
        raise Refusal("the local image ID is not the configuration digest the build recorded; refusing before any credential")
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64" or image.get("Variant"):
        raise Refusal("the local image is not a single linux/amd64 image")
    if image.get("RepoDigests"):
        raise Refusal("the local image already carries a registry digest; the build is not this attempt's own")
    provenance = read_provenance((image.get("Config") or {}).get("Labels"), commit)
    if provenance["run_id"] != env.get("GITHUB_RUN_ID") or provenance["run_attempt"] != env.get("GITHUB_RUN_ATTEMPT"):
        raise Refusal("the local image's provenance names another run or attempt")
    _check_spdx(sbom)
    contract = RELEASE_CONTRACTS[CURRENT_RELEASE_SCHEMA_VERSION]
    approval = check_recorded_approval(_json(env.get("APPROVAL_EVIDENCE", ""), "the approval evidence"), commit, contract)
    return {
        "schema": DRAFT_SCHEMA,
        "commit": commit,
        "approval": approval,
        "provenance": provenance,
        "local_config_digest": built,
        "sbom_sha256": sha256_bytes(sbom),
        "build": build_inputs(contract),
    }


def check_draft(draft) -> dict:
    if not isinstance(draft, dict) or set(draft) != DRAFT_KEYS or draft.get("schema") != DRAFT_SCHEMA:
        raise Refusal("the release draft is malformed")
    check_recorded_approval(draft["approval"], draft["commit"], RELEASE_CONTRACTS[CURRENT_RELEASE_SCHEMA_VERSION])
    if not DIGEST.fullmatch(draft["local_config_digest"] or "") or not SHA256.fullmatch(draft["sbom_sha256"] or ""):
        raise Refusal("the release draft's digests are malformed")
    if not isinstance(draft["provenance"], dict) or set(draft["provenance"]) != {"run_id", "run_attempt", "created"}:
        raise Refusal("the release draft's provenance is malformed")
    return draft


# ---------------------------------------------------------------------- resumable publication


def _single_image(images_doc, repository_url: str, digest: str | None = None) -> dict:
    details = (images_doc or {}).get("imageDetails") if isinstance(images_doc, dict) else None
    if not isinstance(details, list) or not details:
        raise Refusal("the registry holds no such image: it was never pushed or is not retained")
    if len(details) != 1:
        raise Refusal("the registry answered with more than one image")
    image = details[0]
    location = REPOSITORY_URL.fullmatch(repository_url or "")
    if not location or image.get("registryId") != location.group("account") or image.get("repositoryName") != location.group("name"):
        raise Refusal("the image is not in the approved release repository")
    if not DIGEST.fullmatch(image.get("imageDigest") or "") or (digest is not None and image["imageDigest"] != digest):
        raise Refusal("the image's digest is not the release digest")
    if image.get("imageManifestMediaType") not in IMAGE_MANIFEST_MEDIA_TYPES:
        raise Refusal("the release digest is not a single-image manifest")
    return image


def publication_mode(draft: dict, repository_url: str, tag_doc) -> str:
    """'fresh' when git-<commit> does not exist yet; 'resume' when an earlier attempt pushed it."""
    if not isinstance(tag_doc, dict) or tag_doc.get("imageDetails") == []:
        if tag_doc == {"imageDetails": []}:
            return "fresh"
        raise Refusal("the registry's answer for git-<commit> is malformed")
    image = _single_image(tag_doc, repository_url)
    if image.get("imageTags") != [f"git-{draft['commit']}"]:
        raise Refusal("git-<commit> exists alongside another tag; explicit human recovery is required")
    return "resume"


def tag_digest(draft: dict, repository_url: str, tag_doc) -> str:
    """The digest git-<commit> names, which must now exist carrying that one tag and no other."""
    image = _single_image(tag_doc, repository_url)
    if image.get("imageTags") != [f"git-{draft['commit']}"]:
        raise Refusal("git-<commit> does not carry exactly its one tag; explicit human recovery is required")
    return image["imageDigest"]


def sbom_key(commit: str, config_digest: str) -> str:
    """One SBOM per built image, addressed by the image's configuration digest, which carries the
    attempt's provenance: an attempt that fails before pushing leaves an SBOM no record names, and
    never an object a later attempt would have to overwrite."""
    if not COMMIT.fullmatch(commit or "") or not DIGEST.fullmatch(config_digest or ""):
        raise Refusal("the commit or configuration digest is malformed")
    return f"releases/{commit}/sbom-{config_digest.split(':', 1)[1]}.spdx.json"


def record_key(commit: str) -> str:
    return f"releases/{commit}/release-manifest.json"


def object_metadata(kind: str, commit: str, digest: str, body: bytes) -> dict:
    """The object metadata that fixes a release object's semantic identity: what it is, for which
    commit, bound to which digest, and its full SHA-256. S3 stores it with the object, immutably."""
    if kind not in ("sbom", "record") or not COMMIT.fullmatch(commit or "") or not DIGEST.fullmatch(digest or ""):
        raise Refusal("the object's kind, commit or digest is malformed")
    return {
        "firmbatch-kind": kind,
        "firmbatch-commit": commit,
        "firmbatch-digest": digest,
        "firmbatch-sha256": sha256_bytes(body),
    }


def _check_object_head(head, metadata: dict) -> None:
    if not isinstance(head, dict) or head.get("DeleteMarker"):
        raise Refusal("the release object's metadata could not be read")
    if head.get("ServerSideEncryption") != "aws:kms":
        raise Refusal("the release object is not KMS-encrypted")
    if head.get("Metadata") != metadata:
        raise Refusal("the release object's semantic identity is not this release's")


def _manifest(manifest_doc, digest: str, media_type: str) -> dict:
    images = manifest_doc.get("images") if isinstance(manifest_doc, dict) else None
    if not isinstance(images, list) or len(images) != 1 or manifest_doc.get("failures"):
        raise Refusal("the registry did not return exactly the release image's manifest")
    entry = images[0]
    if (entry.get("imageId") or {}).get("imageDigest") != digest:
        raise Refusal("the registry returned another image's manifest")
    raw = entry.get("imageManifest")
    if not isinstance(raw, str) or "sha256:" + sha256_bytes(raw.encode("utf-8")) != digest:
        raise Refusal("the manifest's own SHA-256 is not the release digest")
    manifest = _json(raw, "the image manifest")
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
        raise Refusal("the image manifest is not a schema-2 manifest")
    if manifest.get("mediaType", entry.get("imageManifestMediaType")) != media_type:
        raise Refusal("the image manifest's media type is not the registry's")
    config = manifest.get("config")
    if (
        not isinstance(config, dict) or config.get("mediaType") != IMAGE_MANIFEST_MEDIA_TYPES[media_type]
        or not DIGEST.fullmatch(config.get("digest") or "")
    ):
        raise Refusal("the image manifest names no single-image configuration")
    if not isinstance(manifest.get("layers"), list) or not manifest["layers"]:
        raise Refusal("the image manifest has no layers")
    return manifest


def image_config_digest(repository_url: str, images_doc, manifest_doc) -> str:
    image = _single_image(images_doc, repository_url)
    return _manifest(manifest_doc, image["imageDigest"], image["imageManifestMediaType"])["config"]["digest"]


def registry_identity(draft: dict, mode: str, repository_url: str, images_doc, manifest_doc, config_blob: bytes,
                      local_repo_digest: str | None) -> dict:
    """What git-<commit> is in the registry, proven from the registry's own bytes.

    The manifest hashes to the digest; the configuration blob hashes to the digest the manifest
    names; its labels carry the provenance. A fresh publication must find exactly the image this
    attempt built and pushed. A resumed one accepts the provenance of the attempt that pushed it --
    and refuses, for human recovery, anything not this commit's release.
    """
    commit = check_draft(draft)["commit"]
    image = _single_image(images_doc, repository_url)
    if image.get("imageTags") != [f"git-{commit}"]:
        raise Refusal("git-<commit> carries another tag; explicit human recovery is required")
    digest, media_type = image["imageDigest"], image["imageManifestMediaType"]
    manifest = _manifest(manifest_doc, digest, media_type)
    config_digest = manifest["config"]["digest"]
    if "sha256:" + sha256_bytes(config_blob) != config_digest:
        raise Refusal("the configuration blob's SHA-256 is not the digest its manifest names")
    config = _json(config_blob, "the image configuration")
    if not isinstance(config, dict) or config.get("os") != "linux" or config.get("architecture") != "amd64":
        raise Refusal("the release image is not a linux/amd64 image")
    provenance = read_provenance((config.get("config") or {}).get("Labels"), commit)
    if mode == "fresh":
        if local_repo_digest != f"{repository_url}@{digest}":
            raise Refusal("the digest the registry holds is not the digest this attempt's push produced")
        if config_digest != draft["local_config_digest"] or provenance != draft["provenance"]:
            raise Refusal("git-<commit> is not the image this attempt built; explicit human recovery is required")
    elif mode != "resume":
        raise Refusal("the publication mode is neither fresh nor resume")
    return {
        "schema": "firmbatch.release-identity",
        "commit": commit,
        "repository": repository_url,
        "digest": digest,
        "media_type": media_type,
        "config_digest": config_digest,
        "provenance": provenance,
    }


def check_sbom_object(commit: str, config_digest: str, body: bytes, head) -> str:
    _check_object_head(head, object_metadata("sbom", commit, config_digest, body))
    _check_spdx(body)
    return sha256_bytes(body)


def build_release_record(draft: dict, identity: dict, sbom_body: bytes, sbom_head) -> dict:
    """The release record, a deterministic function of the pushed image and the committed inputs.

    Every authority-bearing field -- digest, provenance, approval, inputs, the SBOM's key and digest --
    comes from the registry, the stored SBOM or the commit, never from the attempt that happens to
    write it, so a retry regenerates exactly the same bytes.
    """
    commit = check_draft(draft)["commit"]
    if not isinstance(identity, dict) or identity.get("commit") != commit:
        raise Refusal("the registry identity is for another commit")
    config_digest = identity["config_digest"]
    sbom_sha = check_sbom_object(commit, config_digest, sbom_body, sbom_head)
    contract = RELEASE_CONTRACTS[CURRENT_RELEASE_SCHEMA_VERSION]
    artifact = contract.artifacts[0]
    record = {
        "schema": RELEASE_RECORD_SCHEMA,
        "schema_version": contract.version,
        "source": {"repository": REPOSITORY, "repository_id": REPOSITORY_ID, "ref": f"refs/heads/{DEFAULT_BRANCH}", "commit": commit},
        "approval": draft["approval"],
        "publication": {
            "workflow": contract.workflow,
            "workflow_ref": contract.workflow_ref,
            "run_id": identity["provenance"]["run_id"],
            "run_attempt": identity["provenance"]["run_attempt"],
            "image_created": identity["provenance"]["created"],
        },
        "artifacts": {
            artifact: {
                "repository": identity["repository"],
                "tag": f"git-{commit}",
                "digest": identity["digest"],
                "image": f"{identity['repository']}@{identity['digest']}",
                "media_type": identity["media_type"],
                "config_digest": config_digest,
            },
        },
        "components": {component: artifact for component in contract.components},
        "build": draft["build"],
        "sbom": {"key": sbom_key(commit, config_digest), "format": "spdx-json", "sha256": sbom_sha},
        "scan": {"status": "pending"},
        "signatures": [],
    }
    check_release_record(record, commit)
    return record


def record_bytes(record: dict) -> bytes:
    return (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")


def compare_release_object(kind: str, commit: str, digest: str, expected: bytes, existing: bytes, head) -> None:
    """After a 412 or an uncertain write: the object at the key must be byte-for-byte, and by its
    stored semantic identity, the object this release produces. Otherwise publication fails closed."""
    if sha256_bytes(existing) != sha256_bytes(expected):
        raise Refusal("an object already exists at this key and is not byte-for-byte this release's; explicit human recovery is required")
    _check_object_head(head, object_metadata(kind, commit, digest, expected))
    if kind == "record":
        stored = _json(existing, "the stored release record")
        image = check_release_record(stored, commit)
        if IMAGE_REFERENCE.fullmatch(image).group("digest") != digest:
            raise Refusal("the stored release record names another digest; explicit human recovery is required")
    else:
        _check_spdx(existing)


# ---------------------------------------------------------------------- versioned release records

RELEASE_RECORD_SCHEMA = "firmbatch.release-record"
RECORD_KEYS = frozenset({
    "schema", "schema_version", "source", "approval", "publication", "artifacts", "components", "build", "sbom", "scan",
    "signatures",
})


@dataclasses.dataclass(frozen=True)
class ReleaseContract:
    """The immutable historical contract a release record of one schema version binds, frozen with it.

    Its component set, required lock files and publishing workflow identity; the names of the gate and
    publication jobs its exact publish attempt must show; and the approval rules its frozen approval is
    validated by. A later component (the M6 GPU worker, say), lock file, renamed publication workflow,
    renamed CI job or changed approval rule is a NEW version beside this one. A record is verified under
    the contract of the version it declares -- its own workflow path, job names and approval rules -- so
    a later version neither invalidates it nor reinterprets it, and rollback to it stays possible; an
    unknown version is refused. A version is retired only by removing its entry here, in a reviewed
    change recording the compatibility decision (ADR 0012 decision 13, "Versioned contracts").

    What a contract never holds is the live security overlay -- security stops, digest-scoped exceptions
    and their expiry, the admission maxima -- which promotion and apply read from origin/main when they
    run (security_overlay_from_main), beside the contract and independently of it.
    """

    version: int
    components: tuple[str, ...]
    artifacts: tuple[str, ...]
    lock_files: tuple[str, ...]
    workflow: str
    workflow_ref: str
    publish_gate_jobs: tuple[str, ...]
    publish_job: str
    approval_keys: frozenset
    qualifying_associations: tuple[str, ...]
    write_permissions: tuple[str, ...]
    validator: Callable[[dict, str, "ReleaseContract"], str]


def _check_release_record_v1(record: dict, commit: str, contract: ReleaseContract) -> str:
    if set(record) != RECORD_KEYS or record.get("schema") != RELEASE_RECORD_SCHEMA:
        raise Refusal("the release record holds keys outside its schema")
    expected_source = {"repository": REPOSITORY, "repository_id": REPOSITORY_ID, "ref": f"refs/heads/{DEFAULT_BRANCH}", "commit": commit}
    if not COMMIT.fullmatch(commit or "") or record["source"] != expected_source:
        raise Refusal("the release record names another repository, ref or commit")
    check_recorded_approval(record["approval"], commit, contract)
    publication = record["publication"]
    if not isinstance(publication, dict) or set(publication) != {"workflow", "workflow_ref", "run_id", "run_attempt", "image_created"}:
        raise Refusal("the release record's publication holds keys outside its schema")
    if publication["workflow"] != contract.workflow or publication["workflow_ref"] != contract.workflow_ref:
        raise Refusal("the release was not published by the artifact-publish workflow on main")
    if not all(isinstance(publication[k], str) and POSITIVE_INTEGER.fullmatch(publication[k]) for k in ("run_id", "run_attempt")):
        raise Refusal("the release record's publish run or attempt is malformed")
    if not isinstance(publication["image_created"], str) or not LABEL_TIMESTAMP.fullmatch(publication["image_created"]):
        raise Refusal("the release record's build time is malformed")
    artifacts = record["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != set(contract.artifacts):
        raise Refusal("the release record names artifacts outside its contract")
    for artifact in artifacts.values():
        if not isinstance(artifact, dict) or set(artifact) != {"repository", "tag", "digest", "image", "media_type", "config_digest"}:
            raise Refusal("a release artifact holds keys outside its schema")
        if not REPOSITORY_URL.fullmatch(artifact["repository"] or "") or not DIGEST.fullmatch(artifact["digest"] or ""):
            raise Refusal("a release artifact's repository or digest is malformed")
        if artifact["tag"] != f"git-{commit}" or artifact["image"] != f"{artifact['repository']}@{artifact['digest']}":
            raise Refusal("a release artifact's tag or image reference does not match its commit and digest")
        if artifact["media_type"] not in IMAGE_MANIFEST_MEDIA_TYPES or not DIGEST.fullmatch(artifact["config_digest"] or ""):
            raise Refusal("a release artifact is not a single-image manifest with a configuration digest")
    components = record["components"]
    if not isinstance(components, dict) or set(components) != set(contract.components) or not set(components.values()) <= set(artifacts):
        raise Refusal("the release record does not map exactly its contract's components to its artifacts")
    build = record["build"]
    if not isinstance(build, dict) or set(build) != {"dockerfile_sha256", "dependency_locks", "base_images", "build_arguments"}:
        raise Refusal("the release record's build section holds keys outside its schema")
    locks = build["dependency_locks"]
    locks_bound = (
        isinstance(locks, dict) and set(locks) == set(contract.lock_files) and all(SHA256.fullmatch(v or "") for v in locks.values())
    )
    if not SHA256.fullmatch(build["dockerfile_sha256"] or "") or not locks_bound:
        raise Refusal("the release record does not bind its contract's Dockerfile and dependency-lock digests")
    bases = build["base_images"]
    if not isinstance(bases, list) or not bases or not all(isinstance(b, str) and PINNED_BASE_IMAGE.fullmatch(b) for b in bases):
        raise Refusal("the release record does not bind base-image digests")
    if build["build_arguments"] != []:
        raise Refusal("a release is built with no build argument")
    primary = artifacts[components["web_api"]]
    expected_sbom = {"key": sbom_key(commit, primary["config_digest"]), "format": "spdx-json"}
    sbom = record["sbom"]
    if not isinstance(sbom, dict) or set(sbom) != {"key", "format", "sha256"} or {k: sbom[k] for k in ("key", "format")} != expected_sbom:
        raise Refusal("the release record does not reference its image's SBOM")
    if not SHA256.fullmatch(sbom["sha256"] or ""):
        raise Refusal("the release record's SBOM digest is malformed")
    if record["scan"] != {"status": "pending"}:
        raise Refusal("the release record's scan status is malformed")
    if not isinstance(record["signatures"], list):
        raise Refusal("the release record's signatures are malformed")
    return primary["image"]


RELEASE_CONTRACTS: dict[int, ReleaseContract] = {
    1: ReleaseContract(
        version=1,
        components=("web_api", "identity_broker", "migrate", "bootstrap", "identity_binding"),
        artifacts=("control-plane",),
        lock_files=("requirements-v1-lock.txt", "portal/package-lock.json"),
        workflow=PUBLISH_WORKFLOW,
        workflow_ref=PUBLISH_WORKFLOW_REF,
        # The jobs of one artifact-publish attempt, as GitHub names them. The gates must have succeeded
        # in exactly the attempt a release names; the publication job must have run in it.
        publish_gate_jobs=(
            "Preflight (no environment, no AWS)",
            "Full required verification (ci.yml, reused unchanged) / locks",
            "Full required verification (ci.yml, reused unchanged) / verify",
            "Full required verification (ci.yml, reused unchanged) / container",
        ),
        publish_job="Build once, publish or resume one immutable release (artifact-publish)",
        approval_keys=frozenset({
            "pull_request", "pull_request_author_id", "pull_request_author_login", "head_commit", "merge_commit", "merged_at",
            "approver_id", "approver_login", "review_id", "review_submitted_at", "review_commit", "reviewer_association",
            "reviewer_permission",
        }),
        # The association the review reports between the reviewing account and the repository. It is not
        # proof of write access -- a member or collaborator can hold read access -- which the permission
        # read at approval time establishes instead (approval_evidence).
        qualifying_associations=("OWNER", "MEMBER", "COLLABORATOR"),
        write_permissions=("admin", "maintain", "write"),
        validator=_check_release_record_v1,
    ),
}
CURRENT_RELEASE_SCHEMA_VERSION = 1


def release_contract(record) -> ReleaseContract:
    """The contract of the schema version a record declares. An unknown version is refused, never guessed."""
    if not isinstance(record, dict):
        raise Refusal("the release record is missing")
    version = record.get("schema_version")
    contract = RELEASE_CONTRACTS.get(version) if isinstance(version, int) and not isinstance(version, bool) else None
    if contract is None:
        raise Refusal("the release record declares an unknown or retired schema version")
    return contract


def check_release_record(record, commit: str) -> str:
    """Validate a release record under the contract of the schema version it declares, and return
    the one image reference it deploys."""
    contract = release_contract(record)
    return contract.validator(record, commit, contract)


# ---------------------------------------------------------------------- admission

ADMISSION_POLICY_KEYS = frozenset({"schema_version", "purpose", "require_scan_status", "maximum_findings", "exceptions", "security_stops"})
EXCEPTION_KEYS = frozenset({"image_digest", "vulnerability_ids", "reason", "approver", "approval_reference", "created_at", "expires_at"})
SECURITY_STOP_KEYS = frozenset({"image_digest", "release_commit", "reason", "reference", "created_at"})
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNDEFINED")


def check_admission_policy(policy, now: dt.datetime) -> dict:
    """The committed admission policy, whole. One malformed or overly broad entry refuses every
    admission: an exception is exact digests and exact vulnerability IDs, reviewed, and short-lived."""
    if not isinstance(policy, dict) or set(policy) != ADMISSION_POLICY_KEYS or policy.get("schema_version") != 2:
        raise Refusal("the admission policy is missing or has an unknown schema")
    if policy["require_scan_status"] != "COMPLETE":
        raise Refusal("the admission policy does not require a complete scan")
    maxima = policy["maximum_findings"]
    if not isinstance(maxima, dict) or not {"CRITICAL", "HIGH"} <= set(maxima) or not set(maxima) <= set(SEVERITIES):
        raise Refusal("the admission policy's finding maxima are malformed")
    if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in maxima.values()):
        raise Refusal("the admission policy's finding maxima are malformed")
    exceptions = policy["exceptions"]
    if not isinstance(exceptions, list):
        raise Refusal("the admission policy's exceptions are malformed")
    for entry in exceptions:
        if not isinstance(entry, dict) or set(entry) != EXCEPTION_KEYS:
            raise Refusal("an admission exception holds keys outside its schema")
        if not DIGEST.fullmatch(entry["image_digest"] or ""):
            raise Refusal("an admission exception names no exact image digest")
        ids = entry["vulnerability_ids"]
        if not isinstance(ids, list) or not ids or len(ids) > MAX_EXCEPTION_IDS or len(set(ids)) != len(ids):
            raise Refusal("an admission exception names no, too many or repeated vulnerability identifiers")
        if not all(isinstance(i, str) and VULNERABILITY_ID.fullmatch(i) for i in ids):
            raise Refusal("an admission exception names a vulnerability identifier that is not exact")
        if not isinstance(entry["reason"], str) or not 20 <= len(entry["reason"].strip()) <= 1000:
            raise Refusal("an admission exception gives no reason")
        approver = entry["approver"]
        approver_named = isinstance(approver, dict) and set(approver) == {"login", "id"}
        if not approver_named or not LOGIN.fullmatch(str(approver["login"])) or not _positive_int(approver["id"]):
            raise Refusal("an admission exception names no approver")
        if not PULL_REQUEST_URL.fullmatch(entry["approval_reference"] or ""):
            raise Refusal("an admission exception cites no reviewed pull request")
        created, expires = _timestamp(entry["created_at"]), _timestamp(entry["expires_at"])
        if not created < expires or expires - created > MAX_EXCEPTION_LIFETIME or created > now:
            raise Refusal("an admission exception has no short, explicit, already-started lifetime")
    stops = policy["security_stops"]
    if not isinstance(stops, list):
        raise Refusal("the admission policy's security stops are malformed")
    for stop in stops:
        if not isinstance(stop, dict) or set(stop) != SECURITY_STOP_KEYS:
            raise Refusal("a security stop holds keys outside its schema")
        if not DIGEST.fullmatch(stop["image_digest"] or "") or not COMMIT.fullmatch(stop["release_commit"] or ""):
            raise Refusal("a security stop names no exact digest and commit")
        if not isinstance(stop["reason"], str) or not stop["reason"].strip() or not PULL_REQUEST_URL.fullmatch(stop["reference"] or ""):
            raise Refusal("a security stop gives no reason or reviewed reference")
        _timestamp(stop["created_at"])
    return policy


def _scan_findings(scan_doc) -> list[tuple[str, str]]:
    findings_doc = scan_doc.get("imageScanFindings") if isinstance(scan_doc, dict) else None
    if not isinstance(findings_doc, dict):
        raise Refusal("the scan result carries no findings section")
    basic = findings_doc.get("findings", [])
    enhanced = findings_doc.get("enhancedFindings", [])
    if not isinstance(basic, list) or not isinstance(enhanced, list):
        raise Refusal("the scan findings are malformed")
    found = []
    for finding in basic:
        name, severity = (finding or {}).get("name"), (finding or {}).get("severity")
        if not isinstance(name, str) or severity not in SEVERITIES:
            raise Refusal("a scan finding is malformed")
        found.append((name, severity))
    for finding in enhanced:
        vid = ((finding or {}).get("packageVulnerabilityDetails") or {}).get("vulnerabilityId")
        severity = (finding or {}).get("severity")
        if not isinstance(vid, str) or severity not in SEVERITIES:
            raise Refusal("a scan finding is malformed")
        found.append((vid, severity))
    counts = findings_doc.get("findingSeverityCounts", {})
    if not isinstance(counts, dict) or not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in counts.values()):
        raise Refusal("the scan's severity counts are malformed")
    listed = collections.Counter(severity for _, severity in found)
    if {k: v for k, v in counts.items() if v} != dict(listed):
        raise Refusal("the scan's severity counts and its listed findings disagree, so a finding could be hidden")
    return found


def check_admission(policy, digest: str, commit: str, scan_doc, now: dt.datetime) -> None:
    """Admit the exact digest: no security stop, a complete scan of exactly that digest, and no more
    findings per severity than the maxima once unexpired exceptions for that digest are applied."""
    check_admission_policy(policy, now)
    for stop in policy["security_stops"]:
        if stop["image_digest"] == digest or stop["release_commit"] == commit:
            raise Refusal("a security stop refuses this release")
    if (scan_doc.get("imageId") or {}).get("imageDigest") != digest if isinstance(scan_doc, dict) else True:
        raise Refusal("the scan result is not for the release digest")
    if (scan_doc.get("imageScanStatus") or {}).get("status") != policy["require_scan_status"]:
        raise Refusal("the release image's scan is not complete")
    exempt = {
        vid for entry in policy["exceptions"]
        if entry["image_digest"] == digest and _timestamp(entry["created_at"]) <= now < _timestamp(entry["expires_at"])
        for vid in entry["vulnerability_ids"]
    }
    remaining = collections.Counter(severity for vid, severity in _scan_findings(scan_doc) if vid not in exempt)
    for severity, maximum in policy["maximum_findings"].items():
        if remaining.get(severity, 0) > maximum:
            raise Refusal(f"the release image exceeds the admission policy's {severity} findings")


def check_release_image(image: str, commit: str, repository_doc, images_doc, scan_doc, policy, now: dt.datetime) -> None:
    """The recorded digest exists, immutably, in the approved repository, and passes admission.

    Resolved by digest, never by tag; the one tag it carries must be exactly git-<commit>, so it
    did not arrive through a mutable or environment tag. Rollback runs the same check against an
    earlier record: a digest that is no longer retained is refused, never rebuilt.
    """
    match = IMAGE_REFERENCE.fullmatch(image or "")
    if not match:
        raise Refusal("the release image is not a digest-qualified reference")
    repositories = (repository_doc or {}).get("repositories") if isinstance(repository_doc, dict) else None
    if not isinstance(repositories, list) or len(repositories) != 1:
        raise Refusal("the approved release repository could not be described")
    repository = repositories[0]
    if repository.get("repositoryUri") != match.group("repository"):
        raise Refusal("the release image is not in the approved release repository")
    if repository.get("imageTagMutability") != "IMMUTABLE" or repository.get("imageTagMutabilityExclusionFilters"):
        raise Refusal("the release repository's tags are not immutable without exception")
    if (repository.get("encryptionConfiguration") or {}).get("encryptionType") != "KMS":
        raise Refusal("the release repository is not KMS-encrypted")
    if (repository.get("imageScanningConfiguration") or {}).get("scanOnPush") is not True:
        raise Refusal("the release repository does not scan on push")
    detail = _single_image(images_doc, match.group("repository"), match.group("digest"))
    if detail.get("imageTags") != [f"git-{commit}"]:
        raise Refusal("the release digest carries a tag other than exactly git-<commit>")
    check_admission(policy, match.group("digest"), commit, scan_doc, now)


def verify_release(*, api, env: dict, record_data: bytes, record_head, commit: str, repository_doc, images_doc, scan_doc,
                   policy, now: dt.datetime, expected_version_id: str | None = None, expected_sha256: str | None = None,
                   expected_image: str | None = None) -> dict:
    """Everything promotion and apply re-check about one release, in one place.

    Two things, kept apart. The release's immutable historical contract, read from the record under the
    contract of the schema version it declares: the exact record object (and, at apply, exactly the
    version and SHA-256 the authorization names); its schema, repository, commit and frozen approval,
    cross-checked against the pull request's immutable facts; the exact publish attempt, by that
    contract's job names. And, independently, the live security overlay ``policy`` -- the admission
    policy as origin/main holds it now -- applied to the digest's repository, tags and fresh scan. Any
    relationship that changed, and any stop or exception change merged since the plan, refuses the release.
    """
    if not COMMIT.fullmatch(commit or ""):
        raise Refusal("the release commit is not a full 40-hex SHA")
    record_sha = sha256_bytes(record_data)
    version_id = record_head.get("VersionId") if isinstance(record_head, dict) else None
    if not isinstance(version_id, str) or not VERSION_ID.fullmatch(version_id) or version_id == "null":
        raise Refusal("the release record's version could not be read")
    if expected_version_id is not None and (version_id != expected_version_id or record_sha != expected_sha256):
        raise Refusal("the release record is not the exact version and content the authorization names")
    record = _json(record_data, "the release record")
    contract = release_contract(record)
    image = contract.validator(record, commit, contract)
    if expected_image is not None and image != expected_image:
        raise Refusal("the release record's image is not the image the authorization and dispatch name")
    match = IMAGE_REFERENCE.fullmatch(image)
    _check_object_head(record_head, object_metadata("record", commit, match.group("digest"), record_data))
    if match.group("repository") != approved_repository_url(env):
        raise Refusal("the release record names a repository other than the approved one")
    verify_pull_request_facts(api, record["approval"], commit)
    verify_publish_attempt(api, record["publication"], commit, contract)
    check_release_image(image, commit, repository_doc, images_doc, scan_doc, policy, now)
    return {"release_image": image, "release_commit": commit, "release_record_version_id": version_id, "release_record_sha256": record_sha}


def check_destination_digest(source_image: str, destination_repository_url: str, images_doc) -> str:
    """Cross-account or cross-region promotion: deploy only once the destination holds the same
    digest. Nothing is rebuilt or re-tagged to get there."""
    source = IMAGE_REFERENCE.fullmatch(source_image or "")
    if not source or not REPOSITORY_URL.fullmatch(destination_repository_url or ""):
        raise Refusal("the source image or destination repository is malformed")
    details = (images_doc or {}).get("imageDetails") if isinstance(images_doc, dict) else None
    if not details:
        raise Refusal("the destination does not hold the image yet; wait for the promotion and verify again")
    _single_image(images_doc, destination_repository_url, source.group("digest"))
    return f"{destination_repository_url}@{source.group('digest')}"


# ---------------------------------------------------------------------- plan object and plan file


def check_plan_object(head: dict, expected_version_id: str, max_age_hours: int, now: dt.datetime) -> None:
    if not isinstance(head, dict):
        raise Refusal("the plan object's metadata could not be read")
    if head.get("DeleteMarker"):
        raise Refusal("the named version is a delete marker")
    if head.get("VersionId") != expected_version_id:
        raise Refusal("S3 did not return the named version")
    if head.get("ServerSideEncryption") != "aws:kms":
        raise Refusal("the plan object is not KMS-encrypted")
    if head.get("ObjectLockMode") != "GOVERNANCE":
        raise Refusal("the plan object is not under Object Lock governance retention")
    if _timestamp(head.get("ObjectLockRetainUntilDate")) <= now:
        raise Refusal("the plan object's retention has lapsed; the plan has expired")
    age = now - _timestamp(head.get("LastModified"))
    if age < dt.timedelta(0) or age > dt.timedelta(hours=max_age_hours):
        raise Refusal("the plan version is older than the allowed age")
    if not isinstance(head.get("ContentLength"), int) or head["ContentLength"] <= 0:
        raise Refusal("the plan object is empty")


def compare_lock(plan: pathlib.Path, lockfile: pathlib.Path) -> None:
    """The saved plan's embedded provider lock must be the approved commit's lock file.

    Reads one entry of the plan archive and nothing else; the plan's embedded state is never
    extracted.
    """
    try:
        with zipfile.ZipFile(plan) as archive:
            names = set(archive.namelist())
            if "tfplan" not in names:
                raise Refusal("the downloaded object is not a Terraform saved plan")
            if ".terraform.lock.hcl" not in names:
                raise Refusal("the saved plan carries no dependency lock file")
            embedded = hashlib.sha256(archive.read(".terraform.lock.hcl")).hexdigest()
    except (zipfile.BadZipFile, OSError):
        raise Refusal("the saved plan could not be opened") from None
    if embedded != sha256_file(lockfile):
        raise Refusal("the saved plan's provider lock digest differs from the approved commit's")


def check_terraform_version(document: dict, pinned: str) -> None:
    if not isinstance(document, dict) or document.get("terraform_version") != pinned:
        raise Refusal("the installed Terraform is not the pinned version")


def _plan_contract(document: dict) -> dict:
    variables = document.get("variables") if isinstance(document.get("variables"), dict) else {}

    def value(name):
        entry = variables.get(name)
        return entry.get("value") if isinstance(entry, dict) else None

    contract = {
        "name_prefix": value("name_prefix"),
        "account": value("expected_account_id"),
        "region": value("region"),
        "release_image": value("release_image"),
        "declared_registry": "{}.dkr.ecr.{}.amazonaws.com/{}".format(
            value("release_registry_account_id"), value("release_registry_region"), value("release_repository_name"),
        ),
    }
    if not (isinstance(contract["name_prefix"], str) and re.fullmatch(r"[a-z][a-z0-9-]{2,22}[a-z0-9]", contract["name_prefix"])):
        raise Refusal("the plan does not record the environment's name prefix")
    if not (isinstance(contract["account"], str) and ACCOUNT.fullmatch(contract["account"])):
        raise Refusal("the plan does not record the staging account")
    if not (isinstance(contract["region"], str) and REGION.fullmatch(contract["region"])):
        raise Refusal("the plan does not record the staging region")
    return contract


def _refuse_unknown(unknown: dict, attributes: tuple[str, ...], what: str) -> None:
    for attribute in attributes:
        if unknown.get(attribute):
            raise Refusal(f"a {what}'s {attribute} is unknown while planning and cannot be checked; a human applies it")


def check_task_definition(after: dict, unknown: dict, contract: dict, expected_image: str) -> None:
    """One task-definition revision against the delivery contract. Never prints a value."""
    checked = (
        "family", "container_definitions", "execution_role_arn", "task_role_arn",
        "network_mode", "requires_compatibilities", "volume", "pid_mode", "ipc_mode", "skip_destroy",
    )
    _refuse_unknown(unknown, checked, "task definition")
    prefix, account, region = contract["name_prefix"], contract["account"], contract["region"]
    family = after.get("family") or ""
    suffix = family[len(prefix) + 1:] if family.startswith(prefix + "-") else None
    if suffix not in ECS_CONTRACT:
        raise Refusal("a task definition's family is not one of the approved families")
    if after.get("skip_destroy") is not True:
        raise Refusal("a task definition is not skip_destroy; a rollout would deregister the revision a rollback needs")
    for attribute, kind in (("execution_role_arn", "execution"), ("task_role_arn", "task")):
        if after.get(attribute) != f"arn:aws:iam::{account}:role/{family}-{kind}":
            raise Refusal(f"a task definition names a {kind} role other than its pre-created role")
    if after.get("network_mode") != "awsvpc":
        raise Refusal("a task definition uses host or bridge networking")
    if list(after.get("requires_compatibilities") or []) != ["FARGATE"]:
        raise Refusal("a task definition is not Fargate-only")
    if after.get("pid_mode") or after.get("ipc_mode"):
        raise Refusal("a task definition shares a host PID or IPC namespace")
    if after.get("volume"):
        raise Refusal("a task definition declares a volume; no host mount or volume is allowed")
    try:
        containers = json.loads(after.get("container_definitions") or "")
    except (TypeError, ValueError):
        raise Refusal("a task definition's container definitions could not be read") from None
    if not isinstance(containers, list) or len(containers) != 1 or not isinstance(containers[0], dict):
        raise Refusal("a task definition must hold exactly one container")
    container = containers[0]
    if container.get("image") != expected_image:
        raise Refusal("a container image is not the verified release digest")
    if container.get("privileged") not in (None, False):
        raise Refusal("a container is privileged")
    if container.get("readonlyRootFilesystem") is not True:
        raise Refusal("a container's root filesystem is writable")
    if not isinstance(container.get("user"), str) or not NON_ROOT_USER.fullmatch(container["user"]):
        raise Refusal("a container does not run as a numeric non-root user")
    linux = container.get("linuxParameters") or {}
    capabilities = linux.get("capabilities") or {}
    if capabilities.get("add"):
        raise Refusal("a container adds a Linux capability")
    if "ALL" not in (capabilities.get("drop") or []):
        raise Refusal("a container does not drop every Linux capability")
    if linux.get("devices") or container.get("mountPoints") or container.get("volumesFrom"):
        raise Refusal("a container mounts a host device, volume or another container's volumes")
    approved = ECS_CONTRACT[suffix]["secrets"]
    secrets = container.get("secrets") or []
    names = [s.get("name") for s in secrets if isinstance(s, dict)]
    if len(names) != len(secrets) or sorted(names) != sorted(approved):
        raise Refusal("a container's secret references differ from its approved set")
    for secret in secrets:
        target = approved[secret["name"]]
        if target == "rds!":
            pattern = rf"arn:aws:secretsmanager:{re.escape(region)}:{account}:secret:rds!db-[A-Za-z0-9-]+"
        else:
            container_name = f"{re.escape(prefix)}/{re.escape(target)}"
            pattern = rf"arn:aws:secretsmanager:{re.escape(region)}:{account}:secret:{container_name}(-[A-Za-z0-9]{{6}})?"
        if not isinstance(secret.get("valueFrom"), str) or not re.fullmatch(pattern, secret["valueFrom"]):
            raise Refusal("a container references a secret other than its approved container")


def check_service(after: dict, unknown: dict, contract: dict) -> None:
    _refuse_unknown(unknown, ("name", "launch_type", "enable_execute_command", "network_configuration"), "service")
    prefix, account, region = contract["name_prefix"], contract["account"], contract["region"]
    name = after.get("name")
    approved = {f"{prefix}-{family}" for family, spec in ECS_CONTRACT.items() if spec["service"]}
    if name not in approved:
        raise Refusal("a service is not one of the two approved services")
    if after.get("enable_execute_command") is not False:
        raise Refusal("a service enables ECS Exec")
    if after.get("launch_type") != "FARGATE":
        raise Refusal("a service is not on Fargate")
    networks = after.get("network_configuration") or []
    if len(networks) != 1 or networks[0].get("assign_public_ip") is not False:
        raise Refusal("a service's tasks could receive a public IP")
    # A new revision's ARN is unknown until it is registered; a known one must be the service's own family.
    if not unknown.get("task_definition"):
        pattern = rf"arn:aws:ecs:{re.escape(region)}:{account}:task-definition/{re.escape(name)}:[0-9]+"
        if not isinstance(after.get("task_definition"), str) or not re.fullmatch(pattern, after["task_definition"]):
            raise Refusal("a service runs a task definition outside its own approved family")


def check_ecs_change(change: dict, kind: str, contract: dict, expected_image: str) -> int:
    """1 for each checked task-definition or service change, 0 for anything else."""
    resource_type = change.get("type")
    if resource_type not in ECS_PIPELINE_TYPES:
        raise Refusal("the plan changes an ECS resource type outside the delivery contract")
    if resource_type in ("aws_ecs_cluster", "aws_ecs_cluster_capacity_providers") or kind in ("no-op", "read"):
        return 0
    body = change.get("change") or {}
    if kind in ("delete", "replace") and resource_type == "aws_ecs_task_definition":
        # With skip_destroy the provider only forgets the old revision; it stays registered.
        before = body.get("before") or {}
        if before.get("skip_destroy") is not True:
            raise Refusal("the plan would deregister a task-definition revision; every revision is kept for rollback")
    if kind == "delete":
        before = body.get("before") or {}
        prefix = contract["name_prefix"]
        if resource_type == "aws_ecs_task_definition":
            valid = before.get("family") in {f"{prefix}-{family}" for family in ECS_CONTRACT}
        else:
            valid = before.get("name") in {f"{prefix}-{family}" for family, spec in ECS_CONTRACT.items() if spec["service"]}
        if not valid:
            raise Refusal("the plan removes an ECS resource outside the delivery contract")
        return 1
    after = body.get("after")
    unknown = body.get("after_unknown") if isinstance(body.get("after_unknown"), dict) else {}
    if not isinstance(after, dict):
        raise Refusal("an ECS change carries no planned value")
    if resource_type == "aws_ecs_task_definition":
        check_task_definition(after, unknown, contract, expected_image)
    else:
        check_service(after, unknown, contract)
    return 1


def summarize_plan(document: dict, mode: str, terraform_version: str, expected_image: str) -> tuple[str, int]:
    """Return a sanitized Markdown summary and the number of human-applied changes.

    Counts only. No address, attribute or value leaves this function. Every ECS change is
    checked against the delivery contract in both modes, and any departure refuses the plan.
    """
    if not isinstance(document, dict):
        raise Refusal("the plan rendering could not be read")
    if document.get("terraform_version") != terraform_version:
        raise Refusal("the plan was made by a Terraform other than the pinned version")
    if document.get("errored") is True:
        raise Refusal("the plan recorded an error")
    if not IMAGE_REFERENCE.fullmatch(expected_image or ""):
        raise Refusal("the expected image is not a digest-qualified reference")
    contract = _plan_contract(document)
    if contract["release_image"] != expected_image:
        raise Refusal("the plan's release_image is not the verified release digest")
    if IMAGE_REFERENCE.fullmatch(expected_image).group("repository") != contract["declared_registry"]:
        raise Refusal("the plan's release_registry_* inputs do not declare the verified release's repository")
    counts = {"create": 0, "update": 0, "delete": 0, "replace": 0, "no-op": 0, "read": 0}
    human_changes = 0
    ecs_checked = 0
    for change in document.get("resource_changes") or []:
        actions = tuple((change.get("change") or {}).get("actions") or ())
        if actions in (("delete", "create"), ("create", "delete")):
            kind = "replace"
        elif len(actions) == 1 and actions[0] in counts:
            kind = actions[0]
        else:
            raise Refusal("the plan contains an action this summary does not recognise")
        counts[kind] += 1
        resource_type = change.get("type")
        if not isinstance(resource_type, str) or not resource_type:
            raise Refusal("the plan contains a resource change without a type")
        if kind not in ("no-op", "read") and human_applied(resource_type):
            human_changes += 1
        if resource_type.startswith("aws_ecs_"):
            ecs_checked += check_ecs_change(change, kind, contract, expected_image)
    lines = [
        f"### Sanitized {mode} summary",
        "",
        "| Action | Resources |",
        "| --- | --- |",
        *(f"| {kind} | {counts[kind]} |" for kind in ("create", "update", "replace", "delete", "read", "no-op")),
        "",
        f"Human-applied changes (IAM, KMS, secrets, the release registry, buckets, budget actions): {human_changes}"
        + (" -- a human applies these; the pipeline refuses this plan." if human_changes else ""),
        "",
        f"Task-definition and service changes checked against the delivery contract: {ecs_checked}"
        " (release digest, pre-created roles, approved secret references, container hardening, revisions kept for rollback).",
        "",
        "Policy results and the cost summary are not produced by this job. "
        "The full plan is reviewed in a separately authenticated operator session.",
    ]
    return "\n".join(lines), human_changes


# ---------------------------------------------------------------------- command line


def _stdin_json():
    try:
        return json.load(sys.stdin)
    except ValueError:
        raise Refusal("standard input is not JSON") from None


def _read_json(path: pathlib.Path, what: str):
    return _json(path.read_bytes(), what)


def _write_output(name: str, value: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        raise Refusal("GITHUB_OUTPUT is not set")
    if "\n" in value or "\r" in value:
        raise Refusal("a step output would span lines")
    with open(output, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fail-closed staging delivery checks.")
    sub = parser.add_subparsers(dest="command", required=True)

    preflight = sub.add_parser("preflight")
    preflight.add_argument("--workflow", choices=sorted(ENVIRONMENTS), required=True)
    sub.add_parser("verify-checkout")
    sub.add_parser("check-deployment-authorization")
    sub.add_parser("check-publish-attempt")
    sub.add_parser("draft-config-digest").add_argument("--draft", required=True, type=pathlib.Path)
    variables = sub.add_parser("check-environment-variables")
    variables.add_argument("--workflow", choices=sorted(ENVIRONMENTS), required=True)
    sub.add_parser("write-tfvars").add_argument("--out", required=True, type=pathlib.Path)
    sub.add_parser("check-terraform-version").add_argument("--pinned-file", required=True, type=pathlib.Path)
    plan_object = sub.add_parser("check-plan-object")
    plan_object.add_argument("--expected-version-id", required=True)
    plan_object.add_argument("--max-age-hours", required=True, type=int)
    lock = sub.add_parser("compare-lock")
    lock.add_argument("--plan", required=True, type=pathlib.Path)
    lock.add_argument("--lockfile", required=True, type=pathlib.Path)
    summary = sub.add_parser("plan-summary")
    summary.add_argument("--mode", choices=("plan", "apply"), required=True)
    summary.add_argument("--terraform-version", required=True)
    summary.add_argument("--expected-image", required=True)

    sub.add_parser("check-build-inputs").add_argument("--dockerfile", required=True, type=pathlib.Path)
    draft = sub.add_parser("release-draft")
    draft.add_argument("--image-inspect", required=True, type=pathlib.Path)
    draft.add_argument("--build-metadata", required=True, type=pathlib.Path)
    draft.add_argument("--sbom", required=True, type=pathlib.Path)
    draft.add_argument("--out", required=True, type=pathlib.Path)
    mode = sub.add_parser("publication-mode")
    mode.add_argument("--draft", required=True, type=pathlib.Path)
    mode.add_argument("--repository-url", required=True)
    mode.add_argument("--tag-json", required=True, type=pathlib.Path)
    tag = sub.add_parser("tag-digest")
    tag.add_argument("--draft", required=True, type=pathlib.Path)
    tag.add_argument("--repository-url", required=True)
    tag.add_argument("--tag-json", required=True, type=pathlib.Path)
    release_digest = sub.add_parser("release-digest")
    release_digest.add_argument("--record", required=True, type=pathlib.Path)
    release_digest.add_argument("--commit", required=True)
    sub.add_parser("sbom-key").add_argument("--draft", required=True, type=pathlib.Path)
    metadata = sub.add_parser("object-metadata")
    metadata.add_argument("--kind", choices=("sbom", "record"), required=True)
    metadata.add_argument("--commit", required=True)
    metadata.add_argument("--digest", required=True)
    metadata.add_argument("--body", required=True, type=pathlib.Path)
    config_digest = sub.add_parser("image-config-digest")
    config_digest.add_argument("--repository-url", required=True)
    config_digest.add_argument("--images-json", required=True, type=pathlib.Path)
    config_digest.add_argument("--manifest-json", required=True, type=pathlib.Path)
    identity = sub.add_parser("registry-identity")
    identity.add_argument("--draft", required=True, type=pathlib.Path)
    identity.add_argument("--mode", choices=("fresh", "resume"), required=True)
    identity.add_argument("--repository-url", required=True)
    identity.add_argument("--images-json", required=True, type=pathlib.Path)
    identity.add_argument("--manifest-json", required=True, type=pathlib.Path)
    identity.add_argument("--config-blob", required=True, type=pathlib.Path)
    identity.add_argument("--local-repo-digest")
    identity.add_argument("--out", required=True, type=pathlib.Path)
    record = sub.add_parser("release-record")
    record.add_argument("--draft", required=True, type=pathlib.Path)
    record.add_argument("--identity", required=True, type=pathlib.Path)
    record.add_argument("--sbom-object", required=True, type=pathlib.Path)
    record.add_argument("--sbom-head", required=True, type=pathlib.Path)
    record.add_argument("--out", required=True, type=pathlib.Path)
    compare = sub.add_parser("compare-release-object")
    compare.add_argument("--kind", choices=("sbom", "record"), required=True)
    compare.add_argument("--commit", required=True)
    compare.add_argument("--digest", required=True)
    compare.add_argument("--expected", required=True, type=pathlib.Path)
    compare.add_argument("--existing", required=True, type=pathlib.Path)
    compare.add_argument("--head", required=True, type=pathlib.Path)
    release = sub.add_parser("verify-release")
    release.add_argument("--record", required=True, type=pathlib.Path)
    release.add_argument("--record-head", required=True, type=pathlib.Path)
    release.add_argument("--commit", required=True)
    release.add_argument("--repository-json", required=True, type=pathlib.Path)
    release.add_argument("--image-json", required=True, type=pathlib.Path)
    release.add_argument("--scan-json", required=True, type=pathlib.Path)
    release.add_argument("--expected-record-version-id")
    release.add_argument("--expected-record-sha256")
    release.add_argument("--expected-image")
    destination = sub.add_parser("verify-destination-digest")
    destination.add_argument("--source-image", required=True)
    destination.add_argument("--destination-repository-url", required=True)
    destination.add_argument("--image-json", required=True, type=pathlib.Path)
    return parser


def _dispatch(args, env: dict) -> None:
    command = args.command
    if command == "preflight":
        with open(env.get("GITHUB_EVENT_PATH", ""), encoding="utf-8") as handle:
            event = json.load(handle)
        check_context(env, event)
        check_readiness(json.loads(READINESS_PATH.read_text(encoding="utf-8")), args.workflow)
        api = _api_from_env(env)
        check_environment(api, ENVIRONMENTS[args.workflow])
        if args.workflow == "apply":
            inputs = validate_apply_inputs(env)
            commit = inputs["source_commit"]
            check_reachable(inputs["release_commit"])
            check_deployment_authorization(readiness_from_main(), inputs, _now())
        else:
            commit = env.get("GITHUB_SHA", "")
        evidence = check_commit_approved(api, commit)
        check_reachable(commit)
        _write_output("source_commit", commit)
        if args.workflow == "publish":
            # Frozen into the release record: later promotion and rollback validate this, never a
            # reviewer's current permission or a later review.
            _write_output("approval_evidence", json.dumps(evidence, sort_keys=True, separators=(",", ":")))
        elif args.workflow == "plan":
            release_commit = validate_release_commit(env)
            check_reachable(release_commit)
            _write_output("release_commit", release_commit)
        print(f"preflight: {args.workflow} prerequisites satisfied")
    elif command == "verify-checkout":
        # Inside the apply job: re-derive the commits from the dispatch inputs, and re-verify the
        # checkout, its reachability and its approval without relying on the preflight's outputs.
        inputs = validate_apply_inputs(env)
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=False).stdout.strip()
        if head != inputs["source_commit"]:
            raise Refusal("the checked-out commit is not the commit named by plan_key")
        check_reachable(inputs["source_commit"])
        check_reachable(inputs["release_commit"])
        check_commit_approved(_api_from_env(env), inputs["source_commit"])
        print("checkout: the approved, reachable commit named by plan_key")
    elif command == "check-deployment-authorization":
        entry = check_deployment_authorization(readiness_from_main(), validate_apply_inputs(env), _now())
        print(f"deployment authorization: in force until {entry['expires_at']} for exactly this plan and release")
    elif command == "check-build-inputs":
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=False).stdout.strip()
        if not COMMIT.fullmatch(head) or head != env.get("SOURCE_COMMIT") or head != env.get("GITHUB_SHA"):
            raise Refusal("the checkout is not the preflighted commit")
        dockerfile_base_images(args.dockerfile.read_text(encoding="utf-8"))
        print("build inputs: the preflighted commit, digest-pinned base images, no build argument")
    elif command == "check-publish-attempt":
        check_current_publish_attempt(_api_from_env(env), env)
        print("publish attempt: this attempt's own preflight and verification jobs succeeded in it")
    elif command == "release-draft":
        document = release_draft(
            _read_json(args.image_inspect, "the image inspection"), args.sbom.read_bytes(), env,
            _read_json(args.build_metadata, "the build metadata"),
        )
        _write_private(args.out, json.dumps(document, sort_keys=True).encode("utf-8"))
        print("release draft: the local image, its provenance, SBOM and approval, before any credential")
    elif command == "draft-config-digest":
        print(check_draft(_read_json(args.draft, "the draft"))["local_config_digest"])
    elif command == "publication-mode":
        draft = check_draft(_read_json(args.draft, "the draft"))
        print(publication_mode(draft, args.repository_url, _read_json(args.tag_json, "the tag lookup")))
    elif command == "tag-digest":
        draft = check_draft(_read_json(args.draft, "the draft"))
        print(tag_digest(draft, args.repository_url, _read_json(args.tag_json, "the tag lookup")))
    elif command == "release-digest":
        image = check_release_record(_read_json(args.record, "the release record"), args.commit)
        print(IMAGE_REFERENCE.fullmatch(image).group("digest"))
    elif command == "sbom-key":
        draft = check_draft(_read_json(args.draft, "the draft"))
        print(sbom_key(draft["commit"], draft["local_config_digest"]))
    elif command == "object-metadata":
        metadata = object_metadata(args.kind, args.commit, args.digest, args.body.read_bytes())
        print(",".join(f"{key}={value}" for key, value in sorted(metadata.items())))
    elif command == "image-config-digest":
        images, manifest = _read_json(args.images_json, "the image"), _read_json(args.manifest_json, "the manifest")
        print(image_config_digest(args.repository_url, images, manifest))
    elif command == "registry-identity":
        document = registry_identity(
            _read_json(args.draft, "the draft"), args.mode, args.repository_url, _read_json(args.images_json, "the image"),
            _read_json(args.manifest_json, "the manifest"), args.config_blob.read_bytes(), args.local_repo_digest,
        )
        _write_private(args.out, json.dumps(document, sort_keys=True).encode("utf-8"))
        print(f"registry identity: git-{document['commit']} is {document['digest']}, pushed by run {document['provenance']['run_id']} "
              f"attempt {document['provenance']['run_attempt']}")
    elif command == "release-record":
        document = build_release_record(
            _read_json(args.draft, "the draft"), _read_json(args.identity, "the registry identity"),
            args.sbom_object.read_bytes(), _read_json(args.sbom_head, "the SBOM object's metadata"),
        )
        _write_private(args.out, record_bytes(document))
        print("release record: generated")
    elif command == "compare-release-object":
        compare_release_object(args.kind, args.commit, args.digest, args.expected.read_bytes(), args.existing.read_bytes(),
                               _read_json(args.head, "the object's metadata"))
        print(f"{args.kind}: the existing object is exactly this release's")
    elif command == "verify-release":
        if (args.expected_record_version_id is None) != (args.expected_record_sha256 is None):
            raise Refusal("an expected record version needs its expected SHA-256")
        outputs = verify_release(
            api=_api_from_env(env), env=env, record_data=args.record.read_bytes(),
            record_head=_read_json(args.record_head, "the record's metadata"),
            commit=args.commit, repository_doc=_read_json(args.repository_json, "the repository"),
            images_doc=_read_json(args.image_json, "the image"), scan_doc=_read_json(args.scan_json, "the scan"),
            policy=security_overlay_from_main(), now=_now(),
            expected_version_id=args.expected_record_version_id, expected_sha256=args.expected_record_sha256,
            expected_image=args.expected_image,
        )
        for name, value in outputs.items():
            _write_output(name, value)
        digest = IMAGE_REFERENCE.fullmatch(outputs["release_image"]).group("digest")
        print(f"Release `git-{args.commit}` verified by digest: `{digest}`; record version `{outputs['release_record_version_id']}`.")
    elif command == "verify-destination-digest":
        print(check_destination_digest(args.source_image, args.destination_repository_url, _read_json(args.image_json, "the image")))
    elif command == "check-environment-variables":
        check_environment_variables(env, args.workflow)
        print("environment variables: accepted")
    elif command == "write-tfvars":
        write_tfvars(env, args.out)
        print("staging variables: written")
    elif command == "check-terraform-version":
        check_terraform_version(_stdin_json(), args.pinned_file.read_text(encoding="utf-8").strip())
        print("terraform version: pinned")
    elif command == "check-plan-object":
        check_plan_object(_stdin_json(), args.expected_version_id, args.max_age_hours, _now())
        print("plan object: the named, retained, unexpired version")
    elif command == "compare-lock":
        compare_lock(args.plan, args.lockfile)
        print("provider lock: matches the approved commit")
    elif command == "plan-summary":
        text, trust_changes = summarize_plan(_stdin_json(), args.mode, args.terraform_version, args.expected_image)
        print(text)
        if args.mode == "apply" and trust_changes:
            raise Refusal("the saved plan changes a human-applied resource type, which the pipeline never applies")


def run(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        _dispatch(args, dict(os.environ))
    except (Refusal, OSError, ValueError, KeyError, TypeError) as exc:
        reason = str(exc) if isinstance(exc, Refusal) else f"{type(exc).__name__} while reading an input"
        print(f"refused: {reason}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(run())
