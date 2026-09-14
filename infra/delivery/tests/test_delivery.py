"""Each delivery check refuses when its property is absent (ADR 0011 decision 9; ADR 0012).

Synthetic inputs only. No test contacts GitHub or AWS: the GitHub API is a function passed in,
S3, ECR and the image are small in-memory fakes that answer what the workflows' AWS CLI calls would,
and the saved plan is a zip file built here.
"""

import copy
import dataclasses
import datetime as dt
import hashlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import delivery  # noqa: E402
from delivery import Refusal  # noqa: E402

COMMIT = "a" * 40
EARLIER_COMMIT = "9" * 40
HEAD = "b" * 40
SHA = "c" * 64
ACCOUNT = "111111111111"
REPOSITORY_NAME = "firmbatch/control-plane"
REPO_URL = f"{ACCOUNT}.dkr.ecr.eu-central-1.amazonaws.com/{REPOSITORY_NAME}"
DIGEST = "sha256:" + "d" * 64
EARLIER_DIGEST = "sha256:" + "e" * 64
IMAGE = f"{REPO_URL}@{DIGEST}"
ROLE_ARN = "arn:aws:iam::111111111111:role/firmbatch-staging-github-"
KEY_ID = "00000000-0000-4000-8000-000000000000"
NOW = dt.datetime(2026, 9, 14, 12, 0, tzinfo=dt.timezone.utc)
PREFIX = "firmbatch-staging"
OCI = "application/vnd.oci.image.manifest.v1+json"
DOCKER = "application/vnd.docker.distribution.manifest.v2+json"
INDEX = "application/vnd.oci.image.index.v1+json"
PUBLISH_ROLE = "arn:aws:iam::111111111111:role/firmbatch-artifact-publish"
OTHER_REPO_IMAGE = f"{ACCOUNT}.dkr.ecr.eu-central-1.amazonaws.com/other@{DIGEST}"
TASK_DEFINITION_ARN = f"arn:aws:ecs:eu-central-1:{ACCOUNT}:task-definition"
SBOM = b'{"spdxVersion": "SPDX-2.3", "name": "firmbatch-release"}'
TAG = f"git-{COMMIT}"
ARTIFACT_ENV = {
    "ARTIFACT_REGISTRY_ACCOUNT_ID": ACCOUNT,
    "ARTIFACT_REGISTRY_REGION": "eu-central-1",
    "ARTIFACT_REPOSITORY_NAME": REPOSITORY_NAME,
    "ARTIFACT_RELEASE_BUCKET": "synthetic-releases",
}
APPROVAL = {
    "pull_request": 7,
    "pull_request_author_id": 1001,
    "pull_request_author_login": "author",
    "head_commit": HEAD,
    "merge_commit": COMMIT,
    "merged_at": "2026-09-14T00:00:00Z",
    "approver_id": 2002,
    "approver_login": "reviewer",
    "review_id": 9001,
    "review_submitted_at": "2026-09-13T20:00:00Z",
    "review_commit": HEAD,
    "reviewer_association": "COLLABORATOR",
    "reviewer_permission": "write",
}


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def context(**overrides):
    env = {
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_REPOSITORY": "chamsrut/firmbatch",
        "GITHUB_REPOSITORY_ID": "1349512121",
    }
    env.update(overrides)
    return env


EVENT = {"repository": {"id": 1349512121, "fork": False, "default_branch": "main"}}


V1 = delivery.RELEASE_CONTRACTS[1]
HUMAN_APPLIED = "human_applied_resources_applied_by_human"


def readiness(prerequisites=True, authorizations=None, **overrides):
    """Every known prerequisite attested true, the first set to `prerequisites`, then `overrides`."""
    names = sorted(delivery.KNOWN_PREREQUISITES)
    attested = {name: True for name in names}
    attested[names[0]] = prerequisites
    attested.update(overrides)
    return {
        "schema_version": 2,
        "github_repository": "chamsrut/firmbatch",
        "github_repository_id": "1349512121",
        "prerequisites": attested,
        "deployment_authorization": {"schema_version": 1, "authorizations": authorizations or []},
    }


def environment_api(environment=None, policies=None):
    environment = environment if environment is not None else {
        "protection_rules": [{"type": "required_reviewers", "prevent_self_review": True, "reviewers": [{"type": "User"}]}],
        "can_admins_bypass": False,
        "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
    }
    policies = policies if policies is not None else {"branch_policies": [{"name": "main", "type": "branch"}]}

    def api(path):
        if path.endswith("/deployment-branch-policies"):
            return policies
        return environment

    return api


MERGED = [{
    "number": 7,
    "merged_at": "2026-09-14T00:00:00Z",
    "merge_commit_sha": COMMIT,
    "base": {"ref": "main"},
    "head": {"sha": HEAD},
    "user": {"login": "author", "id": 1001},
}]
REVIEWERS = [{"type": "User"}]


def review(login="reviewer", uid=2002, state="APPROVED", commit=HEAD, submitted="2026-09-13T20:00:00Z", rid=9001,
           association="COLLABORATOR"):
    return {
        "id": rid, "user": {"login": login, "id": uid}, "state": state, "commit_id": commit,
        "submitted_at": submitted, "author_association": association,
    }


def pulls_api(pulls, reviews, permissions=None, calls=None):
    permissions = permissions or {}

    def api(path):
        if calls is not None:
            calls.append(path)
        if "/collaborators/" in path:
            login = path.split("/collaborators/")[1].split("/")[0]
            return {"permission": permissions.get(login, "write")}
        if "/reviews" in path:
            page = int(path.rsplit("page=", 1)[1])
            return reviews[(page - 1) * 100:page * 100]
        return pulls

    return api


# ---------------------------------------------------------------------- the image, the registry, the bucket


def image_labels(run_id="4242", attempt="1", commit=COMMIT, created="2026-09-14T11:00:00Z", **overrides):
    labels = {
        "org.opencontainers.image.source": "https://github.com/chamsrut/firmbatch",
        "org.opencontainers.image.revision": commit,
        "org.opencontainers.image.created": created,
        "io.firmbatch.release.provenance": "firmbatch.release-provenance.v1",
        "io.firmbatch.release.repository-id": "1349512121",
        "io.firmbatch.release.workflow-ref": "chamsrut/firmbatch/.github/workflows/artifact-publish.yml@refs/heads/main",
        "io.firmbatch.release.run-id": run_id,
        "io.firmbatch.release.run-attempt": attempt,
        "maintainer": "a base image's own label, which provenance ignores",
    }
    labels.update(overrides)
    return labels


def config_blob(labels, architecture="amd64"):
    return json.dumps({"architecture": architecture, "os": "linux", "config": {"Labels": labels}}, sort_keys=True).encode()


def image_inspect(labels, config_digest, **overrides):
    image = {"Id": config_digest, "Os": "linux", "Architecture": "amd64", "RepoDigests": [], "Config": {"Labels": labels}}
    image.update(overrides)
    return [image]


def build_metadata(config_digest, manifest_digest="sha256:" + "7" * 64):
    """What docker build --metadata-file records: the configuration digest, and the manifest digest."""
    return {"containerimage.config.digest": config_digest, "containerimage.digest": manifest_digest}


def publish_env(run_id="4242", attempt="1", approval=None, commit=COMMIT):
    return {
        "SOURCE_COMMIT": commit,
        "GITHUB_SHA": commit,
        "GITHUB_WORKFLOW_REF": "chamsrut/firmbatch/.github/workflows/artifact-publish.yml@refs/heads/main",
        "GITHUB_RUN_ID": run_id,
        "GITHUB_RUN_ATTEMPT": attempt,
        "APPROVAL_EVIDENCE": json.dumps(approval if approval is not None else APPROVAL),
    }


def draft_for(run_id="4242", attempt="1", labels=None):
    labels = labels if labels is not None else image_labels(run_id, attempt)
    blob = config_blob(labels)
    config_digest = sha256(blob)
    inspect = image_inspect(labels, config_digest)
    return delivery.release_draft(inspect, SBOM, publish_env(run_id, attempt), build_metadata(config_digest)), blob


class Interrupted(Exception):
    """The job died here: the runner was lost, a step failed, the credential expired."""


class PreconditionFailed(Exception):
    """S3 answered 412: an object already exists at the key."""


class ResponseLost(Exception):
    """S3 stored the object, and the response never arrived."""


class Registry:
    """ECR as describe-images, batch-get-image, get-download-url-for-layer and an immutable push see it."""

    def __init__(self):
        self.images = {}
        self.blobs = {}
        self.pushes = 0

    def push(self, tag, blob, media=DOCKER):
        if tag in self.images:
            raise AssertionError("an immutable tag was pushed twice")
        config_digest = sha256(blob)
        raw = json.dumps({
            "schemaVersion": 2, "mediaType": media,
            "config": {"mediaType": delivery.IMAGE_MANIFEST_MEDIA_TYPES.get(media, "x"), "size": len(blob), "digest": config_digest},
            "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 1, "digest": "sha256:" + "1" * 64}],
        }, sort_keys=True)
        digest = sha256(raw.encode())
        self.images[tag] = {"digest": digest, "media": media, "raw": raw, "tags": [tag]}
        self.blobs[config_digest] = blob
        self.pushes += 1
        return f"{REPO_URL}@{digest}"

    def describe_tag(self, tag):
        image = self.images.get(tag)
        if image is None:
            return {"imageDetails": []}
        return {"imageDetails": [{
            "registryId": ACCOUNT, "repositoryName": REPOSITORY_NAME, "imageDigest": image["digest"],
            "imageTags": list(image["tags"]), "imageManifestMediaType": image["media"],
        }]}

    def batch_get(self, digest):
        image = next(i for i in self.images.values() if i["digest"] == digest)
        entry = {"imageId": {"imageDigest": digest}, "imageManifest": image["raw"], "imageManifestMediaType": image["media"]}
        return {"images": [entry], "failures": []}


class Bucket:
    """The release-record bucket as put-object --if-none-match and get-object see it."""

    def __init__(self):
        self.objects = {}
        self.writes = 0

    def put(self, key, body, metadata, lose_response=False):
        if key in self.objects:
            raise PreconditionFailed(key)
        self.objects[key] = (body, metadata, f"v{len(self.objects) + 1}")
        self.writes += 1
        if lose_response:
            raise ResponseLost(key)

    def get(self, key):
        if key not in self.objects:
            raise Interrupted(f"get-object failed for {key}")
        body, metadata, version = self.objects[key]
        return body, {"VersionId": version, "ServerSideEncryption": "aws:kms", "Metadata": dict(metadata)}


def put_once(bucket, key, body, kind, digest, lose_response=False):
    """The workflow's put_once: create once; after a 412 or a lost response, read back and compare."""
    try:
        bucket.put(key, body, delivery.object_metadata(kind, COMMIT, digest, body), lose_response)
        return
    except (PreconditionFailed, ResponseLost):
        pass
    existing, head = bucket.get(key)
    delivery.compare_release_object(kind, COMMIT, digest, body, existing, head)


def publish(registry, bucket, run_id="4242", attempt="1", fail=None, labels=None):
    """One dispatch of artifact-publish's publication step, in the workflow's order, stopping at `fail`."""
    draft, blob = draft_for(run_id, attempt, labels)
    mode = delivery.publication_mode(draft, REPO_URL, registry.describe_tag(TAG))
    local_repo_digest = ""
    if mode == "fresh":
        put_once(bucket, delivery.sbom_key(COMMIT, draft["local_config_digest"]), SBOM, "sbom", draft["local_config_digest"])
        if fail == "after-sbom":
            raise Interrupted(fail)
        local_repo_digest = registry.push(TAG, blob)
        if fail == "after-push":
            raise Interrupted(fail)
    tag_doc = registry.describe_tag(TAG)
    digest = delivery.tag_digest(draft, REPO_URL, tag_doc)
    manifest_doc = registry.batch_get(digest)
    config_digest = delivery.image_config_digest(REPO_URL, tag_doc, manifest_doc)
    identity = delivery.registry_identity(draft, mode, REPO_URL, tag_doc, manifest_doc, registry.blobs[config_digest], local_repo_digest)
    if fail == "after-identity":
        raise Interrupted(fail)
    sbom_body, sbom_head = bucket.get(f"releases/{COMMIT}/sbom-{config_digest.split(':')[1]}.spdx.json")
    record = delivery.record_bytes(delivery.build_release_record(draft, identity, sbom_body, sbom_head))
    if fail == "before-record":
        raise Interrupted(fail)
    put_once(bucket, delivery.record_key(COMMIT), record, "record", digest, lose_response=(fail == "record-response-lost"))
    return mode, record


def published():
    registry, bucket = Registry(), Bucket()
    publish(registry, bucket)
    return registry, bucket


def repository_doc(**overrides):
    repository = {
        "repositoryUri": REPO_URL,
        "imageTagMutability": "IMMUTABLE",
        "encryptionConfiguration": {"encryptionType": "KMS"},
        "imageScanningConfiguration": {"scanOnPush": True},
    }
    repository.update(overrides)
    return {"repositories": [repository]}


def images_doc(commit=COMMIT, digest=DIGEST, tags=None, media_type=OCI, repository=REPOSITORY_NAME):
    return {"imageDetails": [{
        "registryId": ACCOUNT,
        "repositoryName": repository,
        "imageDigest": digest,
        "imageTags": tags if tags is not None else [f"git-{commit}"],
        "imageManifestMediaType": media_type,
    }]}


def scan_doc(digest=DIGEST, status="COMPLETE", findings=None, enhanced=None, counts=None):
    if findings is None:
        findings = [{"name": "CVE-2026-0001", "severity": "MEDIUM"}, {"name": "CVE-2026-0002", "severity": "LOW"}]
    enhanced = enhanced or []
    listed = [f["severity"] for f in findings] + [f["severity"] for f in enhanced]
    document = {
        "imageId": {"imageDigest": digest},
        "imageScanStatus": {"status": status},
        "imageScanFindings": {
            "findingSeverityCounts": counts if counts is not None else {s: listed.count(s) for s in set(listed)},
            "findings": findings,
        },
    }
    if enhanced:
        document["imageScanFindings"]["enhancedFindings"] = enhanced
    return document


def admission_policy(exceptions=None, stops=None, **maxima):
    return {
        "schema_version": 2,
        "purpose": "synthetic",
        "require_scan_status": "COMPLETE",
        "maximum_findings": {"CRITICAL": 0, "HIGH": 0, **maxima},
        "exceptions": exceptions or [],
        "security_stops": stops or [],
    }


def exception(digest=DIGEST, ids=("CVE-2026-9999",), created="2026-09-10T00:00:00Z", expires="2026-09-30T00:00:00Z", **overrides):
    entry = {
        "image_digest": digest,
        "vulnerability_ids": list(ids),
        "reason": "No fixed version exists yet; the vulnerable code path is unreachable in this image.",
        "approver": {"login": "security-reviewer", "id": 3003},
        "approval_reference": "https://github.com/chamsrut/firmbatch/pull/12",
        "created_at": created,
        "expires_at": expires,
    }
    entry.update(overrides)
    return entry


def attempt_api(record, *, attempt_overrides=None, jobs=None, pull_overrides=None, calls=None, aggregate_conclusion="success"):
    """The GitHub API as verify-release reads it, for the release a record names."""
    publication = record["publication"]
    run_id, attempt = publication["run_id"], publication["run_attempt"]
    attempt_doc = {
        "id": int(run_id), "run_attempt": int(attempt), "path": ".github/workflows/artifact-publish.yml", "head_sha": COMMIT,
        "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
        "repository": {"id": 1349512121},
    }
    attempt_doc.update(attempt_overrides or {})
    if jobs is None:
        gate = {"run_attempt": int(attempt), "status": "completed", "conclusion": "success"}
        jobs = [{"name": name, **gate} for name in V1.publish_gate_jobs]
        jobs.append({"name": V1.publish_job, "run_attempt": int(attempt), "status": "completed", "conclusion": "success"})
    pull = {
        "number": 7, "merge_commit_sha": COMMIT, "base": {"ref": "main"}, "head": {"sha": HEAD},
        "user": {"login": "author", "id": 1001}, "merged_at": "2026-09-14T00:00:00Z",
    }
    pull.update(pull_overrides or {})

    def api(path):
        if calls is not None:
            calls.append(path)
        base = f"/repos/chamsrut/firmbatch/actions/runs/{run_id}"
        if path == f"{base}/attempts/{attempt}":
            return attempt_doc
        if path.startswith(f"{base}/attempts/{attempt}/jobs"):
            return {"total_count": len(jobs), "jobs": jobs}
        if path == base:
            return {**attempt_doc, "run_attempt": int(attempt) + 1, "conclusion": aggregate_conclusion}
        if path == "/repos/chamsrut/firmbatch/pulls/7":
            return pull
        return None

    return api


def secret_arn(target):
    if target == "rds!":
        return "arn:aws:secretsmanager:eu-central-1:111111111111:secret:rds!db-0123abcd-4567"
    return f"arn:aws:secretsmanager:eu-central-1:111111111111:secret:{PREFIX}/{target}-AbCdEf"


def task_definition_change(suffix="web-api", container=None, before=None, **after):
    definition = {
        "name": suffix,
        "image": IMAGE,
        "essential": True,
        "user": "10001:10001",
        "readonlyRootFilesystem": True,
        "privileged": False,
        "linuxParameters": {"initProcessEnabled": True, "capabilities": {"drop": ["ALL"]}},
        "secrets": [{"name": name, "valueFrom": secret_arn(target)} for name, target in delivery.ECS_CONTRACT[suffix]["secrets"].items()],
    }
    for key, value in (container or {}).items():
        if value is None:
            definition.pop(key, None)
        else:
            definition[key] = value
    planned = {
        "family": f"{PREFIX}-{suffix}",
        "network_mode": "awsvpc",
        "requires_compatibilities": ["FARGATE"],
        "execution_role_arn": f"arn:aws:iam::{ACCOUNT}:role/{PREFIX}-{suffix}-execution",
        "task_role_arn": f"arn:aws:iam::{ACCOUNT}:role/{PREFIX}-{suffix}-task",
        "volume": [],
        "pid_mode": None,
        "ipc_mode": None,
        "skip_destroy": True,
        "container_definitions": json.dumps([definition]),
    }
    planned.update(after)
    return {
        "address": f"module.compute.aws_ecs_task_definition.this[\"{suffix}\"]",
        "type": "aws_ecs_task_definition",
        "change": {
            "actions": ["delete", "create"],
            "before": before if before is not None else {"family": f"{PREFIX}-{suffix}", "skip_destroy": True},
            "after": planned,
            "after_unknown": {"arn": True, "revision": True},
        },
    }


def service_change(suffix="web-api", unknown=None, **after):
    planned = {
        "name": f"{PREFIX}-{suffix}",
        "launch_type": "FARGATE",
        "enable_execute_command": False,
        "network_configuration": [{"assign_public_ip": False, "subnets": ["subnet-a"], "security_groups": ["sg-a"]}],
        "task_definition": None,
    }
    planned.update(after)
    return {
        "address": f"module.compute.aws_ecs_service.this[\"{suffix}\"]",
        "type": "aws_ecs_service",
        "change": {"actions": ["update"], "after": planned, "after_unknown": unknown if unknown is not None else {"task_definition": True}},
    }


def rendering(changes, version="1.15.8", release_image=IMAGE, registry=(ACCOUNT, "eu-central-1", REPOSITORY_NAME), **extra):
    return {
        "terraform_version": version,
        "variables": {
            "name_prefix": {"value": PREFIX},
            "expected_account_id": {"value": ACCOUNT},
            "region": {"value": "eu-central-1"},
            "release_image": {"value": release_image},
            "release_registry_account_id": {"value": registry[0]},
            "release_registry_region": {"value": registry[1]},
            "release_repository_name": {"value": registry[2]},
        },
        "resource_changes": changes,
        **extra,
    }


def run_cli(argv, document, env=None):
    return subprocess.run(
        [sys.executable, str(HERE.parent / "delivery.py"), *argv],
        input=json.dumps(document), capture_output=True, text=True, check=False, env=env,
    )


# ---------------------------------------------------------------------- context, readiness, approval


class Context(unittest.TestCase):
    def test_the_expected_context_passes(self):
        delivery.check_context(context(), EVENT)

    def test_each_departure_is_refused(self):
        cases = {
            "pull request": (context(GITHUB_EVENT_NAME="pull_request"), EVENT),
            "pull request target": (context(GITHUB_EVENT_NAME="pull_request_target"), EVENT),
            "push": (context(GITHUB_EVENT_NAME="push"), EVENT),
            "non-main ref": (context(GITHUB_REF="refs/heads/feature"), EVENT),
            "tag ref": (context(GITHUB_REF="refs/tags/v1"), EVENT),
            "unprotected main": (context(GITHUB_REF_PROTECTED="false"), EVENT),
            "another repository": (context(GITHUB_REPOSITORY="someone/firmbatch"), EVENT),
            "another repository id": (context(GITHUB_REPOSITORY_ID="1"), EVENT),
            "fork": (context(), {"repository": {"id": 1349512121, "fork": True, "default_branch": "main"}}),
            "missing fork flag": (context(), {"repository": {"id": 1349512121, "default_branch": "main"}}),
            "other default branch": (context(), {"repository": {"id": 1349512121, "fork": False, "default_branch": "dev"}}),
        }
        for name, (env, event) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.check_context(env, event)


class Readiness(unittest.TestCase):
    def test_the_committed_attestation_refuses_every_workflow(self):
        committed = json.loads(delivery.READINESS_PATH.read_text())
        for workflow in ("publish", "plan", "apply"):
            with self.subTest(workflow=workflow):
                with self.assertRaises(Refusal):
                    delivery.check_readiness(committed, workflow)
        self.assertEqual(committed["deployment_authorization"], {"schema_version": 1, "authorizations": []})

    def test_an_unmet_prerequisite_or_an_old_schema_is_refused(self):
        for document in (readiness(prerequisites=False), {**readiness(), "schema_version": 1}):
            with self.subTest(document=document["schema_version"]):
                with self.assertRaises(Refusal):
                    delivery.check_readiness(document, "plan")
        delivery.check_readiness(readiness(), "apply")

    def test_a_truthy_non_boolean_is_not_an_attestation(self):
        document = readiness()
        document["prerequisites"][sorted(delivery.KNOWN_PREREQUISITES)[0]] = "true"
        with self.assertRaisesRegex(Refusal, "not a boolean"):
            delivery.check_readiness(document, "plan")

    def test_the_committed_attestation_names_exactly_the_known_prerequisites(self):
        committed = json.loads(delivery.READINESS_PATH.read_text())
        self.assertEqual(set(committed["prerequisites"]), delivery.KNOWN_PREREQUISITES)
        self.assertTrue(all(value is False for value in committed["prerequisites"].values()))

    def test_publication_does_not_wait_for_the_first_staging_apply_it_precedes(self):
        # The documented order: bootstrap, artifacts, publish a release, the human's first staging apply
        # of that release, and only then human_applied_resources_applied_by_human. Publication requiring
        # that attestation made the order impossible without a false one.
        before_first_apply = readiness(**{HUMAN_APPLIED: False})
        delivery.check_readiness(before_first_apply, "publish")
        for workflow in ("plan", "apply"):
            with self.subTest(workflow=workflow):
                with self.assertRaisesRegex(Refusal, HUMAN_APPLIED):
                    delivery.check_readiness(before_first_apply, workflow)
        self.assertNotIn(HUMAN_APPLIED, delivery.WORKFLOW_PREREQUISITES["publish"])

    def test_each_workflow_refuses_without_each_prerequisite_it_needs(self):
        for workflow, names in delivery.WORKFLOW_PREREQUISITES.items():
            for name in names:
                with self.subTest(workflow=workflow, prerequisite=name):
                    with self.assertRaisesRegex(Refusal, name):
                        delivery.check_readiness(readiness(**{name: False}), workflow)

    def test_a_renamed_missing_or_extra_prerequisite_is_refused(self):
        renamed = readiness()
        renamed["prerequisites"]["release_registry_applied"] = renamed["prerequisites"].pop("release_registry_applied_by_human")
        missing = readiness()
        missing["prerequisites"].pop(HUMAN_APPLIED)
        extra = readiness()
        extra["prerequisites"]["m3_3d_deployment_authorized"] = True
        for name, document in {"renamed": renamed, "missing": missing, "extra": extra}.items():
            with self.subTest(case=name):
                with self.assertRaisesRegex(Refusal, "exactly the known prerequisites"):
                    delivery.check_readiness(document, "publish")
        with self.assertRaises(Refusal):
            delivery.check_readiness(readiness(), "deploy")


class DeploymentAuthorization(unittest.TestCase):
    """An authorization is bound to one plan object and one release, and expires within a day."""

    inputs = {
        "plan_key": f"plans/staging/{COMMIT}/{SHA}.tfplan",
        "plan_version_id": "planversion1",
        "plan_sha256": SHA,
        "release_commit": EARLIER_COMMIT,
        "release_digest": DIGEST,
        "release_record_version_id": "recordversion1",
        "release_record_sha256": "f" * 64,
    }

    def entry(self, **overrides):
        entry = {
            "environment": "staging",
            "plan_key": self.inputs["plan_key"],
            "plan_version_id": self.inputs["plan_version_id"],
            "plan_sha256": SHA,
            "release_commit": EARLIER_COMMIT,
            "release_image_digest": DIGEST,
            "release_record_version_id": "recordversion1",
            "release_record_sha256": "f" * 64,
            "authorized_by": "owner",
            "authorization_reference": "https://github.com/chamsrut/firmbatch/pull/40",
            "authorized_at": "2026-09-14T10:00:00Z",
            "expires_at": "2026-09-14T18:00:00Z",
        }
        entry.update(overrides)
        return entry

    def test_the_one_authorization_naming_exactly_this_tuple_passes(self):
        found = delivery.check_deployment_authorization(readiness(authorizations=[self.entry()]), self.inputs, NOW)
        self.assertEqual(found["authorized_by"], "owner")

    def test_an_authorization_for_anything_else_authorizes_nothing(self):
        cases = {
            "no authorization": [],
            "another plan key": [self.entry(plan_key=f"plans/staging/{COMMIT}/{'1' * 64}.tfplan", plan_sha256="1" * 64)],
            "another plan version": [self.entry(plan_version_id="planversion2")],
            "another release commit": [self.entry(release_commit=COMMIT)],
            "another digest": [self.entry(release_image_digest=EARLIER_DIGEST)],
            "another record version": [self.entry(release_record_version_id="recordversion2")],
            "another record content": [self.entry(release_record_sha256="0" * 64)],
            "a previous authorization, for an earlier plan of the same release": [
                self.entry(plan_key=f"plans/staging/{EARLIER_COMMIT}/{'2' * 64}.tfplan", plan_sha256="2" * 64, plan_version_id="old"),
            ],
            "expired": [self.entry(expires_at="2026-09-14T11:59:59Z")],
            "not yet in force": [self.entry(authorized_at="2026-09-14T12:30:00Z", expires_at="2026-09-14T13:00:00Z")],
            "longer than a day": [self.entry(authorized_at="2026-09-14T00:00:00Z", expires_at="2026-09-15T00:00:01Z")],
            "ambiguous": [self.entry(), self.entry(authorized_by="second")],
            "a malformed entry beside a good one": [self.entry(), {"environment": "staging"}],
            "no reviewed reference": [self.entry(authorization_reference="slack message")],
            "another environment": [self.entry(environment="production")],
        }
        for name, entries in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.check_deployment_authorization(readiness(authorizations=entries), self.inputs, NOW)

    def test_the_apply_inputs_carry_the_whole_tuple(self):
        env = {
            "PLAN_KEY": self.inputs["plan_key"], "PLAN_VERSION_ID": "planversion1", "PLAN_SHA256": SHA,
            "RELEASE_COMMIT": EARLIER_COMMIT, "RELEASE_IMAGE": IMAGE, "RELEASE_RECORD_VERSION_ID": "recordversion1",
            "RELEASE_RECORD_SHA256": "f" * 64,
        }
        inputs = delivery.validate_apply_inputs(env)
        self.assertEqual({k: inputs[k] for k in self.inputs}, self.inputs)
        self.assertEqual(inputs["source_commit"], COMMIT)
        delivery.check_deployment_authorization(readiness(authorizations=[self.entry()]), inputs, NOW)

    def test_authorization_is_read_from_origin_main(self):
        def git_show(argv, **kwargs):
            self.assertEqual(argv, ["git", "show", "origin/main:infra/delivery/readiness.json"])
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(readiness(authorizations=[self.entry()])).encode())
        document = delivery.readiness_from_main(run=git_show)
        delivery.check_deployment_authorization(document, self.inputs, NOW)
        with self.assertRaises(Refusal):
            delivery.readiness_from_main(run=lambda argv, **kwargs: subprocess.CompletedProcess(argv, 128, stdout=b""))

    def dispatch_check_deployment_authorization(self, main_document, checkout_text):
        """The check-deployment-authorization command line, end to end: the checkout's readiness.json holds
        `checkout_text`, origin/main's holds `main_document`, and only git is faked."""
        env = {
            "PLAN_KEY": self.inputs["plan_key"], "PLAN_VERSION_ID": "planversion1", "PLAN_SHA256": SHA,
            "RELEASE_COMMIT": EARLIER_COMMIT, "RELEASE_IMAGE": IMAGE, "RELEASE_RECORD_VERSION_ID": "recordversion1",
            "RELEASE_RECORD_SHA256": "f" * 64,
        }
        calls = []

        def git(argv, **kwargs):
            calls.append(argv)
            if argv != ["git", "show", "origin/main:infra/delivery/readiness.json"]:
                raise AssertionError(f"check-deployment-authorization ran an unexpected command: {argv}")
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(main_document).encode())

        with tempfile.TemporaryDirectory() as directory:
            checkout = pathlib.Path(directory, "readiness.json")
            checkout.write_text(checkout_text)
            with mock.patch.object(delivery.subprocess, "run", git), mock.patch.object(delivery, "READINESS_PATH", checkout), \
                    mock.patch.object(delivery, "_now", lambda: NOW), mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                delivery._dispatch(delivery._parser().parse_args(["check-deployment-authorization"]), env)
        return calls, out.getvalue()

    def test_the_command_reads_the_authorization_from_main_never_the_historical_checkout(self):
        # The checkout -- the plan's older commit -- would authorize exactly the dispatched tuple; main does not.
        checkout_authorizes = json.dumps(readiness(authorizations=[self.entry()]))
        for name, main_document in {
            "main records no authorization": readiness(),
            "main authorizes a different plan version": readiness(authorizations=[self.entry(plan_version_id="planversion2")]),
            "main's authorization for this tuple has been replaced by one for another release": readiness(
                authorizations=[self.entry(release_image_digest=EARLIER_DIGEST)],
            ),
        }.items():
            with self.subTest(case=name):
                with self.assertRaisesRegex(Refusal, "no single deployment authorization"):
                    self.dispatch_check_deployment_authorization(main_document, checkout_authorizes)

    def test_the_command_accepts_exactly_the_tuple_main_authorizes(self):
        # The checkout's copy is unreadable, so passing proves the command never consulted it.
        calls, output = self.dispatch_check_deployment_authorization(readiness(authorizations=[self.entry()]), "not json")
        self.assertEqual(calls, [["git", "show", "origin/main:infra/delivery/readiness.json"]])
        self.assertIn("in force until 2026-09-14T18:00:00Z", output)


class Environments(unittest.TestCase):
    def test_a_protected_main_only_environment_passes(self):
        delivery.check_environment(environment_api(), "artifact-publish")

    def test_a_missing_environment_is_refused_before_it_is_referenced(self):
        with self.assertRaises(Refusal):
            delivery.check_environment(lambda path: None, "artifact-publish")

    def test_each_missing_protection_is_refused(self):
        good = {
            "protection_rules": [{"type": "required_reviewers", "prevent_self_review": True, "reviewers": [{"type": "User"}]}],
            "can_admins_bypass": False,
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
        }
        cases = {
            "no reviewers": {**good, "protection_rules": []},
            "empty reviewer list": {
                **good, "protection_rules": [{"type": "required_reviewers", "prevent_self_review": True, "reviewers": []}],
            },
            "self-review allowed": {
                **good, "protection_rules": [{"type": "required_reviewers", "prevent_self_review": False, "reviewers": REVIEWERS}],
            },
            "administrators bypass": {**good, "can_admins_bypass": True},
            "any branch": {**good, "deployment_branch_policy": None},
            "protected branches rather than main": {
                **good, "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False},
            },
        }
        for name, environment in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.check_environment(environment_api(environment), "staging-apply")

    def test_a_branch_policy_other_than_main_is_refused(self):
        for policies in (
            {"branch_policies": []},
            {"branch_policies": [{"name": "main"}, {"name": "release/*"}]},
            {"branch_policies": [{"name": "main", "type": "tag"}]},
        ):
            with self.subTest(policies=policies):
                with self.assertRaises(Refusal):
                    delivery.check_environment(environment_api(policies=policies), "artifact-publish")


class Approval(unittest.TestCase):
    """Approval is historical: reviews before the merge, from accounts with write access."""

    def test_an_independently_approved_merge_yields_frozen_evidence(self):
        evidence = delivery.approval_evidence(pulls_api(MERGED, [review()]), COMMIT)
        self.assertEqual(evidence, APPROVAL)

    def test_each_unapproved_source_is_refused(self):
        cases = {
            "no pull request": ([], []),
            "not merged": ([{**MERGED[0], "merged_at": None}], []),
            "merged elsewhere": ([{**MERGED[0], "base": {"ref": "dev"}}], []),
            "commit inside, not the merge": ([{**MERGED[0], "merge_commit_sha": "d" * 40}], []),
            "no review": (MERGED, []),
            "self-approved": (MERGED, [review(login="author", uid=1001)]),
            "self-approved under another login spelling": (MERGED, [review(login="Author", uid=1001)]),
            "approved an earlier head": (MERGED, [review(commit="e" * 40)]),
            "approval then changes requested before the merge": (MERGED, [
                review(), review(state="CHANGES_REQUESTED", submitted="2026-09-13T21:00:00Z", rid=9002),
            ]),
            "another qualified reviewer requests changes before the merge": (MERGED, [
                review(), review(login="second", uid=2003, state="CHANGES_REQUESTED", rid=9003),
            ]),
            "approval dismissed": (MERGED, [review(), review(state="DISMISSED", submitted="2026-09-13T22:00:00Z", rid=9004)]),
            "the only approval came after the merge": (MERGED, [review(submitted="2026-09-14T00:00:01Z")]),
            "the approver had no write association when reviewing": (MERGED, [review(association="CONTRIBUTOR")]),
            "an approval with no association": (MERGED, [review(association="NONE")]),
            "an approval with no submission time": (MERGED, [{**review(), "submitted_at": None}]),
        }
        for name, (pulls, reviews) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.approval_evidence(pulls_api(pulls, reviews), COMMIT)

    def test_an_approver_without_write_permission_does_not_count(self):
        for permission in ("read", "triage", "none"):
            with self.subTest(permission=permission):
                with self.assertRaises(Refusal):
                    delivery.approval_evidence(pulls_api(MERGED, [review()], {"reviewer": permission}), COMMIT)

    def test_reviews_after_the_merge_and_from_unqualified_accounts_are_ignored(self):
        late = review(login="late", uid=2004, state="CHANGES_REQUESTED", submitted="2026-09-15T00:00:00Z", rid=9005)
        passer_by = review(login="passer-by", uid=2005, state="CHANGES_REQUESTED", association="NONE", rid=9006)
        no_write = review(login="reader", uid=2006, state="CHANGES_REQUESTED", rid=9007)
        evidence = delivery.approval_evidence(pulls_api(MERGED, [review(), late, passer_by, no_write], {"reader": "read"}), COMMIT)
        self.assertEqual(evidence["review_id"], 9001)

    def test_every_page_of_reviews_is_read(self):
        comments = [review(login=f"commenter-{n}", uid=5000 + n, state="COMMENTED", rid=100 + n) for n in range(100)]
        delivery.approval_evidence(pulls_api(MERGED, comments + [review()]), COMMIT)
        requested = [review(state="CHANGES_REQUESTED", submitted="2026-09-13T23:00:00Z", rid=9010)]
        with self.assertRaises(Refusal):
            delivery.approval_evidence(pulls_api(MERGED, [review()] + comments + requested), COMMIT)

    def test_a_tampered_recorded_approval_is_refused(self):
        cases = {
            "another merge commit": {"merge_commit": EARLIER_COMMIT},
            "the author approving": {"approver_id": 1001},
            "the author's login approving": {"approver_login": "author"},
            "no write association": {"reviewer_association": "CONTRIBUTOR"},
            "no write permission": {"reviewer_permission": "read"},
            "reviewed after the merge": {"review_submitted_at": "2026-09-14T00:00:01Z"},
            "another head reviewed": {"review_commit": "e" * 40},
            "a string id": {"review_id": "9001"},
            "an extra field": {"current_permission": "admin"},
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.check_recorded_approval({**APPROVAL, **change}, COMMIT, V1)

    def test_a_short_sha_and_an_unreachable_commit_are_refused(self):
        with self.assertRaises(Refusal):
            delivery.approval_evidence(pulls_api(MERGED, []), "abc123")
        with self.assertRaises(Refusal):
            delivery.check_reachable(COMMIT, run=lambda *args, **kwargs: subprocess.CompletedProcess(args, 1))


# ---------------------------------------------------------------------- inputs and variables


class ApplyInputs(unittest.TestCase):
    def inputs(self, **overrides):
        env = {
            "PLAN_KEY": f"plans/staging/{COMMIT}/{SHA}.tfplan",
            "PLAN_VERSION_ID": "3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY",
            "PLAN_SHA256": SHA,
            "RELEASE_COMMIT": EARLIER_COMMIT,
            "RELEASE_IMAGE": IMAGE,
            "RELEASE_RECORD_VERSION_ID": "recordversion1",
            "RELEASE_RECORD_SHA256": "f" * 64,
        }
        env.update(overrides)
        return env

    def test_exact_inputs_name_the_source_commit(self):
        self.assertEqual(delivery.validate_apply_inputs(self.inputs())["source_commit"], COMMIT)

    def test_each_malformed_input_is_refused(self):
        cases = {
            "missing key": self.inputs(PLAN_KEY=""),
            "another environment's plan": self.inputs(PLAN_KEY=f"plans/production/{COMMIT}/{SHA}.tfplan"),
            "short commit": self.inputs(PLAN_KEY=f"plans/staging/abc/{SHA}.tfplan"),
            "traversal": self.inputs(PLAN_KEY=f"plans/staging/../{COMMIT}/{SHA}.tfplan"),
            "missing version": self.inputs(PLAN_VERSION_ID=""),
            "null version": self.inputs(PLAN_VERSION_ID="null"),
            "version with a slash": self.inputs(PLAN_VERSION_ID="a/b"),
            "sha mismatch": self.inputs(PLAN_SHA256="d" * 64),
            "upper-case sha": self.inputs(PLAN_SHA256=SHA.upper()),
            "no release image": self.inputs(RELEASE_IMAGE=""),
            "tag-only release image": self.inputs(RELEASE_IMAGE=f"{REPO_URL}:latest"),
            "release tag rather than digest": self.inputs(RELEASE_IMAGE=f"{REPO_URL}:git-{COMMIT}"),
            "tag and digest": self.inputs(RELEASE_IMAGE=f"{REPO_URL}:latest@{DIGEST}"),
            "no release commit": self.inputs(RELEASE_COMMIT=""),
            "no record version": self.inputs(RELEASE_RECORD_VERSION_ID=""),
            "a short record sha": self.inputs(RELEASE_RECORD_SHA256="f" * 10),
        }
        for name, env in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.validate_apply_inputs(env)


TFVARS = {
    "expected_account_id": "111111111111",
    "region": "eu-central-1",
    "reviewer_cidrs": ["11.22.33.0/24"],
    "reviewer_address_space_limit": {"ipv4_addresses": 256, "ipv6_slash64_networks": 0},
    "release_registry_account_id": ACCOUNT,
    "release_registry_region": "eu-central-1",
    "release_repository_name": REPOSITORY_NAME,
}


class EnvironmentVariables(unittest.TestCase):
    def variables(self, workflow="plan", **overrides):
        env = dict(ARTIFACT_ENV)
        if workflow == "plan":
            env["STAGING_TFVARS_JSON"] = json.dumps(TFVARS)
        if workflow == "publish":
            env["ARTIFACT_PUBLISH_ROLE_ARN"] = PUBLISH_ROLE
            env["ARTIFACT_RELEASE_KMS_KEY_ARN"] = f"arn:aws:kms:eu-central-1:111111111111:key/{KEY_ID}"
        else:
            env.update({
                "STAGING_AWS_ACCOUNT_ID": "111111111111",
                "STAGING_AWS_REGION": "eu-central-1",
                "STAGING_STATE_BUCKET": "synthetic-state",
                "STAGING_PLAN_BUCKET": "synthetic-plans",
                "STAGING_STATE_KMS_KEY_ARN": "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-000000000000",
                "STAGING_PLAN_KMS_KEY_ARN": "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-4000-8000-000000000001",
            })
        if workflow == "plan":
            env["STAGING_PLAN_ROLE_ARN"] = "arn:aws:iam::111111111111:role/firmbatch-staging-github-plan"
        elif workflow == "apply":
            env["STAGING_APPLY_ROLE_ARN"] = "arn:aws:iam::111111111111:role/firmbatch-staging-github-apply"
            env["STAGING_MAX_PLAN_AGE_HOURS"] = "24"
            env["RELEASE_IMAGE"] = IMAGE
        env.update(overrides)
        return env

    def test_well_formed_variables_pass(self):
        for workflow in ("publish", "plan", "apply"):
            with self.subTest(workflow=workflow):
                delivery.check_environment_variables(self.variables(workflow), workflow)

    def test_each_departure_is_refused(self):
        cases = {
            "plan using the apply role": ("plan", {"STAGING_PLAN_ROLE_ARN": f"{ROLE_ARN}apply"}),
            "apply using the plan role": ("apply", {"STAGING_APPLY_ROLE_ARN": f"{ROLE_ARN}plan"}),
            "both deployment roles visible": ("plan", {"STAGING_APPLY_ROLE_ARN": f"{ROLE_ARN}apply"}),
            "role in another account": ("plan", {"STAGING_PLAN_ROLE_ARN": "arn:aws:iam::222222222222:role/firmbatch-staging-github-plan"}),
            "shared bucket": ("plan", {"STAGING_PLAN_BUCKET": "synthetic-state"}),
            "key in another region": ("plan", {"STAGING_STATE_KMS_KEY_ARN": f"arn:aws:kms:us-east-1:111111111111:key/{KEY_ID}"}),
            "permanent access key": ("plan", {"AWS_ACCESS_KEY_ID": "SYNTHETICKEY"}),
            "plan age beyond a day": ("apply", {"STAGING_MAX_PLAN_AGE_HOURS": "48"}),
            "plan sees the publish role": ("plan", {"ARTIFACT_PUBLISH_ROLE_ARN": PUBLISH_ROLE}),
            "apply sees the publish role": ("apply", {"ARTIFACT_PUBLISH_ROLE_ARN": PUBLISH_ROLE}),
            "publish sees the plan role": ("publish", {"STAGING_PLAN_ROLE_ARN": f"{ROLE_ARN}plan"}),
            "publish sees the apply role": ("publish", {"STAGING_APPLY_ROLE_ARN": f"{ROLE_ARN}apply"}),
            "publish sees deployment configuration": ("publish", {"STAGING_TFVARS_JSON": "{}"}),
            "publish role in another account": ("publish", {"ARTIFACT_PUBLISH_ROLE_ARN": PUBLISH_ROLE.replace(ACCOUNT, "222222222222")}),
            "publish role with another name": ("publish", {"ARTIFACT_PUBLISH_ROLE_ARN": f"{ROLE_ARN}apply"}),
            "release key in another account": (
                "publish", {"ARTIFACT_RELEASE_KMS_KEY_ARN": f"arn:aws:kms:eu-central-1:222222222222:key/{KEY_ID}"},
            ),
            "malformed registry": ("plan", {"ARTIFACT_REGISTRY_ACCOUNT_ID": "1"}),
            "apply without the record bucket": ("apply", {"ARTIFACT_RELEASE_BUCKET": ""}),
            "apply image from another repository": ("apply", {"RELEASE_IMAGE": IMAGE.replace(ACCOUNT, "222222222222")}),
            "apply image by tag": ("apply", {"RELEASE_IMAGE": f"{REPO_URL}:latest"}),
        }
        for name, (workflow, overrides) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.check_environment_variables(self.variables(workflow, **overrides), workflow)


class RegistryDeclaration(unittest.TestCase):
    """The canonical registry is declared once and named identically everywhere; nothing derives it."""

    ARTIFACT_ACCOUNT = "333333333333"

    def dedicated(self):
        """Every place names a registry in a dedicated artifact account and another region."""
        registry = {
            "ARTIFACT_REGISTRY_ACCOUNT_ID": self.ARTIFACT_ACCOUNT, "ARTIFACT_REGISTRY_REGION": "eu-west-1",
            "ARTIFACT_REPOSITORY_NAME": REPOSITORY_NAME, "ARTIFACT_RELEASE_BUCKET": "synthetic-releases",
        }
        tfvars = {
            **TFVARS, "release_registry_account_id": self.ARTIFACT_ACCOUNT, "release_registry_region": "eu-west-1",
        }
        image = f"{self.ARTIFACT_ACCOUNT}.dkr.ecr.eu-west-1.amazonaws.com/{REPOSITORY_NAME}@{DIGEST}"
        return registry, tfvars, image

    def staging(self, registry, tfvars, **extra):
        return {
            **registry, "STAGING_AWS_ACCOUNT_ID": ACCOUNT, "STAGING_AWS_REGION": "eu-central-1",
            "STAGING_STATE_BUCKET": "synthetic-state", "STAGING_PLAN_BUCKET": "synthetic-plans",
            "STAGING_STATE_KMS_KEY_ARN": f"arn:aws:kms:eu-central-1:{ACCOUNT}:key/{KEY_ID}",
            "STAGING_PLAN_KMS_KEY_ARN": f"arn:aws:kms:eu-central-1:{ACCOUNT}:key/00000000-0000-4000-8000-000000000001",
            "STAGING_TFVARS_JSON": json.dumps(tfvars), **extra,
        }

    def test_a_registry_in_a_dedicated_artifact_account_passes_when_every_place_declares_it(self):
        registry, tfvars, image = self.dedicated()
        plan = self.staging(registry, tfvars, STAGING_PLAN_ROLE_ARN=f"arn:aws:iam::{ACCOUNT}:role/firmbatch-staging-github-plan")
        delivery.check_environment_variables(plan, "plan")
        apply = {
            **self.staging(registry, tfvars, STAGING_APPLY_ROLE_ARN=f"arn:aws:iam::{ACCOUNT}:role/firmbatch-staging-github-apply"),
            "STAGING_MAX_PLAN_AGE_HOURS": "12", "RELEASE_IMAGE": image,
        }
        apply.pop("STAGING_TFVARS_JSON")
        delivery.check_environment_variables(apply, "apply")
        publish = {
            **registry, "ARTIFACT_PUBLISH_ROLE_ARN": f"arn:aws:iam::{self.ARTIFACT_ACCOUNT}:role/firmbatch-artifact-publish",
            "ARTIFACT_RELEASE_KMS_KEY_ARN": f"arn:aws:kms:eu-west-1:{self.ARTIFACT_ACCOUNT}:key/{KEY_ID}",
        }
        delivery.check_environment_variables(publish, "publish")
        with tempfile.TemporaryDirectory() as directory:
            out = pathlib.Path(directory, "staging.tfvars.json")
            delivery.write_tfvars({**plan, "RELEASE_IMAGE": image}, out)
            self.assertEqual(json.loads(out.read_text())["release_image"], image)
        text, _ = delivery.summarize_plan(
            rendering([], release_image=image, registry=(self.ARTIFACT_ACCOUNT, "eu-west-1", REPOSITORY_NAME)), "apply", "1.15.8", image,
        )
        self.assertIn("Sanitized apply summary", text)

    def test_any_place_naming_another_registry_is_refused_before_the_credential(self):
        registry, tfvars, image = self.dedicated()
        role = {"STAGING_PLAN_ROLE_ARN": f"arn:aws:iam::{ACCOUNT}:role/firmbatch-staging-github-plan"}
        cases = {
            # The Terraform inputs silently re-pointed at the staging account and region.
            "plan-time variables naming the staging account": {**tfvars, "release_registry_account_id": ACCOUNT},
            "plan-time variables naming the staging region": {**tfvars, "release_registry_region": "eu-central-1"},
            "plan-time variables naming another repository": {**tfvars, "release_repository_name": "firmbatch/other"},
            "plan-time variables that omit the registry": {k: v for k, v in tfvars.items() if not k.startswith("release_")},
        }
        for name, document in cases.items():
            with self.subTest(case=name):
                with self.assertRaisesRegex(Refusal, "declared registry disagree"):
                    delivery.check_environment_variables(self.staging(registry, document, **role), "plan")
        with self.assertRaisesRegex(Refusal, "STAGING_TFVARS_JSON"):
            delivery.check_environment_variables({**self.staging(registry, tfvars, **role), "STAGING_TFVARS_JSON": ""}, "plan")
        apply = {**self.staging(registry, tfvars), "STAGING_APPLY_ROLE_ARN": f"arn:aws:iam::{ACCOUNT}:role/firmbatch-staging-github-apply",
                 "STAGING_MAX_PLAN_AGE_HOURS": "12", "RELEASE_IMAGE": image.replace(self.ARTIFACT_ACCOUNT, ACCOUNT)}
        with self.assertRaisesRegex(Refusal, "approved release repository"):
            delivery.check_environment_variables(apply, "apply")
        for name, declared in {
            "the plan declaring the staging account": (ACCOUNT, "eu-west-1", REPOSITORY_NAME),
            "the plan declaring no registry": (None, None, None),
        }.items():
            with self.subTest(case=name):
                with self.assertRaisesRegex(Refusal, "release_registry"):
                    delivery.summarize_plan(rendering([], release_image=image, registry=declared), "plan", "1.15.8", image)


class Tfvars(unittest.TestCase):
    base = {
        "expected_account_id": "111111111111",
        "region": "eu-central-1",
        "reviewer_cidrs": ["11.22.33.0/24"],
        "reviewer_address_space_limit": {"ipv4_addresses": 256, "ipv6_slash64_networks": 0},
        "release_registry_account_id": ACCOUNT,
        "release_registry_region": "eu-central-1",
        "release_repository_name": REPOSITORY_NAME,
    }

    def write(self, document, **env):
        environment = {
            "STAGING_TFVARS_JSON": json.dumps(document),
            "STAGING_AWS_ACCOUNT_ID": "111111111111",
            "STAGING_AWS_REGION": "eu-central-1",
            "RELEASE_IMAGE": IMAGE,
            **ARTIFACT_ENV,
            **env,
        }
        with tempfile.TemporaryDirectory() as directory:
            out = pathlib.Path(directory, "staging.tfvars.json")
            delivery.write_tfvars(environment, out)
            return oct(out.stat().st_mode & 0o777), json.loads(out.read_text())

    def test_accepted_variables_are_written_owner_only_with_the_verified_digest(self):
        mode, written = self.write(self.base)
        self.assertEqual(mode, "0o600")
        # Release metadata and the Terraform input agree on the digest: the input IS the record's.
        self.assertEqual(written["release_image"], IMAGE)

    def test_each_unacceptable_document_is_refused(self):
        cases = {
            "open allow-list": ({**self.base, "reviewer_cidrs": ["0.0.0.0/0"]}, {}),
            "empty allow-list": ({**self.base, "reviewer_cidrs": []}, {}),
            "another account": ({**self.base, "expected_account_id": "222222222222"}, {}),
            "another region": ({**self.base, "region": "us-west-2"}, {}),
            "a secret-like key": ({**self.base, "database_password": "x"}, {}),
            "configuration supplying the image": ({**self.base, "release_image": IMAGE}, {}),
            "configuration supplying a digest": ({**self.base, "image_digest": DIGEST}, {}),
            "no verified image": (self.base, {"RELEASE_IMAGE": ""}),
            "a tag-only image": (self.base, {"RELEASE_IMAGE": f"{REPO_URL}:latest"}),
            "an image from another repository": (self.base, {"RELEASE_IMAGE": OTHER_REPO_IMAGE}),
            "a registry the variables disagree with": ({**self.base, "release_registry_account_id": "222222222222"}, {}),
        }
        for name, (document, env) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    self.write(document, **env)


# ---------------------------------------------------------------------- build once: publication


class BuildInputs(unittest.TestCase):
    def test_the_repository_dockerfile_is_digest_pinned_with_no_build_argument(self):
        images = delivery.dockerfile_base_images((delivery.REPO / "Dockerfile").read_text())
        self.assertGreaterEqual(len(images), 2)
        self.assertTrue(all("@sha256:" in image for image in images))

    def test_each_unreproducible_input_is_refused(self):
        cases = {
            "unpinned base": "FROM python:3.11-slim\n",
            "tag only": "FROM python:3.11.16-slim-bookworm AS runtime\n",
            "build argument": "ARG ENVIRONMENT=staging\nFROM python@sha256:" + "0" * 64 + "\n",
            "build argument after FROM": "FROM python@sha256:" + "0" * 64 + "\nARG FIRMBATCH_ENV\n",
            "parameterised base": "FROM ${BASE}@sha256:" + "0" * 64 + "\n",
            "no base": "RUN true\n",
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.dockerfile_base_images(text)


class ReleaseDraft(unittest.TestCase):
    """Before any credential: the built image inspected, its provenance, SBOM and the frozen approval."""

    def test_the_draft_binds_the_local_image_its_provenance_sbom_approval_and_inputs(self):
        draft, blob = draft_for()
        self.assertEqual(draft["local_config_digest"], sha256(blob))
        self.assertEqual(draft["provenance"], {"run_id": "4242", "run_attempt": "1", "created": "2026-09-14T11:00:00Z"})
        self.assertEqual(draft["approval"], APPROVAL)
        self.assertEqual(set(draft["build"]["dependency_locks"]), {"requirements-v1-lock.txt", "portal/package-lock.json"})
        delivery.check_draft(draft)

    def test_each_unpublishable_local_image_is_refused(self):
        labels = image_labels()
        blob = config_blob(labels)
        good = image_inspect(labels, sha256(blob))[0]
        metadata = build_metadata(sha256(blob))
        cases = {
            "an image index": {**good, "Descriptor": {"mediaType": INDEX}},
            "an attestation manifest descriptor": {**good, "Descriptor": {"mediaType": "application/vnd.in-toto+json"}},
            "arm64": {**good, "Architecture": "arm64"},
            "a variant": {**good, "Variant": "v8"},
            "already pushed": {**good, "RepoDigests": [f"{REPO_URL}@{DIGEST}"]},
            "no configuration digest": {**good, "Id": "abc"},
            "another run's labels": {**good, "Config": {"Labels": image_labels(run_id="1")}},
            "another attempt's labels": {**good, "Config": {"Labels": image_labels(attempt="2")}},
            "another commit's labels": {**good, "Config": {"Labels": image_labels(commit=EARLIER_COMMIT)}},
            "another repository's labels": {**good, "Config": {"Labels": image_labels(**{"io.firmbatch.release.repository-id": "1"})}},
            "a missing provenance label": {
                **good, "Config": {"Labels": {k: v for k, v in labels.items() if k != "io.firmbatch.release.run-id"}},
            },
            "a malformed build time": {**good, "Config": {"Labels": image_labels(created="yesterday")}},
            "two images": None,
        }
        for name, image in cases.items():
            with self.subTest(case=name):
                inspect = [good, good] if image is None else [image]
                with self.assertRaises(Refusal):
                    delivery.release_draft(inspect, SBOM, publish_env(), metadata)

    def test_an_image_store_reporting_a_manifest_digest_is_refused_before_any_credential(self):
        # Docker's containerd image store reports the manifest digest as the image ID. The draft used to
        # record it as the configuration digest: the SBOM was stored under it, the push succeeded, and
        # every resume then looked for the SBOM under the registry's configuration digest, stranding the tag.
        labels = image_labels()
        blob = config_blob(labels)
        config_digest = sha256(blob)
        manifest_digest = "sha256:" + "7" * 64
        cases = {
            "the containerd store: a descriptor, and the manifest digest as the image ID": (
                image_inspect(labels, manifest_digest, Descriptor={"mediaType": OCI, "digest": manifest_digest, "size": 1}),
                build_metadata(config_digest, manifest_digest),
            ),
            "a descriptor beside the configuration digest": (
                image_inspect(labels, config_digest, Descriptor={"mediaType": OCI}), build_metadata(config_digest),
            ),
            "a manifest digest as the image ID, with no descriptor": (
                image_inspect(labels, manifest_digest), build_metadata(config_digest, manifest_digest),
            ),
            "no recorded configuration digest": (image_inspect(labels, config_digest), {}),
            "unreadable build metadata": (image_inspect(labels, config_digest), None),
            "a malformed recorded digest": (image_inspect(labels, config_digest), build_metadata("sha256:abc")),
        }
        for name, (inspect, metadata) in cases.items():
            with self.subTest(case=name):
                with self.assertRaisesRegex(Refusal, "before any credential"):
                    delivery.release_draft(inspect, SBOM, publish_env(), metadata)
        draft = delivery.release_draft(image_inspect(labels, config_digest), SBOM, publish_env(), build_metadata(config_digest))
        self.assertEqual(draft["local_config_digest"], config_digest)
        # The key the fresh path stores the SBOM under is the key a resume derives from the registry's bytes.
        registry = Registry()
        registry.push(TAG, blob)
        tag_doc = registry.describe_tag(TAG)
        registry_config = delivery.image_config_digest(REPO_URL, tag_doc, registry.batch_get(tag_doc["imageDetails"][0]["imageDigest"]))
        self.assertEqual(delivery.sbom_key(COMMIT, draft["local_config_digest"]), delivery.sbom_key(COMMIT, registry_config))
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "draft.json")
            path.write_text(json.dumps(draft))
            result = run_cli(["draft-config-digest", "--draft", str(path)], {})
            self.assertEqual((result.returncode, result.stdout.strip()), (0, config_digest), result.stderr)

    def test_a_bad_sbom_approval_or_workflow_is_refused(self):
        labels = image_labels()
        metadata = build_metadata(sha256(config_blob(labels)))
        inspect = image_inspect(labels, sha256(config_blob(labels)))
        cases = {
            "an SBOM that is not SPDX": (b'{"bomFormat": "CycloneDX"}', publish_env()),
            "an SBOM that is not JSON": (b"not json", publish_env()),
            "no approval evidence": (SBOM, {**publish_env(), "APPROVAL_EVIDENCE": ""}),
            "a self-approval": (SBOM, publish_env(approval={**APPROVAL, "approver_id": 1001})),
            "another workflow": (
                SBOM, {**publish_env(), "GITHUB_WORKFLOW_REF": "chamsrut/firmbatch/.github/workflows/ci.yml@refs/heads/main"},
            ),
            "a commit other than the dispatch": (SBOM, {**publish_env(), "GITHUB_SHA": EARLIER_COMMIT}),
        }
        for name, (sbom, env) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.release_draft(inspect, sbom, env, metadata)


class Publication(unittest.TestCase):
    """Publication is an explicit, resumable state machine that never overwrites and never rebuilds for an environment."""

    def test_a_fresh_publication_pushes_once_and_records_this_attempt(self):
        registry, bucket = Registry(), Bucket()
        mode, data = publish(registry, bucket)
        record = json.loads(data)
        self.assertEqual((mode, registry.pushes), ("fresh", 1))
        self.assertEqual(record["publication"]["run_id"], "4242")
        self.assertEqual(record["publication"]["run_attempt"], "1")
        self.assertEqual(record["approval"], APPROVAL)
        self.assertEqual(record["schema_version"], 1)
        self.assertEqual(set(bucket.objects), {delivery.record_key(COMMIT), record["sbom"]["key"]})
        self.assertEqual(delivery.check_release_record(record, COMMIT), record["artifacts"]["control-plane"]["image"])

    def test_a_repeat_dispatch_of_a_completed_publication_changes_nothing(self):
        registry, bucket = published()
        before = copy.deepcopy(bucket.objects)
        mode, data = publish(registry, bucket, run_id="5555")
        self.assertEqual((mode, registry.pushes, bucket.writes), ("resume", 1, 2))
        self.assertEqual(bucket.objects, before)
        self.assertEqual(json.loads(data)["publication"]["run_id"], "4242")

    def test_a_failure_after_the_sbom_and_before_the_push_is_published_afresh_by_the_next_attempt(self):
        registry, bucket = Registry(), Bucket()
        with self.assertRaises(Interrupted):
            publish(registry, bucket, fail="after-sbom")
        mode, data = publish(registry, bucket, run_id="4343")
        record = json.loads(data)
        self.assertEqual((mode, registry.pushes), ("fresh", 1))
        self.assertEqual(record["publication"]["run_id"], "4343")
        self.assertEqual(len(bucket.objects), 3)  # the first attempt's SBOM stays, named by no record

    def test_a_failure_after_the_push_is_resumed_without_a_second_push_and_names_the_original_attempt(self):
        for fail in ("after-push", "after-identity", "before-record"):
            with self.subTest(fail=fail):
                registry, bucket = Registry(), Bucket()
                with self.assertRaises(Interrupted):
                    publish(registry, bucket, fail=fail)
                mode, data = publish(registry, bucket, run_id="4343", attempt="1")
                record = json.loads(data)
                self.assertEqual((mode, registry.pushes), ("resume", 1))
                self.assertEqual((record["publication"]["run_id"], record["publication"]["run_attempt"]), ("4242", "1"))

    def test_a_rerun_attempt_of_the_same_run_resumes_the_attempt_that_pushed(self):
        registry, bucket = Registry(), Bucket()
        with self.assertRaises(Interrupted):
            publish(registry, bucket, fail="after-push")
        mode, data = publish(registry, bucket, run_id="4242", attempt="2")
        self.assertEqual(mode, "resume")
        self.assertEqual(json.loads(data)["publication"]["run_attempt"], "1")

    def test_a_lost_record_response_is_proven_complete_by_reading_the_object_back(self):
        registry, bucket = Registry(), Bucket()
        mode, data = publish(registry, bucket, fail="record-response-lost")
        self.assertEqual(bucket.get(delivery.record_key(COMMIT))[0], data)

    def test_the_record_is_regenerated_byte_for_byte(self):
        registry, bucket = published()
        first = bucket.get(delivery.record_key(COMMIT))[0]
        for run_id in ("6000", "6001"):
            _, again = publish(registry, bucket, run_id=run_id)
            self.assertEqual(again, first)

    def test_a_tag_with_incompatible_provenance_stops_for_human_recovery(self):
        for name, labels in {
            "another commit": image_labels(run_id="1", commit=EARLIER_COMMIT),
            "another repository": image_labels(run_id="1", **{"io.firmbatch.release.repository-id": "1"}),
            "another workflow": image_labels(
                run_id="1", **{"io.firmbatch.release.workflow-ref": "x/y/.github/workflows/z.yml@refs/heads/main"},
            ),
            "no provenance": {"maintainer": "someone"},
        }.items():
            with self.subTest(case=name):
                registry, bucket = Registry(), Bucket()
                registry.push(TAG, config_blob(labels))
                with self.assertRaisesRegex(Refusal, "human recovery"):
                    publish(registry, bucket, run_id="4343")
                self.assertEqual(registry.pushes, 1)
                self.assertFalse(bucket.objects.get(delivery.record_key(COMMIT)))

    def test_a_tag_carrying_another_tag_or_an_index_is_refused(self):
        registry, bucket = Registry(), Bucket()
        with self.assertRaises(Interrupted):
            publish(registry, bucket, fail="after-push")
        registry.images[TAG]["tags"].append("latest")
        with self.assertRaises(Refusal):
            publish(registry, bucket, run_id="4343")
        registry, bucket = Registry(), Bucket()
        registry.push(TAG, config_blob(image_labels()), media=INDEX)
        with self.assertRaises(Refusal):
            publish(registry, bucket, run_id="4343")

    def test_a_resumed_publication_whose_sbom_is_missing_is_refused(self):
        registry, bucket = Registry(), Bucket()
        with self.assertRaises(Interrupted):
            publish(registry, bucket, fail="after-push")
        bucket.objects.clear()
        with self.assertRaises(Interrupted):
            publish(registry, bucket, run_id="4343")
        self.assertNotIn(delivery.record_key(COMMIT), bucket.objects)

    def test_an_existing_record_for_another_digest_fails_closed(self):
        registry, bucket = published()
        body, metadata, version = bucket.objects[delivery.record_key(COMMIT)]
        record = json.loads(body)
        record["artifacts"]["control-plane"]["digest"] = EARLIER_DIGEST
        bucket.objects[delivery.record_key(COMMIT)] = (delivery.record_bytes(record), metadata, version)
        with self.assertRaisesRegex(Refusal, "human recovery"):
            publish(registry, bucket, run_id="4343")

    def test_an_existing_object_with_the_same_bytes_but_another_identity_fails_closed(self):
        registry, bucket = published()
        key = delivery.record_key(COMMIT)
        body, metadata, version = bucket.objects[key]
        for change in ({"firmbatch-digest": EARLIER_DIGEST}, {"firmbatch-kind": "sbom"}, {"firmbatch-sha256": "0" * 64}):
            with self.subTest(change=change):
                bucket.objects[key] = (body, {**metadata, **change}, version)
                with self.assertRaises(Refusal):
                    publish(registry, bucket, run_id="4343")
        bucket.objects[key] = (body, metadata, version)
        existing, head = bucket.get(key)
        with self.assertRaises(Refusal):
            delivery.compare_release_object("record", COMMIT, json.loads(body)["artifacts"]["control-plane"]["digest"], body, existing,
                                            {**head, "ServerSideEncryption": "AES256"})

    def test_a_fresh_push_the_registry_disagrees_with_is_refused(self):
        registry = Registry()
        draft, blob = draft_for()
        registry.push(TAG, blob)
        tag_doc = registry.describe_tag(TAG)
        digest = tag_doc["imageDetails"][0]["imageDigest"]
        manifest = registry.batch_get(digest)
        cases = {
            "the push reported another digest": (manifest, blob, f"{REPO_URL}@{EARLIER_DIGEST}"),
            "a manifest that does not hash to the digest": (
                {**manifest, "images": [{**manifest["images"][0], "imageManifest": manifest["images"][0]["imageManifest"] + " "}]},
                blob, f"{REPO_URL}@{digest}",
            ),
            "a configuration blob that does not hash to its digest": (manifest, blob + b" ", f"{REPO_URL}@{digest}"),
            "a registry failure entry": ({**manifest, "failures": [{"failureCode": "ImageNotFound"}]}, blob, f"{REPO_URL}@{digest}"),
        }
        for name, (manifest_doc, config, local) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.registry_identity(draft, "fresh", REPO_URL, tag_doc, manifest_doc, config, local)
        other_draft, _ = draft_for(run_id="9999")
        with self.assertRaisesRegex(Refusal, "human recovery"):
            delivery.registry_identity(other_draft, "fresh", REPO_URL, tag_doc, manifest, blob, f"{REPO_URL}@{digest}")

    def test_a_post_push_configuration_digest_mismatch_writes_no_record_and_the_comparison_is_load_bearing(self):
        # Three digests never to be confused: the local image ID, which Docker's containerd store reports as the
        # manifest digest; BuildKit's configuration digest; and the registry's manifest digest.
        labels = image_labels()
        blob = config_blob(labels)
        buildkit_config = sha256(blob)
        registry, bucket = Registry(), Bucket()
        pushed = registry.push(TAG, blob)  # the irreversible action
        tag_doc = registry.describe_tag(TAG)
        manifest_digest = tag_doc["imageDetails"][0]["imageDigest"]
        manifest = registry.batch_get(manifest_digest)
        registry_config = delivery.image_config_digest(REPO_URL, tag_doc, manifest)
        local_image_id = manifest_digest
        self.assertEqual(registry_config, buildkit_config)
        self.assertNotEqual(local_image_id, buildkit_config)
        self.assertEqual(pushed, f"{REPO_URL}@{manifest_digest}")

        # Before any credential, the draft refuses a local image ID that is not the build's configuration digest,
        # so the workflow never reaches the push holding the wrong digest.
        with self.assertRaisesRegex(Refusal, "before any credential"):
            delivery.release_draft(
                image_inspect(labels, local_image_id), SBOM, publish_env(), build_metadata(buildkit_config, manifest_digest),
            )

        # A draft carrying the local image ID can only come from bypassing that check. Give it every other chance:
        # an SBOM stored under the digest it attests and one under the registry's configuration digest.
        good, _ = draft_for()
        forged = {**good, "local_config_digest": local_image_id}
        put_once(bucket, delivery.sbom_key(COMMIT, local_image_id), SBOM, "sbom", local_image_id)
        put_once(bucket, delivery.sbom_key(COMMIT, registry_config), SBOM, "sbom", registry_config)
        writes = bucket.writes
        config = registry.blobs[registry_config]
        with self.assertRaisesRegex(Refusal, "not the image this attempt built; explicit human recovery"):
            delivery.registry_identity(forged, "fresh", REPO_URL, tag_doc, manifest, config, pushed)
        self.assertNotIn(delivery.record_key(COMMIT), bucket.objects)
        self.assertEqual(bucket.writes, writes)

        # The mutation: the same code without the post-push configuration-digest comparison publishes a record that
        # binds the pushed image to a draft that attested another digest. The comparison is what refuses it.
        source = pathlib.Path(delivery.__file__).read_text(encoding="utf-8")
        comparison = 'if config_digest != draft["local_config_digest"] or provenance != draft["provenance"]:'
        self.assertEqual(source.count(comparison), 1)
        mutant = type(sys)("delivery_without_the_config_comparison")
        mutant.__file__ = delivery.__file__
        sys.modules[mutant.__name__] = mutant
        try:
            exec(compile(source.replace(comparison, 'if provenance != draft["provenance"]:'), delivery.__file__, "exec"), mutant.__dict__)
        finally:
            sys.modules.pop(mutant.__name__, None)
        identity = mutant.registry_identity(forged, "fresh", REPO_URL, tag_doc, manifest, config, pushed)
        sbom_body, sbom_head = bucket.get(delivery.sbom_key(COMMIT, identity["config_digest"]))
        record = mutant.build_release_record(forged, identity, sbom_body, sbom_head)
        self.assertEqual(record["artifacts"]["control-plane"]["config_digest"], buildkit_config)
        self.assertNotEqual(record["artifacts"]["control-plane"]["config_digest"], forged["local_config_digest"])

    def test_the_record_holds_no_credential_plan_or_environment_configuration(self):
        _, data = publish(Registry(), Bucket())
        rendered = data.decode().lower()
        for forbidden in ("password", "secret", "token", "credential", "tfplan", "tfvars", "staging", "aws_access"):
            self.assertNotIn(forbidden, rendered)


class ReleaseRecordContract(unittest.TestCase):
    """Release records are versioned; each version's contract is frozen with it."""

    def record(self):
        _, data = publish(Registry(), Bucket())
        return json.loads(data)

    def test_every_tampered_record_is_refused(self):
        def tamper(change):
            record = copy.deepcopy(self.record())
            change(record)
            return record

        cases = {
            "a credential field": lambda r: r.__setitem__("credentials", {"aws_secret_access_key": "x"}),
            "a plan": lambda r: r.__setitem__("plan", {"key": "plans/staging/x.tfplan"}),
            "environment configuration": lambda r: r["build"].__setitem__("environment", "staging"),
            "another commit": lambda r: r["source"].__setitem__("commit", "f" * 40),
            "a fork": lambda r: r["source"].__setitem__("repository", "someone/firmbatch"),
            "another ref": lambda r: r["source"].__setitem__("ref", "refs/heads/feature"),
            "a tag-only artifact": lambda r: r["artifacts"]["control-plane"].__setitem__("image", f"{REPO_URL}:git-{COMMIT}"),
            "digest and image disagree": lambda r: r["artifacts"]["control-plane"].__setitem__("digest", EARLIER_DIGEST),
            "a mutable tag": lambda r: r["artifacts"]["control-plane"].__setitem__("tag", "latest"),
            "no configuration digest": lambda r: r["artifacts"]["control-plane"].__setitem__("config_digest", ""),
            "a build argument": lambda r: r["build"].__setitem__("build_arguments", ["FIRMBATCH_ENV=staging"]),
            "an unpinned base": lambda r: r["build"].__setitem__("base_images", ["python:3.11-slim"]),
            "a missing lock digest": lambda r: r["build"]["dependency_locks"].pop("portal/package-lock.json"),
            "an extra lock": lambda r: r["build"]["dependency_locks"].__setitem__("gpu/requirements-lock.txt", "0" * 64),
            "a branch workflow": lambda r: r["publication"].__setitem__(
                "workflow_ref", "chamsrut/firmbatch/.github/workflows/artifact-publish.yml@refs/heads/feature"
            ),
            "another workflow": lambda r: r["publication"].__setitem__("workflow", ".github/workflows/ci.yml"),
            "no run attempt": lambda r: r["publication"].__setitem__("run_attempt", ""),
            "a numeric run id": lambda r: r["publication"].__setitem__("run_id", 4242),
            "an SBOM of another image": lambda r: r["sbom"].__setitem__("key", f"releases/{COMMIT}/sbom-{'0' * 64}.spdx.json"),
            "no SBOM digest": lambda r: r["sbom"].__setitem__("sha256", ""),
            "a component unmapped": lambda r: r["components"].pop("identity_binding"),
            "a component outside the contract": lambda r: r["components"].__setitem__("gpu_worker", "control-plane"),
            "an approval from the author": lambda r: r["approval"].__setitem__("approver_id", 1001),
            "malformed signatures": lambda r: r.__setitem__("signatures", "unsigned"),
            "an unknown schema name": lambda r: r.__setitem__("schema", "firmbatch.release-manifest.v1"),
            "an unknown schema version": lambda r: r.__setitem__("schema_version", 2),
            "a boolean schema version": lambda r: r.__setitem__("schema_version", True),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.check_release_record(tamper(change), COMMIT)

    def test_the_record_is_checked_against_the_commit_being_promoted(self):
        with self.assertRaises(Refusal):
            delivery.check_release_record(self.record(), EARLIER_COMMIT)

    def test_a_later_contract_version_leaves_earlier_rollback_records_valid(self):
        v1_record = self.record()
        v1 = delivery.RELEASE_CONTRACTS[1]
        v2 = dataclasses.replace(
            v1, version=2, components=v1.components + ("gpu_worker",), lock_files=v1.lock_files + ("gpu/requirements-lock.txt",),
        )
        with mock.patch.dict(delivery.RELEASE_CONTRACTS, {2: v2}):
            self.assertEqual(delivery.check_release_record(v1_record, COMMIT), v1_record["artifacts"]["control-plane"]["image"])
            v2_record = copy.deepcopy(v1_record)
            v2_record["schema_version"] = 2
            v2_record["components"]["gpu_worker"] = "control-plane"
            v2_record["build"]["dependency_locks"]["gpu/requirements-lock.txt"] = "0" * 64
            delivery.check_release_record(v2_record, COMMIT)
            with self.assertRaises(Refusal):
                delivery.check_release_record({**v2_record, "schema_version": 1}, COMMIT)
        with self.assertRaises(Refusal):
            delivery.check_release_record(v2_record, COMMIT)

    def test_retiring_a_version_is_an_explicit_removal(self):
        record = self.record()
        with mock.patch.dict(delivery.RELEASE_CONTRACTS, clear=True):
            with self.assertRaisesRegex(Refusal, "unknown or retired"):
                delivery.check_release_record(record, COMMIT)


# ---------------------------------------------------------------------- promotion and apply re-verification


class Admission(unittest.TestCase):
    """Zero Critical and High by default; exact, digest-scoped, expiring exceptions; security stops."""

    def test_the_committed_policy_is_the_fail_closed_default(self):
        committed = json.loads(delivery.ADMISSION_POLICY_PATH.read_text())
        delivery.check_admission_policy(committed, NOW)
        self.assertEqual(committed["maximum_findings"], {"CRITICAL": 0, "HIGH": 0})
        self.assertEqual((committed["exceptions"], committed["security_stops"]), ([], []))

    def test_a_clean_scan_is_admitted_and_a_finding_over_the_maxima_is_not(self):
        delivery.check_admission(admission_policy(), DIGEST, COMMIT, scan_doc(), NOW)
        for severity in ("CRITICAL", "HIGH"):
            with self.subTest(severity=severity):
                with self.assertRaises(Refusal):
                    finding = scan_doc(findings=[{"name": "CVE-2026-9999", "severity": severity}])
                    delivery.check_admission(admission_policy(), DIGEST, COMMIT, finding, NOW)

    def test_an_unexpired_exception_for_the_exact_digest_and_identifier_admits_its_finding(self):
        critical = scan_doc(findings=[{"name": "CVE-2026-9999", "severity": "CRITICAL"}])
        delivery.check_admission(admission_policy([exception()]), DIGEST, COMMIT, critical, NOW)
        enhanced_finding = {"severity": "HIGH", "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2026-9999"}}
        enhanced = scan_doc(findings=[], enhanced=[enhanced_finding])
        delivery.check_admission(admission_policy([exception()]), DIGEST, COMMIT, enhanced, NOW)

    def test_an_exception_that_does_not_exactly_apply_admits_nothing(self):
        critical = scan_doc(findings=[{"name": "CVE-2026-9999", "severity": "CRITICAL"}, {"name": "CVE-2026-8888", "severity": "HIGH"}])
        cases = {
            "expired": [exception(ids=("CVE-2026-9999", "CVE-2026-8888"), expires="2026-09-14T11:00:00Z")],
            "another digest": [exception(digest=EARLIER_DIGEST, ids=("CVE-2026-9999", "CVE-2026-8888"))],
            "not every identifier": [exception(ids=("CVE-2026-9999",))],
            "another identifier": [exception(ids=("CVE-2026-7777",))],
        }
        for name, exceptions in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.check_admission(admission_policy(exceptions), DIGEST, COMMIT, critical, NOW)

    def test_a_malformed_or_overly_broad_exception_refuses_every_admission(self):
        cases = {
            "no expiry": exception(expires=None),
            "a lifetime over 30 days": exception(expires="2026-10-10T00:00:01Z"),
            "expiring before creation": exception(created="2026-09-20T00:00:00Z", expires="2026-09-19T00:00:00Z"),
            "created in the future": exception(created="2026-09-15T00:00:00Z", expires="2026-09-20T00:00:00Z"),
            "a wildcard identifier": exception(ids=("CVE-2026-*",)),
            "a prefix identifier": exception(ids=("CVE-2026",)),
            "no identifier": exception(ids=()),
            "more than ten identifiers": exception(ids=tuple(f"CVE-2026-{1000 + n}" for n in range(11))),
            "a repeated identifier": exception(ids=("CVE-2026-9999", "CVE-2026-9999")),
            "no exact digest": exception(digest="sha256:*"),
            "no reason": exception(reason="because"),
            "no approver": exception(approver={"login": "", "id": 0}),
            "no reviewed pull request": exception(approval_reference="approved in chat"),
            "an extra key": {**exception(), "applies_to": "all images"},
        }
        for name, entry in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.check_admission(admission_policy([entry]), DIGEST, COMMIT, scan_doc(), NOW)

    def test_a_security_stop_refuses_the_release_whatever_its_scan_and_approval(self):
        stop = {
            "image_digest": DIGEST, "release_commit": COMMIT, "reason": "credential exposure in the image",
            "reference": "https://github.com/chamsrut/firmbatch/pull/99", "created_at": "2026-09-14T09:00:00Z",
        }
        for entry in (stop, {**stop, "image_digest": EARLIER_DIGEST}, {**stop, "release_commit": EARLIER_COMMIT}):
            with self.subTest(entry=entry):
                with self.assertRaisesRegex(Refusal, "security stop"):
                    delivery.check_admission(admission_policy(stops=[entry]), DIGEST, COMMIT, scan_doc(), NOW)

    def test_an_incomplete_or_foreign_scan_is_refused(self):
        cases = {
            "in progress": scan_doc(status="IN_PROGRESS"),
            "another digest": scan_doc(digest=EARLIER_DIGEST),
            "counts that hide a finding": scan_doc(findings=[], counts={"CRITICAL": 1}),
            "a finding the counts omit": scan_doc(findings=[{"name": "CVE-2026-1", "severity": "LOW"}], counts={}),
            "a malformed finding": scan_doc(findings=[{"severity": "LOW"}]),
            "no findings section": {"imageId": {"imageDigest": DIGEST}, "imageScanStatus": {"status": "COMPLETE"}},
        }
        for name, document in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.check_admission(admission_policy(), DIGEST, COMMIT, document, NOW)


class Promotion(unittest.TestCase):
    """verify-release, at plan and again immediately before apply."""

    def setUp(self):
        self.registry, self.bucket = published()
        self.data, self.head = self.bucket.get(delivery.record_key(COMMIT))
        self.record = json.loads(self.data)
        self.image = self.record["artifacts"]["control-plane"]["image"]
        self.digest = self.record["artifacts"]["control-plane"]["digest"]

    def verify(self, api=None, **overrides):
        arguments = {
            "api": api or attempt_api(self.record), "env": ARTIFACT_ENV, "record_data": self.data, "record_head": self.head,
            "commit": COMMIT, "repository_doc": repository_doc(), "images_doc": self.registry.describe_tag(TAG),
            "scan_doc": scan_doc(digest=self.digest), "policy": admission_policy(), "now": NOW,
        }
        arguments.update(overrides)
        return delivery.verify_release(**arguments)

    def test_a_published_release_is_verified_with_its_exact_record_identity(self):
        outputs = self.verify()
        self.assertEqual(outputs["release_image"], self.image)
        self.assertEqual(outputs["release_record_version_id"], self.head["VersionId"])
        self.assertEqual(outputs["release_record_sha256"], hashlib.sha256(self.data).hexdigest())
        self.verify(expected_version_id=outputs["release_record_version_id"], expected_sha256=outputs["release_record_sha256"],
                    expected_image=self.image)

    def test_promotion_validates_the_frozen_approval_never_a_current_permission_or_a_later_review(self):
        calls = []
        self.verify(api=attempt_api(self.record, calls=calls))
        self.assertFalse([path for path in calls if "/collaborators/" in path or "/reviews" in path])
        self.assertIn("/repos/chamsrut/firmbatch/pulls/7", calls)

    def test_the_exact_publish_attempt_is_queried_so_a_later_failed_rerun_changes_nothing(self):
        calls = []
        self.verify(api=attempt_api(self.record, calls=calls, aggregate_conclusion="failure"))
        self.assertNotIn("/repos/chamsrut/firmbatch/actions/runs/4242", calls)
        self.assertIn("/repos/chamsrut/firmbatch/actions/runs/4242/attempts/1", calls)

    def test_a_publication_resumed_after_its_attempt_failed_is_still_the_exact_attempt(self):
        jobs = [{"name": name, "run_attempt": 1, "status": "completed", "conclusion": "success"} for name in V1.publish_gate_jobs]
        jobs.append({"name": V1.publish_job, "run_attempt": 1, "status": "completed", "conclusion": "failure"})
        self.verify(api=attempt_api(self.record, attempt_overrides={"conclusion": "failure"}, jobs=jobs))

    def test_each_unverifiable_publish_attempt_is_refused(self):
        gates = [{"name": name, "run_attempt": 1, "status": "completed", "conclusion": "success"} for name in V1.publish_gate_jobs]
        publication_job = {"name": V1.publish_job, "run_attempt": 1, "status": "completed", "conclusion": "success"}
        cases = {
            "another workflow": {"attempt_overrides": {"path": ".github/workflows/ci.yml"}},
            "another commit": {"attempt_overrides": {"head_sha": "f" * 40}},
            "another branch": {"attempt_overrides": {"head_branch": "feature"}},
            "a pull request event": {"attempt_overrides": {"event": "pull_request"}},
            "still running": {"attempt_overrides": {"status": "in_progress"}},
            "a fork's repository": {"attempt_overrides": {"repository": {"id": 1}}},
            "a failed verification gate": {"jobs": [{**gates[2], "conclusion": "failure"}, *gates[:2], gates[3], publication_job]},
            "a missing gate": {"jobs": [*gates[1:], publication_job]},
            "a gate from another attempt": {"jobs": [{**gates[0], "run_attempt": 2}, *gates[1:], publication_job]},
            "a publication job that never ran": {"jobs": [*gates, {**publication_job, "conclusion": "skipped"}]},
        }
        for name, overrides in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    self.verify(api=attempt_api(self.record, **overrides))
        with self.assertRaises(Refusal):
            self.verify(api=lambda path: None)

    def test_a_changed_pull_request_fact_is_refused(self):
        changes = ({"merged_at": "2026-09-14T01:00:00Z"}, {"head": {"sha": "e" * 40}}, {"user": {"id": 1}}, {"merge_commit_sha": "e" * 40})
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(Refusal):
                    self.verify(api=attempt_api(self.record, pull_overrides=change))

    def test_apply_refuses_any_relationship_that_changed(self):
        outputs = self.verify()
        cases = {
            "another record version": {"expected_version_id": "v9", "expected_sha256": outputs["release_record_sha256"]},
            "another record content": {"expected_version_id": outputs["release_record_version_id"], "expected_sha256": "0" * 64},
            "another dispatched image": {"expected_image": f"{REPO_URL}@{EARLIER_DIGEST}"},
            "the digest now carries another tag": {"images_doc": {"imageDetails": [
                {**self.registry.describe_tag(TAG)["imageDetails"][0], "imageTags": [TAG, "x"]},
            ]}},
            "the digest is gone": {"images_doc": {"imageDetails": []}},
            "the scan now finds a critical": {
                "scan_doc": scan_doc(digest=self.digest, findings=[{"name": "CVE-2026-9", "severity": "CRITICAL"}]),
            },
            "the repository became mutable": {"repository_doc": repository_doc(imageTagMutability="MUTABLE")},
            "a security stop was committed": {"policy": admission_policy(stops=[{
                "image_digest": self.digest, "release_commit": COMMIT, "reason": "revoked",
                "reference": "https://github.com/chamsrut/firmbatch/pull/99", "created_at": "2026-09-14T09:00:00Z",
            }])},
            "the exception expired since the plan": {
                "scan_doc": scan_doc(digest=self.digest, findings=[{"name": "CVE-2026-9999", "severity": "CRITICAL"}]),
                "policy": admission_policy([exception(digest=self.digest, expires="2026-09-14T11:59:00Z")]),
            },
            "the record's stored identity is not its content": {
                "record_head": {**self.head, "Metadata": {**self.head["Metadata"], "firmbatch-sha256": "0" * 64}},
            },
            "another registry configured": {"env": {**ARTIFACT_ENV, "ARTIFACT_REGISTRY_ACCOUNT_ID": "222222222222"}},
            "a record for another commit": {"commit": EARLIER_COMMIT},
        }
        for name, overrides in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    self.verify(**overrides)

    def test_rollback_promotes_an_earlier_retained_digest_and_refuses_one_that_is_gone(self):
        image = delivery.check_release_record(self.record, COMMIT)
        retained, scan = self.registry.describe_tag(TAG), scan_doc(digest=self.digest)
        delivery.check_release_image(image, COMMIT, repository_doc(), retained, scan, admission_policy(), NOW)
        with self.assertRaises(Refusal):
            delivery.check_release_image(image, COMMIT, repository_doc(), {"imageDetails": []}, scan, admission_policy(), NOW)

    def test_the_release_digest_command_prints_only_the_recorded_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "record.json")
            path.write_bytes(self.data)
            result = run_cli(["release-digest", "--record", str(path), "--commit", COMMIT], {})
            self.assertEqual((result.returncode, result.stdout.strip()), (0, self.digest))
            refused = run_cli(["release-digest", "--record", str(path), "--commit", EARLIER_COMMIT], {})
            self.assertEqual(refused.returncode, 3)


class SecurityOverlay(unittest.TestCase):
    """verify-release, as staging-apply runs it, applies the admission policy origin/main holds now --
    never the plan's older checkout, whose copy is ADMISSION_POLICY_PATH."""

    def setUp(self):
        self.registry, self.bucket = published()
        self.data, self.head = self.bucket.get(delivery.record_key(COMMIT))
        self.record = json.loads(self.data)
        self.digest = self.record["artifacts"]["control-plane"]["digest"]
        self.image = self.record["artifacts"]["control-plane"]["image"]

    def stop(self):
        return {
            "image_digest": self.digest, "release_commit": COMMIT, "reason": "credential exposure found after the plan",
            "reference": "https://github.com/chamsrut/firmbatch/pull/99", "created_at": "2026-09-14T11:30:00Z",
        }

    def dispatch_verify_release(self, main_policy, scan=None):
        """The verify-release command line of staging-apply, end to end, with only git and GitHub faked."""
        git_calls = []

        def git(argv, **kwargs):
            git_calls.append(argv)
            if argv != ["git", "show", "origin/main:infra/delivery/admission-policy.json"]:
                raise AssertionError(f"verify-release ran an unexpected command: {argv}")
            if main_policy is None:
                return subprocess.CompletedProcess(argv, 128, stdout=b"")
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(main_policy).encode())

        with tempfile.TemporaryDirectory() as directory:
            def write(name, content):
                path = pathlib.Path(directory, name)
                path.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode())
                return str(path)

            argv = [
                "verify-release", "--record", write("record.json", self.data), "--record-head", write("head.json", self.head),
                "--commit", COMMIT, "--repository-json", write("repository.json", repository_doc()),
                "--image-json", write("image.json", self.registry.describe_tag(TAG)),
                "--scan-json", write("scan.json", scan or scan_doc(digest=self.digest)),
                "--expected-record-version-id", self.head["VersionId"],
                "--expected-record-sha256", hashlib.sha256(self.data).hexdigest(), "--expected-image", self.image,
            ]
            output = pathlib.Path(directory, "github-output")
            with mock.patch.object(delivery.subprocess, "run", git), \
                    mock.patch.object(delivery, "_api_from_env", lambda env: attempt_api(self.record)), \
                    mock.patch.object(delivery, "_now", lambda: NOW), \
                    mock.patch.object(delivery, "ADMISSION_POLICY_PATH", pathlib.Path(directory, "no-checkout-copy.json")), \
                    mock.patch.dict("os.environ", {"GITHUB_OUTPUT": str(output)}), \
                    mock.patch("sys.stdout", new_callable=io.StringIO):
                delivery._dispatch(delivery._parser().parse_args(argv), {**ARTIFACT_ENV, "GITHUB_TOKEN": "synthetic"})
            return git_calls, output.read_text()

    def test_a_stop_merged_to_main_after_the_plan_refuses_the_apply_the_checkout_would_admit(self):
        # The checkout an apply runs from is the plan's commit, whose admission policy has no stop.
        self.assertEqual(json.loads(delivery.ADMISSION_POLICY_PATH.read_text())["security_stops"], [])
        with self.assertRaisesRegex(Refusal, "security stop"):
            self.dispatch_verify_release(admission_policy(stops=[self.stop()]))

    def test_an_exception_removed_on_main_after_the_plan_no_longer_admits_its_finding(self):
        critical = scan_doc(digest=self.digest, findings=[{"name": "CVE-2026-9999", "severity": "CRITICAL"}])
        calls, outputs = self.dispatch_verify_release(admission_policy([exception(digest=self.digest)]), scan=critical)
        self.assertIn(f"release_image={self.image}", outputs)
        with self.assertRaisesRegex(Refusal, "CRITICAL"):
            self.dispatch_verify_release(admission_policy(), scan=critical)

    def test_the_overlay_is_read_from_main_and_nowhere_else(self):
        calls, outputs = self.dispatch_verify_release(admission_policy())
        self.assertEqual(calls, [["git", "show", "origin/main:infra/delivery/admission-policy.json"]])
        self.assertIn(f"release_record_sha256={hashlib.sha256(self.data).hexdigest()}", outputs)
        with self.assertRaisesRegex(Refusal, "could not be read from origin/main"):
            self.dispatch_verify_release(None)
        with self.assertRaisesRegex(Refusal, "unknown schema"):
            self.dispatch_verify_release({**admission_policy(), "schema_version": 3})


class HistoricalContract(unittest.TestCase):
    """A release is interpreted by the contract of the version it declares -- its workflow identity, gate-job
    names and approval rules -- so a later contract neither invalidates nor reinterprets an earlier record."""

    def setUp(self):
        self.registry, self.bucket = published()
        self.data, self.head = self.bucket.get(delivery.record_key(COMMIT))
        self.record = json.loads(self.data)
        self.digest = self.record["artifacts"]["control-plane"]["digest"]

    def verify(self, api):
        return delivery.verify_release(
            api=api, env=ARTIFACT_ENV, record_data=self.data, record_head=self.head, commit=COMMIT, repository_doc=repository_doc(),
            images_doc=self.registry.describe_tag(TAG), scan_doc=scan_doc(digest=self.digest), policy=admission_policy(), now=NOW,
        )

    def test_a_renamed_publication_workflow_is_a_new_version_and_version_one_rollback_still_verifies(self):
        renamed = ".github/workflows/release-publish.yml"
        v2 = dataclasses.replace(V1, version=2, workflow=renamed, workflow_ref=f"chamsrut/firmbatch/{renamed}@refs/heads/main")
        with mock.patch.dict(delivery.RELEASE_CONTRACTS, {2: v2}), mock.patch.object(delivery, "CURRENT_RELEASE_SCHEMA_VERSION", 2), \
                mock.patch.object(delivery, "PUBLISH_WORKFLOW", renamed):
            # The unchanged, valid v1 record -- whose attempt ran artifact-publish.yml -- verifies by its own identity,
            # even with the module-level workflow and the current contract both renamed.
            self.assertEqual(self.record["publication"]["workflow"], V1.workflow)
            self.verify(attempt_api(self.record))
            # The current contract cannot reinterpret it: an attempt of the renamed workflow is not its attempt.
            with self.assertRaisesRegex(Refusal, "publication workflow"):
                self.verify(attempt_api(self.record, attempt_overrides={"path": renamed}))
            # Relabelling the record as v2 does not move it under the new identity.
            with self.assertRaisesRegex(Refusal, "not published by"):
                delivery.check_release_record({**self.record, "schema_version": 2}, COMMIT)
        # Unknown versions still fail closed.
        for version in (2, 3, 0):
            with self.subTest(version=version):
                with self.assertRaisesRegex(Refusal, "unknown or retired"):
                    delivery.check_release_record({**self.record, "schema_version": version}, COMMIT)

    def test_renamed_jobs_and_changed_approval_rules_are_a_new_version_that_does_not_invalidate_an_earlier_release(self):
        v2 = dataclasses.replace(
            V1, version=2, publish_gate_jobs=tuple(f"{name} (renamed)" for name in V1.publish_gate_jobs),
            publish_job=f"{V1.publish_job} (renamed)", qualifying_associations=("OWNER",), write_permissions=("admin",),
        )
        done = {"run_attempt": 1, "status": "completed", "conclusion": "success"}
        v2_jobs = [{"name": name, **done} for name in (*v2.publish_gate_jobs, v2.publish_job)]
        with mock.patch.dict(delivery.RELEASE_CONTRACTS, {2: v2}), mock.patch.object(delivery, "CURRENT_RELEASE_SCHEMA_VERSION", 2):
            # The v1 release -- a COLLABORATOR's write approval, v1's job names -- still promotes and rolls back.
            self.verify(attempt_api(self.record))
            # It is judged by v1's job names, never the current contract's.
            with self.assertRaisesRegex(Refusal, "gate"):
                self.verify(attempt_api(self.record, jobs=v2_jobs))
            # A record declaring v2 is judged by v2's rules, under which that approval no longer qualifies.
            with self.assertRaisesRegex(Refusal, "without write access"):
                delivery.check_release_record({**self.record, "schema_version": 2}, COMMIT)
            # And a new publication's approval is computed under the current contract.
            with self.assertRaises(Refusal):
                delivery.approval_evidence(pulls_api(MERGED, [review()]), COMMIT)
            self.assertEqual(delivery.approval_evidence(pulls_api(MERGED, [review()]), COMMIT, V1), APPROVAL)

    def test_a_revoked_approver_blocks_the_deployment_commit_but_not_a_frozen_release(self):
        revoked = pulls_api(MERGED, [review()], {"reviewer": "read"})
        with self.assertRaisesRegex(Refusal, "no qualified reviewer"):
            delivery.check_commit_approved(revoked, COMMIT)
        self.assertEqual(delivery.check_recorded_approval(self.record["approval"], COMMIT, V1), APPROVAL)
        calls = []
        self.verify(attempt_api(self.record, calls=calls))
        self.assertFalse([path for path in calls if "/collaborators/" in path])


class CurrentPublishAttempt(unittest.TestCase):
    """Before any credential, publication applies the gate predicate promotion applies later."""

    WORKFLOW_REF = "chamsrut/firmbatch/.github/workflows/artifact-publish.yml@refs/heads/main"

    def env(self, **overrides):
        return {"GITHUB_RUN_ID": "4242", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_WORKFLOW_REF": self.WORKFLOW_REF, **overrides}

    def jobs(self, gate_attempt=2, conclusion="success"):
        gate = {"run_attempt": gate_attempt, "status": "completed", "conclusion": conclusion}
        gates = [{"name": name, **gate} for name in V1.publish_gate_jobs]
        return gates + [{"name": V1.publish_job, "run_attempt": 2, "status": "in_progress", "conclusion": None}]

    def api(self, jobs, total=None):
        def api(path):
            self.assertEqual(path, "/repos/chamsrut/firmbatch/actions/runs/4242/attempts/2/jobs?per_page=100")
            return {"total_count": len(jobs) if total is None else total, "jobs": jobs}
        return api

    def test_this_attempts_own_succeeded_gates_pass(self):
        delivery.check_current_publish_attempt(self.api(self.jobs()), self.env())

    def test_a_rerun_whose_gates_are_listed_under_an_earlier_attempt_is_refused_before_anything_is_pushed(self):
        cases = {
            "carried-over gates listed under attempt 1": self.api(self.jobs(gate_attempt=1)),
            "a failed gate": self.api(self.jobs(conclusion="failure")),
            "a missing gate": self.api(self.jobs()[1:]),
            "a gate listed twice": self.api(self.jobs() + self.jobs()[:1]),
            "a truncated job listing": self.api(self.jobs(), total=40),
        }
        for name, api in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.check_current_publish_attempt(api, self.env())
        for name, env in {
            "no attempt": self.env(GITHUB_RUN_ATTEMPT=""),
            "another workflow": self.env(GITHUB_WORKFLOW_REF="chamsrut/firmbatch/.github/workflows/ci.yml@refs/heads/main"),
        }.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.check_current_publish_attempt(self.api(self.jobs()), env)
        # The same jobs would refuse promotion of a release that attempt published, forever.
        publication = {"run_id": "4242", "run_attempt": "2"}
        attempt = {
            "id": 4242, "run_attempt": 2, "path": ".github/workflows/artifact-publish.yml", "head_sha": COMMIT, "head_branch": "main",
            "event": "workflow_dispatch", "status": "completed", "repository": {"id": 1349512121},
        }
        stranded = self.jobs(gate_attempt=1)
        stranded[-1] = {**stranded[-1], "status": "completed", "conclusion": "success"}

        def api(path):
            return {"total_count": len(stranded), "jobs": stranded} if path.endswith("/jobs?per_page=100") else attempt
        with self.assertRaises(Refusal):
            delivery.verify_publish_attempt(api, publication, COMMIT, V1)


class AdmissionTypes(unittest.TestCase):
    """A boolean is never a count, a maximum or an identifier, although Python counts it as an integer."""

    def test_booleans_are_refused_where_integers_are_required(self):
        low = [{"name": "CVE-2026-0002", "severity": "LOW"}]
        cases = {
            "a False maximum": (admission_policy(CRITICAL=False), scan_doc()),
            "a True maximum": (admission_policy(HIGH=True), scan_doc()),
            "a True severity count": (admission_policy(), scan_doc(findings=low, counts={"LOW": True})),
            "a True approver id": (admission_policy([exception(approver={"login": "security-reviewer", "id": True})]), scan_doc()),
        }
        for name, (policy, scan) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.check_admission(policy, DIGEST, COMMIT, scan, NOW)
        for key in ("review_id", "approver_id", "pull_request"):
            with self.subTest(key=key):
                with self.assertRaises(Refusal):
                    delivery.check_recorded_approval({**APPROVAL, key: True}, COMMIT, V1)


class DestinationDigest(unittest.TestCase):
    """A later account or region deploys only once its destination holds the same digest."""

    destination = "222222222222.dkr.ecr.eu-west-1.amazonaws.com/firmbatch/control-plane"

    def destination_images(self, digest=DIGEST, repository=REPOSITORY_NAME):
        document = images_doc(digest=digest, repository=repository)
        document["imageDetails"][0]["registryId"] = "222222222222"
        return document

    def test_an_equal_destination_digest_passes(self):
        self.assertEqual(
            delivery.check_destination_digest(IMAGE, self.destination, self.destination_images()),
            f"{self.destination}@{DIGEST}",
        )

    def test_a_missing_different_or_misplaced_destination_image_is_refused(self):
        cases = {
            "not replicated yet": {"imageDetails": []},
            "a different digest": self.destination_images(digest=EARLIER_DIGEST),
            "another destination repository": self.destination_images(repository="firmbatch/other"),
            "an image index": {"imageDetails": [{**self.destination_images()["imageDetails"][0], "imageManifestMediaType": INDEX}]},
        }
        for name, document in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.check_destination_digest(IMAGE, self.destination, document)

    def test_a_tag_only_source_is_refused(self):
        with self.assertRaises(Refusal):
            delivery.check_destination_digest(f"{REPO_URL}:latest", self.destination, self.destination_images())


# ---------------------------------------------------------------------- plan object and plan file


class PlanObject(unittest.TestCase):
    def head(self, **overrides):
        document = {
            "VersionId": "v1",
            "ServerSideEncryption": "aws:kms",
            "ObjectLockMode": "GOVERNANCE",
            "ObjectLockRetainUntilDate": "2026-09-15T00:00:00+00:00",
            "LastModified": "2026-09-14T06:00:00+00:00",
            "ContentLength": 4096,
        }
        document.update(overrides)
        return document

    def test_the_named_retained_fresh_version_passes(self):
        delivery.check_plan_object(self.head(), "v1", 24, NOW)

    def test_each_unusable_object_is_refused(self):
        cases = {
            "another version": self.head(VersionId="v2"),
            "delete marker": self.head(DeleteMarker=True),
            "not KMS": self.head(ServerSideEncryption="AES256"),
            "no Object Lock": self.head(ObjectLockMode=None),
            "compliance rather than governance": self.head(ObjectLockMode="COMPLIANCE"),
            "retention lapsed": self.head(ObjectLockRetainUntilDate="2026-09-14T11:00:00+00:00"),
            "too old": self.head(LastModified="2026-09-13T06:00:00+00:00"),
            "from the future": self.head(LastModified="2026-09-14T13:00:00+00:00"),
            "empty": self.head(ContentLength=0),
            "naive timestamp": self.head(LastModified="2026-09-14T06:00:00"),
        }
        for name, head in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.check_plan_object(head, "v1", 24, NOW)


def planfile(lock_bytes=b'provider "x" {}\n', include_lock=True, include_plan=True):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        if include_plan:
            archive.writestr("tfplan", b"synthetic")
        if include_lock:
            archive.writestr(".terraform.lock.hcl", lock_bytes)
        archive.writestr("tfstate", b"synthetic state that must never be read")
    return buffer.getvalue()


class ProviderLock(unittest.TestCase):
    def compare(self, plan_bytes, lock_bytes):
        with tempfile.TemporaryDirectory() as directory:
            plan = pathlib.Path(directory, "plan.tfplan")
            lock = pathlib.Path(directory, ".terraform.lock.hcl")
            plan.write_bytes(plan_bytes)
            lock.write_bytes(lock_bytes)
            delivery.compare_lock(plan, lock)

    def test_an_identical_lock_passes(self):
        self.compare(planfile(), b'provider "x" {}\n')

    def test_each_mismatch_is_refused(self):
        cases = {
            "different lock": (planfile(lock_bytes=b'provider "y" {}\n'), b'provider "x" {}\n'),
            "no embedded lock": (planfile(include_lock=False), b'provider "x" {}\n'),
            "not a plan": (planfile(include_plan=False), b'provider "x" {}\n'),
            "not a zip": (b"plain text", b'provider "x" {}\n'),
        }
        for name, (plan_bytes, lock_bytes) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    self.compare(plan_bytes, lock_bytes)


class TerraformVersion(unittest.TestCase):
    def test_only_the_pinned_version_passes(self):
        delivery.check_terraform_version({"terraform_version": "1.15.8"}, "1.15.8")
        for document in ({"terraform_version": "1.15.9"}, {}, []):
            with self.assertRaises(Refusal):
                delivery.check_terraform_version(document, "1.15.8")


# ---------------------------------------------------------------------- plan summary and the authority split


class PlanSummary(unittest.TestCase):
    def test_the_summary_is_counts_only(self):
        secret_value = "synthetic-secret-value-that-must-not-appear"
        changes = [
            {
                "address": "module.network.aws_vpc.this",
                "type": "aws_vpc",
                "change": {"actions": ["create"], "after": {"cidr_block": "10.0.0.0/16"}},
            },
            {
                "address": "module.identity.aws_cognito_user_pool_client.broker",
                "type": "aws_cognito_user_pool_client",
                "change": {"actions": ["update"], "after": {"client_secret": secret_value}},
            },
            {"address": "module.edge.aws_lb.this", "type": "aws_lb", "change": {"actions": ["delete", "create"]}},
            task_definition_change("identity-broker"),
        ]
        text, human = delivery.summarize_plan(rendering(changes), "plan", "1.15.8", IMAGE)
        self.assertEqual(human, 0)
        self.assertIn("| create | 1 |", text)
        self.assertIn("| replace | 2 |", text)
        self.assertIn("delivery contract: 1", text)
        for forbidden in (secret_value, "10.0.0.0/16", "module.", "aws_", DIGEST, "secretsmanager", PREFIX):
            self.assertNotIn(forbidden, text)

    def test_a_trust_anchor_change_is_counted_and_refused_at_apply(self):
        for resource_type in (
            "aws_iam_role", "aws_iam_role_policy", "aws_iam_policy", "aws_iam_openid_connect_provider", "aws_iam_role_policy_attachment",
            "aws_kms_key", "aws_kms_alias", "aws_secretsmanager_secret", "aws_secretsmanager_secret_policy",
            "aws_ecr_repository", "aws_ecr_repository_policy", "aws_ecr_lifecycle_policy", "aws_ecr_replication_configuration",
            "aws_s3_bucket_policy", "aws_budgets_budget_action",
        ):
            for actions in (["create"], ["update"], ["delete"], ["delete", "create"]):
                with self.subTest(resource_type=resource_type, actions=actions):
                    change = {"address": f"module.x.{resource_type}.y", "type": resource_type, "change": {"actions": actions}}
                    document = rendering([change])
                    self.assertEqual(delivery.summarize_plan(document, "apply", "1.15.8", IMAGE)[1], 1)
                    argv = ["plan-summary", "--mode", "apply", "--terraform-version", "1.15.8", "--expected-image", IMAGE]
                    result = run_cli(argv, document)
                    self.assertEqual(result.returncode, 3)
                    self.assertIn("human-applied", result.stderr)

    def test_workload_rollout_budget_and_infrastructure_changes_are_the_pipelines(self):
        document = rendering([
            {"address": "module.delivery.aws_iam_policy.workload_boundary", "type": "aws_iam_policy", "change": {"actions": ["no-op"]}},
            {"address": "module.compute.aws_ecs_cluster.this", "type": "aws_ecs_cluster", "change": {"actions": ["create"]}},
            {"address": "module.database.aws_db_instance.this", "type": "aws_db_instance", "change": {"actions": ["update"]}},
            {"address": "module.observability.aws_budgets_budget.monthly", "type": "aws_budgets_budget", "change": {"actions": ["update"]}},
            *(task_definition_change(suffix) for suffix in delivery.ECS_CONTRACT),
            service_change("web-api"),
            service_change("identity-broker"),
        ])
        text, human = delivery.summarize_plan(document, "apply", "1.15.8", IMAGE)
        self.assertEqual(human, 0)
        self.assertIn("delivery contract: 7", text)
        result = run_cli(["plan-summary", "--mode", "apply", "--terraform-version", "1.15.8", "--expected-image", IMAGE], document)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_version_errors_unknown_actions_and_untyped_changes_are_refused(self):
        for document in (
            rendering([], version="1.15.9"),
            rendering([], errored=True),
            rendering([{"address": "x", "type": "aws_vpc", "change": {"actions": ["forget"]}}]),
            rendering([{"address": "x", "change": {"actions": ["create"]}}]),
        ):
            with self.assertRaises(Refusal):
                delivery.summarize_plan(document, "plan", "1.15.8", IMAGE)

    def test_release_metadata_and_terraform_inputs_must_agree_on_the_digest(self):
        cases = {
            "the plan's variable is another digest": (rendering([], release_image=f"{REPO_URL}@{EARLIER_DIGEST}"), IMAGE),
            "the plan's variable is a tag": (rendering([], release_image=f"{REPO_URL}:latest"), IMAGE),
            "the expected image is a tag": (rendering([], release_image=f"{REPO_URL}:latest"), f"{REPO_URL}:latest"),
            "the plan records no image": (rendering([], release_image=None), IMAGE),
        }
        for name, (document, expected) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(Refusal):
                    delivery.summarize_plan(document, "plan", "1.15.8", expected)


class EcsDeliveryContract(unittest.TestCase):
    """Every task-definition revision and service change is checked before plan storage and apply."""

    def assertRefused(self, change, mode="apply"):
        with self.assertRaises(Refusal):
            delivery.summarize_plan(rendering([change]), mode, "1.15.8", IMAGE)

    def test_the_compute_modules_rendering_passes(self):
        for suffix in delivery.ECS_CONTRACT:
            with self.subTest(family=suffix):
                delivery.summarize_plan(rendering([task_definition_change(suffix)]), "apply", "1.15.8", IMAGE)
        known_revision = service_change(unknown={}, task_definition=f"{TASK_DEFINITION_ARN}/{PREFIX}-web-api:7")
        delivery.summarize_plan(rendering([known_revision]), "apply", "1.15.8", IMAGE)

    def test_a_digest_rollout_registers_a_new_revision_and_deregisters_none(self):
        rollout = task_definition_change(container={"image": f"{REPO_URL}@{DIGEST}"})
        self.assertEqual(rollout["change"]["before"]["skip_destroy"], True)
        text, _ = delivery.summarize_plan(rendering([rollout, service_change(unknown={"task_definition": True})]), "apply", "1.15.8", IMAGE)
        self.assertIn("delivery contract: 2", text)
        self.assertRefused(task_definition_change(before={"family": f"{PREFIX}-web-api", "skip_destroy": False}))
        self.assertRefused(task_definition_change(skip_destroy=False))

    def test_each_departure_from_the_contract_is_refused_in_both_modes(self):
        web = delivery.ECS_CONTRACT["web-api"]["secrets"]
        cases = {
            "a tag-only image": task_definition_change(container={"image": f"{REPO_URL}:latest"}),
            "an image by release tag": task_definition_change(container={"image": f"{REPO_URL}:git-{COMMIT}"}),
            "another digest": task_definition_change(container={"image": f"{REPO_URL}@{EARLIER_DIGEST}"}),
            "an unapproved repository": task_definition_change(container={"image": OTHER_REPO_IMAGE}),
            "a privileged container": task_definition_change(container={"privileged": True}),
            "host networking": task_definition_change(network_mode="host"),
            "bridge networking": task_definition_change(network_mode="bridge"),
            "a host mount": task_definition_change(volume=[{"name": "root", "host_path": "/"}]),
            "a mount point": task_definition_change(container={"mountPoints": [{"sourceVolume": "root", "containerPath": "/host"}]}),
            "a host device": task_definition_change(
                container={"linuxParameters": {"capabilities": {"drop": ["ALL"]}, "devices": [{"hostPath": "/dev/kmsg"}]}}
            ),
            "an added capability": task_definition_change(
                container={"linuxParameters": {"capabilities": {"drop": ["ALL"], "add": ["SYS_ADMIN"]}}}
            ),
            "capabilities not dropped": task_definition_change(container={"linuxParameters": {"capabilities": {}}}),
            "the root user": task_definition_change(container={"user": "0"}),
            "a named root user": task_definition_change(container={"user": "root"}),
            "no user": task_definition_change(container={"user": None}),
            "a writable root filesystem": task_definition_change(container={"readonlyRootFilesystem": False}),
            "an omitted read-only root filesystem": task_definition_change(container={"readonlyRootFilesystem": None}),
            "a host PID namespace": task_definition_change(pid_mode="host"),
            "EC2 compatibility": task_definition_change(requires_compatibilities=["EC2"]),
            "an arbitrary execution role": task_definition_change(execution_role_arn=f"arn:aws:iam::{ACCOUNT}:role/administrator"),
            "another task's role": task_definition_change(task_role_arn=f"arn:aws:iam::{ACCOUNT}:role/{PREFIX}-bootstrap-task"),
            "an unapproved family": task_definition_change(family=f"{PREFIX}-operator-shell"),
            "another environment's family": task_definition_change(family="firmbatch-production-web-api"),
            "a revision that would be deregistered": task_definition_change(skip_destroy=False),
            "an unapproved secret reference": task_definition_change(container={"secrets": [
                *({"name": n, "valueFrom": secret_arn(t)} for n, t in web.items()),
                {"name": "FIRMBATCH_MIGRATION_DATABASE_URL", "valueFrom": secret_arn("migration-database-url")},
            ]}),
            "the right name, another container": task_definition_change(container={"secrets": [
                {"name": "FIRMBATCH_DATABASE_URL", "valueFrom": secret_arn("migration-database-url")},
            ]}),
            "the master secret in the web service": task_definition_change(container={"secrets": [
                {"name": "FIRMBATCH_DATABASE_URL", "valueFrom": secret_arn("rds!")},
            ]}),
            "a secret in another account": task_definition_change(container={"secrets": [
                {"name": "FIRMBATCH_DATABASE_URL", "valueFrom": secret_arn("application-database-url").replace(ACCOUNT, "222222222222")},
            ]}),
            "two containers": task_definition_change(container_definitions=json.dumps([{"image": IMAGE}, {"image": IMAGE}])),
            "unknown container definitions": {
                **task_definition_change(),
                "change": {**task_definition_change()["change"], "after_unknown": {"container_definitions": True}},
            },
            "ECS Exec on a service": service_change(enable_execute_command=True),
            "a public IP": service_change(network_configuration=[{"assign_public_ip": True}]),
            "an EC2 service": service_change(launch_type="EC2"),
            "an unapproved service": service_change(name=f"{PREFIX}-operator-shell"),
            "a service running another family": service_change(unknown={}, task_definition=f"{TASK_DEFINITION_ARN}/{PREFIX}-bootstrap:3"),
            "a task set": {"address": "x", "type": "aws_ecs_task_set", "change": {"actions": ["create"], "after": {}}},
        }
        for name, change in cases.items():
            for mode in ("plan", "apply"):
                with self.subTest(case=name, mode=mode):
                    self.assertRefused(change, mode)

    def test_forgetting_an_approved_revision_is_allowed_and_an_unapproved_removal_is_not(self):
        removal = {
            "address": "x",
            "type": "aws_ecs_task_definition",
            "change": {"actions": ["delete"], "before": {"family": f"{PREFIX}-migrate", "skip_destroy": True}},
        }
        delivery.summarize_plan(rendering([removal]), "apply", "1.15.8", IMAGE)
        deregistration = {**removal, "change": {"actions": ["delete"], "before": {"family": f"{PREFIX}-migrate", "skip_destroy": False}}}
        self.assertRefused(deregistration)
        stray = {"address": "x", "type": "aws_ecs_service", "change": {"actions": ["delete"], "before": {"name": "someone-elses-service"}}}
        self.assertRefused(stray)


if __name__ == "__main__":
    unittest.main()
