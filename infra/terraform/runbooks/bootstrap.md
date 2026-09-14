# Runbook — the human bootstrap

For **Milestone 3.3d**, after the deployment parameters are confirmed and a human has authorized
creating resources. Nothing in Milestone 3.3b performs any step here. ADR 0011 decisions 8 and 9;
ADR 0012 decisions 1, 5, 12, 13 and 15.

The bootstrap creates what the GitHub pipeline depends on, so it never depends on that pipeline.
It is performed by a human, with short-lived credentials, from a checkout of reviewed `main`, in a
fixed order that never names a principal before it exists:

1. **the bootstrap root** creates the state and plan storage, the keys (state, plans, release), the
   GitHub OIDC provider and every GitHub delivery identity — the staging plan and apply roles and the
   artifact-publish role, with their trust policies, permission policies and boundaries — naming the
   **declared** canonical artifact registry;
2. **the artifacts root** creates the release repository and the release-record bucket in that declared
   registry, naming the roles part 1 created, after reading each one and proving it exists;
3. **the first release is published** through `artifact-publish` (`runbooks/staging-delivery.md`, part C),
   once a reviewed pull request has attested parts 1 and 2 — publication does not wait for the first
   staging apply, which deploys it;
4. **the human's first staging apply** creates the staging infrastructure, running that release;
5. **ordinary changes** afterwards use the protected pipeline (`runbooks/staging-delivery.md`), once a
   reviewed pull request has attested that apply.

Each workflow's preflight requires only the attestations it depends on (`WORKFLOW_PREREQUISITES` in
`infra/delivery/delivery.py`): `artifact-publish` never requires
`human_applied_resources_applied_by_human`, which is true only after step 4, so the order above completes
without a false attestation. `staging-plan` and `staging-apply` require every prerequisite.

## Who and with what

- **A human operator**, never an agent and never GitHub Actions.
- **Short-lived credentials from an existing administrator role**, preferably assumed through AWS
  SSO with MFA. Its profile, the account and the authorization to use it are confirmed at M3.3d.
  That role is not named in the repository, and nothing the repository defines trusts it.
- **No permanent access key**, anywhere, at any step.

## What the human owns, and what the pipeline applies

ADR 0012 decision 5 holds the full privilege and resource ownership matrix. In short:

- **Human-owned trust anchors** — created and changed only here: the GitHub OIDC provider; the
  plan, apply and artifact-publish roles, their trust and permission policies and their boundaries
  (bootstrap root); the workload boundary, the operator policy and the ECS execution and task roles and
  their policies (staging root); every KMS key, key policy and alias; every Secrets Manager container;
  the state, plan and release-record buckets; the release registry and its policies; initial secret
  values; service-linked roles.
- **Pipeline-applied, after the first human apply** — through `staging-plan` and `staging-apply`:
  task-definition revisions (registered, never deregistered) and service updates inside the delivery
  contract, image-digest rollout, and ordinary network, edge, database, identity, observability and
  budget changes.

## Before starting

1. The staging account ID, region, bucket names (state, plans, release records), saved-plan retention
   (one day recommended), state version retention, the staging `name_prefix`, the release name prefix,
   repository name and release-record retention, the hosted zone and the one reviewed RDS instance class
   are confirmed and written down outside the repository.
2. The GitHub environments `staging-plan`, `staging-apply` and `artifact-publish` already exist and
   are protected (`runbooks/staging-delivery.md`, part A). **No OIDC trust may exist before they do.**
3. Confirm the credentials belong to the intended account, in the confirmed region, before any
   Terraform command (for example with `aws sts get-caller-identity`, run by the human).
4. The service-linked roles ECS, RDS and Elastic Load Balancing need exist in the account, created by
   the human where they do not (the pipeline cannot create one).

## Part 1 — the account trust root and every delivery identity (`infra/terraform/bootstrap`)

The state and plan buckets, their keys and the release key, the account's GitHub OIDC provider, and the
plan, apply and artifact-publish roles with their policies and boundaries.

1. Copy `bootstrap.tfvars.example` to a directory **outside the repository** and fill it in.
2. The first apply cannot use the S3 backend: the bucket it names does not exist yet. **Copy the
   `infra/terraform/bootstrap` directory to an operator directory outside the repository** — the
   repository's policy check refuses any Terraform override file inside `infra/`, and the override below
   must never be there. In the copy only, create `backend_override.tf` with a local backend whose `path`
   is also outside the repository:

   ```hcl
   terraform {
     backend "local" {
       path = "/secure/operator/path/bootstrap.tfstate"
     }
   }
   ```

3. In the copy: `terraform init -lockfile=readonly`, then
   `terraform plan -var-file=<outside>/bootstrap.tfvars -out=<outside>/bootstrap.tfplan`. Review the plan
   in full. Confirm at least:
   - two buckets — the state bucket without Object Lock, the plan bucket with Object Lock in GOVERNANCE
     mode and lifecycle rules only under `plans/`, and a policy denying `PutObject` to every principal
     but the exact plan role;
   - three KMS keys (state, plans, release), each rotating; the release key's policy denying key
     changes and grants to every pipeline role;
   - one OIDC provider whose only audience is `sts.amazonaws.com`;
   - three roles, each trusting exactly `repo:chamsrut/firmbatch:environment:<its environment>` with
     audience `sts.amazonaws.com`, each under its own boundary and holding exactly one inline policy and
     nothing attached: `staging-plan` (under the plan boundary, which refuses secret values, parameters,
     other keys, saved-plan reads and state writes even to a policy attached later), `staging-apply` (under
     the apply boundary) and `artifact-publish` (under the artifact-publish boundary);
   - the apply boundary's ceiling naming no IAM action but exact reads and `iam:PassRole` on the ten
     `<name_prefix>-<family>-execution|task` roles to `ecs-tasks.amazonaws.com`, and denying
     deregistration, another family or ECS Exec on either service;
   - the artifact-publish policy and boundary allowing pushes to and reads of the one release
     repository, creating and reading back release records, and the release key through S3 only.
4. `terraform apply <outside>/bootstrap.tfplan`.
5. In the copy, delete `backend_override.tf`. Write a backend configuration file outside the repository
   with `bucket`, `region` and `kms_key_id` from the outputs, then
   `terraform init -migrate-state -backend-config=<outside>/bootstrap.s3.tfbackend`. The state now lives
   under `bootstrap/terraform.tfstate` in the state bucket; later plans of this root run from the
   repository checkout with the same `-backend-config`.
6. Remove the copy, the local state file and the local plan file securely.
7. Record the outputs — bucket names, the state, plan and release key ARNs, the OIDC provider ARN, the
   plan, apply and artifact-publish role ARNs and the ten workload role ARNs, identifiers only.

## Part 2 — the release registry (`infra/terraform/artifacts`)

The canonical release repository with its lifecycle and repository policies, and the release-record
bucket. It creates no identity and no key. Applied only by a human, always.

1. Prepare the variables outside the repository from `artifacts.tfvars.example`: `release_kms_key_arn`
   and `artifact_publish_role_arn` from part 1; `release_reader_role_arns` naming the staging plan and
   apply role ARNs from part 1; `pull_account_ids` naming the staging account.
2. `terraform init -lockfile=readonly -backend-config=<outside>/artifacts.s3.tfbackend` (key
   `artifacts/terraform.tfstate`).
3. `terraform plan -var-file=<outside>/artifacts.tfvars -out=<outside>/artifacts.tfplan`. **The plan
   refuses unless every named role already exists**, and unless artifact-publish carries its boundary and
   trusts exactly its environment. Review it in full. Confirm at least: tags `IMMUTABLE` with no
   exclusion filter; KMS encryption under the release key; scan on push; a lifecycle rule selecting
   `untagged` only; the repository policy denying every push to every principal but artifact-publish and
   denying image deletion and tag-mutability changes to everyone; the record bucket's Object Lock, its
   `If-None-Match` requirement and its readers. **No replication configuration.**
4. `terraform apply <outside>/artifacts.tfplan`, then remove the local plan file securely.
5. Record the outputs — repository URL and ARN, registry account and region, bucket name — for the
   GitHub environment variables.

A later dedicated artifact account would run its own bootstrap apply creating only the artifact-publish
identity and release key, and part 2 there; that is a reviewed change to the bootstrap root first.

## Part 3 — the staging root's first full apply

**The first full apply of the staging root is a human's**, because the ECS roles, keys and secret
containers and the resources that use them are created together. Only after the M3.3d authorization,
after M3.3c's review, and after `artifact-publish` has published a release
(`runbooks/staging-delivery.md`, part C).

1. Verify that release exactly as `staging-plan` does — the record, its frozen approval, its exact publish
   attempt, the digest and its admission — with the human's own read-only credentials, and take its full
   `release_image` reference from the release record — never a tag.
2. Prepare the staging variables outside the repository from `staging.tfvars.example`, with the bucket and
   key values from part 1, the `release_registry_*` values from part 2, and that `release_image`.
3. `terraform init -lockfile=readonly -backend-config=<outside>/staging.s3.tfbackend`.
4. `terraform plan -var-file=<outside>/staging.tfvars -out=<outside>/staging.tfplan`. Review the whole
   plan. Confirm at least: every ECS role carries the workload boundary; no wildcard in a trust policy;
   no secret version; every task definition is `skip_destroy` and names exactly the verified
   `release_image`; no role, policy or boundary of a GitHub delivery identity (those are part 1's).
5. `terraform apply <outside>/staging.tfplan`, then remove the local plan file securely.

Afterwards, ordinary changes go through `staging-plan` and `staging-apply`. A plan whose summary
shows a non-zero human-applied count — a change to a trust anchor — is applied this way instead,
from a reviewed commit on `main`.

## Attestations, in two pull requests

Each is a pull request to `main`, reviewed by a code owner who is not its author, changing
`infra/delivery/readiness.json`. A true value is an attestation, not evidence; the M3.3d evidence records
what was created, by identifier and never by value.

1. **After part 2, before publishing:** set `state_plan_buckets_and_delivery_identities_bootstrapped_by_human`
   and `release_registry_applied_by_human` to true. With part A's attestations and M3.3c's review this is
   everything `artifact-publish` requires; publish the first release (`runbooks/staging-delivery.md`,
   part C) before part 3.
2. **After part 3:** set `human_applied_resources_applied_by_human` to true. Only then do `staging-plan` and
   `staging-apply` pass their preflights.
