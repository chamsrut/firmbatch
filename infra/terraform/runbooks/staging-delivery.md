# Runbook — publication and staging delivery

How the manually dispatched `artifact-publish`, `staging-plan` and `staging-apply` workflows become
usable, and how they are used. ADR 0011 decision 9; ADR 0012 decisions 5–9, 13 and 15. **In Milestone
3.3b none of them can run**: `infra/delivery/readiness.json` is all false and records no deployment
authorization, no environment exists, `main` is not protected and no registry exists. Nothing in the
repository creates or changes a GitHub setting; a human does. The privilege and resource ownership
matrix is in ADR 0012 decision 5.

## A. GitHub settings, before any AWS trust exists

Configured by a repository administrator. The repository checks only that the workflows refuse
without them; it cannot prove any of them exists.

1. **Protect `main`** (branch protection or a ruleset): require a pull request; require at least
   one approving review; require review from code owners (`.github/CODEOWNERS`); dismiss stale
   approvals when new commits are pushed; require the status checks `locks`, `verify` and
   `container` from `ci.yml`; block force pushes and deletion; apply the rules to administrators.
2. **A second qualified reviewer.** With one maintainer, required reviews and self-review
   prevention block every change. Add a second person able to review infrastructure, with write access,
   before enabling self-review prevention. Only such a reviewer's approval, submitted before the merge,
   admits a commit.
3. **Create `artifact-publish`, `staging-plan` and `staging-apply`**, each with:
   - required reviewers (the qualified reviewers), with **prevent self-review** enabled;
   - administrators **not** allowed to bypass the protection;
   - deployment branches restricted to **selected branches: `main` only** (no tag rule). For
     `artifact-publish` this policy is what binds publication to protected `main`: IAM sees only the
     environment in GitHub's default OIDC subject.
4. **Forks and pull requests:** require approval before running workflows from outside
   collaborators. None of the three workflows has a pull-request or push trigger; only `ci.yml` runs
   on pull requests, and it holds no environment, token or secret.
5. **No permanent AWS credential anywhere** — no repository, organization or environment secret
   holding an access key. OIDC is the only AWS authentication.
6. Open a pull request setting `github_environments_created_and_protected`,
   `artifact_publish_environment_created_and_protected`,
   `main_branch_protected_with_code_owner_review` and `second_qualified_reviewer_available` to true
   in `infra/delivery/readiness.json`.

Only after this part: the human bootstrap (`runbooks/bootstrap.md`).

## B. Environment configuration

Non-secret identifiers as **environment variables**; each environment holds only its own role.

| Variable | `artifact-publish` | `staging-plan` | `staging-apply` |
| --- | --- | --- | --- |
| `ARTIFACT_REGISTRY_ACCOUNT_ID`, `ARTIFACT_REGISTRY_REGION`, `ARTIFACT_REPOSITORY_NAME` | yes | yes | yes |
| `ARTIFACT_RELEASE_BUCKET` | yes | yes | yes |
| `ARTIFACT_RELEASE_KMS_KEY_ARN` | yes | no | no |
| `ARTIFACT_PUBLISH_ROLE_ARN` | yes | **no** | **no** |
| `STAGING_AWS_ACCOUNT_ID`, `STAGING_AWS_REGION` | no | yes | yes |
| `STAGING_PLAN_ROLE_ARN` | **no** | yes | **no** |
| `STAGING_APPLY_ROLE_ARN` | **no** | **no** | yes |
| `STAGING_STATE_BUCKET`, `STAGING_STATE_KMS_KEY_ARN` | no | yes | yes |
| `STAGING_PLAN_BUCKET`, `STAGING_PLAN_KMS_KEY_ARN` | no | yes | yes |
| `STAGING_MAX_PLAN_AGE_HOURS` (at most 24; the saved-plan lifetime) | no | no | yes |

One **environment secret** on `staging-plan` only: `STAGING_TFVARS_JSON`, the staging root's
variables as JSON, reviewer CIDRs included — and **never `release_image`**, which comes only from the
verified release record. It is a secret so GitHub masks it, not because it is an AWS credential.
Every reviewer CIDR is reviewed by a human on every change and never committed.

**The canonical artifact registry is declared, never derived.** `ARTIFACT_REGISTRY_ACCOUNT_ID`,
`ARTIFACT_REGISTRY_REGION`, `ARTIFACT_REPOSITORY_NAME` and `ARTIFACT_RELEASE_BUCKET` are the values the
bootstrap root's `artifact_registry` output declares, identical in all three environments and equal to the
`release_registry_*` values in `STAGING_TFVARS_JSON`. They may equal the staging account and region only
because a human declared the registry there — the bootstrap root as written requires that, since it creates
the publisher and the release key beside the registry — and nothing in the workflows assumes it.

The workflows refuse a role visible to the wrong environment, an account or region mismatch, a
shared state and plan bucket, keys outside the account and region, an allow-list the policy check
rejects, a `STAGING_TFVARS_JSON` that sets an image, and release-registry variables that disagree
with the Terraform inputs — `staging-plan` checks `STAGING_TFVARS_JSON` against the environment's
declaration **before** it requests its OIDC token. **No workflow input, variable or option can add an admission exception**;
exceptions and security stops live only in the committed admission policy (part J).

## C. Publish a release (`artifact-publish`)

1. M3.3c's programs, dependencies and image have passed review; `runtime_contract_reviewed` is set in
   `STAGING_TFVARS_JSON` and `m3_3c_programs_dependencies_and_image_reviewed` is true in
   `readiness.json`. Publication needs every prerequisite except
   `human_applied_resources_applied_by_human`: the first release is published before the human's first
   staging apply, which deploys it (`runbooks/bootstrap.md`).
2. Dispatch **artifact-publish** from `main`, at the approved merge commit to release. The preflight
   refuses anything else and outputs the approval evidence the release record will freeze. The full CI
   verification runs as a job the publication waits for.
3. An `artifact-publish` reviewer approves. Before any credential, the job builds once with no build
   argument — the image's labels carrying its provenance, this run's ID and attempt among it — inspects
   it, generates the SBOM and writes the release draft. Then it assumes the role and takes one of two
   paths:
   - **fresh** — `git-<commit>` does not exist: it stores this image's SBOM, pushes the one tag, and
     proves from the registry's bytes that the tag is exactly the image it built;
   - **resume** — `git-<commit>` exists: it pushes nothing and proves the tag is this commit's release,
     pushed by an earlier attempt whose SBOM is stored.

   Both write the release record once. A record or SBOM that already exists is accepted only if it is
   byte-for-byte, and by its stored identity, the object this release produces.
4. The job summary shows the mode, the release commit, tag, digest and the record's version and SHA-256.

**Recovering a publication.** A publication that failed part-way — the runner lost, a step failed, a
response never arrived — is resumed by dispatching `artifact-publish` again while `main` is still at that
commit: the record then names the attempt that pushed the image. Prefer a new dispatch to "re-run failed
jobs". A dispatch after completion changes nothing. **When the job refuses for explicit human recovery**
— the tag carries another tag or incompatible provenance, its SBOM is missing, or a stored record or
SBOM differs from what the release produces — do not delete or re-tag anything: investigate in an operator
session, with read-only credentials, how the registry or bucket came to hold it. The image and records are
immutable by design; the ordinary way forward is a new commit and a new release, and pruning or replacing
anything is a reviewed human change to the repository and bucket policies first.

## D. Plan (promote a release by digest)

1. Dispatch **staging-plan** from `main` with `release_commit`. The preflight refuses unless the commit is
   reachable from `main`.
2. A `staging-plan` reviewer approves the deployment. **Approving a plan never authorizes an
   apply.**
3. The plan job reads the release record and refuses unless: its schema version's contract holds; the
   approval frozen into it is valid and the pull request's merge commit, merge time, head and author still
   read as recorded (a reviewer's current permission and later reviews are never consulted); the **exact
   publish run attempt** it names is a completed main dispatch of `artifact-publish` whose preflight and
   verification jobs succeeded; the digest, resolved **by digest**, is in the immutable repository carrying
   exactly `git-<release_commit>`; and the digest is admitted under `infra/delivery/admission-policy.json`
   **as `origin/main` holds it when the job runs** — a complete scan, no critical or high findings but those
   an unexpired exception for exactly that digest names, and no security stop. The record is interpreted by
   the contract of the schema version it declares — its components, locks, workflow, gate-job names and
   approval rules — so a later contract neither invalidates nor reinterprets it; the admission policy is the live security overlay,
   read beside that contract, never frozen into it. Only the record's full reference reaches Terraform.
4. The job summary shows the verified release, action counts, the count of human-applied changes, the
   count of task-definition and service changes checked against the delivery contract, and the
   **deployment tuple**: `plan_key`, `plan_version_id`, `plan_sha256`, `release_commit`, `release_image`,
   `release_record_version_id` and `release_record_sha256`. A non-zero human-applied count means a human
   applies that plan (`runbooks/bootstrap.md`); the pipeline will refuse it. Any departure from the
   delivery contract refuses the plan before it is stored.
5. **Review the full plan in a separately authenticated operator session**: download that exact
   version with short-lived operator credentials into an encrypted directory only the operator can
   read, check its SHA-256, inspect it with `terraform show`, and delete the local copy when the
   review ends. The plan carries state, including the Cognito client secret; it never goes into a
   ticket, chat, artifact or log.
6. Produce the current cost estimate. **Record the deployment authorization** through a reviewed pull
   request to `main` adding one entry to `deployment_authorization.authorizations` in `readiness.json`:
   `environment` (`staging`), the seven tuple values (`plan_key`, `plan_version_id`, `plan_sha256`,
   `release_commit`, `release_image_digest` — the digest part of `release_image` — `release_record_version_id`,
   `release_record_sha256`), `authorized_by`, `authorization_reference` (the pull request's URL),
   `authorized_at` and `expires_at`, **at most 24 hours later**. An authorization names one plan object and
   one release; it never authorizes another, and a later plan needs its own.

## E. Apply

1. Dispatch **staging-apply** from `main` with exactly the seven tuple values. They all appear in the run
   name, and so in the approval request.
2. A `staging-apply` reviewer who is not the dispatcher confirms the run name's tuple against the recorded
   authorization and approves.
3. The job re-verifies everything itself. Before any OIDC token: the checkout, its approval, and one
   unexpired authorization on `origin/main` naming exactly the tuple. Immediately before applying: the
   release — exactly the authorized record version and SHA-256, its approval and publish attempt, the
   digest's repository, tags and a fresh scan, with exceptions and security stops evaluated now under the
   admission policy **on `origin/main`**, so a stop or an exception's removal merged after the plan refuses
   the apply even though the checkout, the plan's commit, predates it. Then the
   plan object and file. It never plans and never builds, tags or pushes. It refuses: an expired, missing
   or mismatched authorization; any change to the release since the plan; another plan version, a delete
   marker, a missing KMS encryption, lapsed retention, a plan older than `STAGING_MAX_PLAN_AGE_HOURS`, a
   SHA-256 mismatch, a provider-lock mismatch with the approved commit, another Terraform version, a commit
   no longer approved on or reachable from `main`, a plan whose `release_image` is not the verified one, a
   change to a trust anchor, and any task-definition or service change outside the delivery contract.
   Terraform refuses a stale plan.
4. Every plan, log and release file stays in a private runner directory the job removes whatever happened.
   A refused or failed apply's output is discarded with it; investigate in an operator session, never by
   printing it into the job log.

## F. Rollback

A rollback is **a new plan**: dispatch `staging-plan` with the `release_commit` of an earlier
release, then review, authorize and apply it as in D and E. Its digest must still be retained in the
registry — tagged releases never expire, and nothing deletes them without a reviewed human change to the
repository policy — and its task-definition revision is still registered, since no rollout deregisters one.
Nothing is rebuilt or re-tagged; a digest that is gone is refused. The earlier release's frozen approval is
what is checked, not anyone's current permission, and it is interpreted by the contract of the version its
record declares. Two things are checked **now**, as for any plan: the admission policy on `origin/main` —
so a release since revoked by a security stop cannot be rolled back to — and the approval of the commit the
rollback plans from, `main`'s head, whose approver must still hold write permission. If that approver's
access has been removed, merge a newly approved commit to `main` first; the rollback then plans from it.

## G. Another account or region (not enabled)

Production, or a staging region elsewhere, receives the **same digest**: a human creates the
destination repository and its policies, the image arrives by controlled replication or a
digest-preserving copy, and deployment waits until `delivery.py verify-destination-digest` shows the
destination holds the release record's digest. Production promotes the same record through its own
plan and approval.

## H. What the pipeline never does

- Upload a plan, its rendering, state, variables or an SBOM as an artifact, or print them to a log.
- Generate a plan in the apply job, or apply anything but the verified saved plan of an authorized tuple.
- Build, tag, push or delete an image in `staging-plan` or `staging-apply`; resolve a release by
  tag; accept an image from environment configuration; overwrite or delete a release record or SBOM.
- Change a trust anchor, write a secret value, pass any role but the ten workload roles, run a
  one-off ECS task, open ECS Exec, run another family on a service or deregister a task-definition revision:
  the migrate and other one-off tasks are run by an operator.
- Delete a plan or a release record. A delete in a versioned bucket only adds a marker; lifecycle
  expires every version and marker under `plans/`, never touches state, and never expires a record.

## I. Evidence

M3.3 AWS staging evidence is captured only after the authorized M3.3d deployment, under
`docs/evidence/m3/aws-staging/`, with the standard provenance header, and only as ADR 0011 decision
10 allows: the sanitized plan summary, never the plan or its rendering.

## J. Admission exceptions and security stops

Both live only in `infra/delivery/admission-policy.json`, changed by a CODEOWNERS-reviewed pull request to
`main`, and both are evaluated independently at plan and at apply, each time **as `origin/main` holds the file
then** — never the copy in the commit the job checked out. A stop merged, or an exception removed, after a
plan was made therefore refuses that plan's apply. They are a live security overlay, not part of any release
record: a record's historical contract is never rewritten by them.

- **An exception** admits named findings of one release: `image_digest` (the exact digest), `vulnerability_ids`
  (exact CVE or GHSA identifiers, at most ten), `reason`, `approver` (`login` and numeric `id`),
  `approval_reference` (the pull request's URL), `created_at` and `expires_at`, **at most 30 days apart**. An
  expired exception, or one for another digest or identifier, admits nothing; a malformed or overly broad
  entry refuses every admission until it is corrected.
- **A security stop** revokes a release without rewriting its history: `image_digest`, `release_commit`,
  `reason`, `reference` and `created_at`. Plan and apply refuse that digest and commit outright, whatever its
  recorded approval or scan. A deployment already running it is replaced by planning and applying another
  release.
