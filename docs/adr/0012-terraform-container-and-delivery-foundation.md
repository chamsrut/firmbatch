# ADR 0012: the M3.3b Terraform, container and delivery foundation is scaffolding that cannot plan, apply, push or deploy until humans prepare it, and agents get no access to AWS

- **Status:** Accepted — implemented and statically tested on
  `feat/milestone-3-3b-terraform-foundation` from `main` at `86d4195` (M3.3a, PR #11). **Nothing
  in it has been planned, applied, pushed or deployed**, and no AWS or GitHub resource exists
  because of it.
- **Date:** 2026-09-13; **corrected 2026-09-14** by two correction passes before commit. The first
  split authority between the human bootstrap and the pipeline instead of making every workload and
  the budget human-only (decision 5), added build once and promote by digest (decision 13) and an
  incidental password-hash correction, migration `0007` (decision 14), and amended decisions 1, 3, 6,
  7 and 10 to match. The second applied an independent review's findings: the apply boundary is
  repaired so that it admits rather than denies (decision 5); every GitHub delivery identity moves into
  the bootstrap root, removing a bootstrap cycle (decisions 1, 5 and 12); task-definition revisions are
  retained for rollback (decision 5); publication becomes a resumable state machine and promotion and
  apply bind to exact, immutable facts (decisions 13 and 15); the policy checker evaluates policies and
  refuses more workflow bypasses, and the guard more wrapper and program spellings (decisions 11 and
  15). A third pass applied the same reviewer's verification of those corrections: promotion and apply
  read the admission policy — the live security overlay — from `origin/main`, apart from each release's
  versioned historical contract, which now also freezes gate-job names and approval rules; readiness
  prerequisites are per workflow, so publication no longer waits for the staging apply it precedes; the
  canonical artifact registry is declared rather than derived; publication refuses, before any
  credential, an image store reporting a manifest digest and a rerun whose gates are listed under
  another attempt; the checker refuses environment expressions, `dynamic` blocks, module providers,
  conditional ci.yml and preflight steps and misresolved module sources, and evaluates the plan role and
  every policy it can reach; the guard parses `gh api` flag clusters, `find`/`tree` writes and GNU
  long-option prefixes; and this record declares its amendments to ADR 0011. The superseded text is
  not kept here: nothing was committed under it.
- **Decision owners:** Firmbatch product owner and maintainers
- **Milestone:** 3.3b — Terraform, container and delivery foundation (ADR 0011 decision 1)
- **Builds on:** ADR 0011 and `docs/architecture/m3-3-aws-staging-topology.md`, **amended** where
  "Amendments to ADR 0011" below says — deployment authority and rollout (§9), migrate before rollout and
  the build per deployment (§9.3), a third environment and plan-version reads (§9.1, §9.3), the policy guard
  (decision 8), and policy results and the cost summary (§9.2, decision 10) — and otherwise unchanged; every
  §17 invariant of `docs/architecture/v1-target-architecture.md`, unchanged.
- **Refines, without reopening:** ADR 0011 decision 7's secrets table (who writes the Cognito
  client secret value), decision 8's module table (the `delivery` module no longer holds ECR, the OIDC
  provider or the GitHub roles), decision 10's evidence location, and the M3.3c migration number
  (`0008`, decision 14). Each refinement is stated below with its reason; what amends ADR 0011 rather than
  refining it is listed under "Amendments to ADR 0011".

## Context

ADR 0011 settled the protected staging architecture and split Milestone 3.3 into four slices,
of which only M3.3d may create a resource. M3.3b is the scaffolding: Terraform roots and
modules, ECS task-definition and service contracts, the container build, ECR and the delivery
structure, with the required acceptance tests. The human approved the protected-file changes
on 2026-09-13 with amendments, recorded here: agents make **no AWS API call, read-only
included**; the evidence restriction covers **M3.3 AWS staging evidence only**; the human's
existing administrator role is for a later **human** bootstrap and is never named in, trusted
by or assumable through anything in the repository.

At implementation, `main` had no branch protection, no rulesets, no environments and no
`CODEOWNERS` file, and the repository is public with forking allowed. Terraform 1.15.8 was the
installed version; the HashiCorp release feed listed 1.15.9 and 1.16.2. The Terraform Registry
listed `hashicorp/aws` 6.64.0 as its latest stable release; its documentation was read for the
attributes whose names were in doubt, and every attribute used is validated by `terraform validate`
against the 6.64.0 schema. Docker, Podman, PyYAML, tflint, checkov and actionlint were not installed.
These are point-in-time observations from read-only lookups, not captured evidence.

## Decision

### 1. Three roots, eight modules, pinned versions, mocked tests

`infra/terraform/` holds three roots, applied in this order:

1. **`bootstrap`** (per account): the state and plan buckets and their keys, the release key, the
   account's GitHub OIDC provider, and **every GitHub delivery identity** — the staging plan and apply
   roles and the artifact-publish role, their trust policies, permission policies and permissions
   boundaries (decision 5);
2. **`artifacts`**: the canonical release repository and the release-record bucket (decision 13). It
   creates no identity and no key; it names the roles the bootstrap root created, and refuses to plan
   until it has read each one and proven it exists — artifact-publish under its boundary, trusting
   exactly its environment — so no resource policy names a principal that does not exist;
3. **`environments/staging`**: the eight modules, whose `delivery` module now holds only the workload
   permissions boundary and the operator's identity-binding policy.

A production placeholder has no `.tf` file. Each root has its own S3 backend key
(`bootstrap/terraform.tfstate`, `artifacts/terraform.tfstate`, `staging/terraform.tfstate`) with
`use_lockfile = true` and `encrypt = true`; no workspace is used anywhere. The bootstrap and
artifacts roots are applied only by a human; the staging root's first apply is a human's
(decision 5). Identity policies may name predictable future ARNs — the release repository, the
release-record objects, the staging roles' task definitions and services — because a policy naming a
resource that does not exist yet grants nothing; resource policies name only principals that exist.

**Terraform is pinned to exactly 1.15.8** — the version installed and validated here — in
`infra/terraform/.terraform-version`, every `required_version`, CI and both workflows; moving to
1.15.9 or 1.16.x is a later, reviewed change with a regenerated lock. **`hashicorp/aws` is pinned
to exactly 6.64.0**, the only provider. Each root commits a `.terraform.lock.hcl` with
`linux_amd64` and `darwin_arm64` hashes.

**Every Terraform test lives in a root's `tests/` directory**, so it runs against that root's
committed lock, targets modules through `run { module { … } }` blocks, uses `mock_provider` for
every provider configuration its root declares, and uses `command = plan` only. The policy
check refuses a test file outside a root, a JSON-syntax `.tftest.json` test anywhere (it reads
only HCL), a test that leaves a provider configuration unmocked, a real `provider` block in a
test, and any command but `plan`; the gate runs that check before any `terraform test`, with every
AWS credential removed and instance metadata disabled. It also refuses, anywhere under `infra/`,
every `*.tf.json` file, every Terraform override file (`override.tf`, `*_override.tf` and their JSON
forms), override directories, a `terraform.d` plugin mirror and CLI configuration (`.terraformrc`,
`terraform.rc`): each can change a root invisibly to checks that read HCL. The first bootstrap apply
therefore uses a copy of the root outside the repository for its temporary local backend
(`runbooks/bootstrap.md`).

### 2. The account is enforced before anything is evaluated

Every AWS provider configuration sets `allowed_account_ids = [var.expected_account_id]`, and each
root postconditions `aws_caller_identity` on the expected account and `aws_region` on the
expected region. The workload region is a variable (`eu-central-1` recommended); the
`us_east_1` alias exists for the Cognito custom-domain certificate only.

### 3. The task definitions are contracts that cannot plan until M3.3c passes review

Every ECS task definition and service carries a precondition on `runtime_contract_reviewed`,
which is false in the example and true only once M3.3c's broker, bootstrap and identity-binding
programs, their dependencies and the image have passed review. Commands, the verified release
reference (`<release repository>@sha256:<64 hex>`, validated against the approved repository, a tag
refused; decision 13), CPU, memory and secret references are parameters. The
environment variable names the containers receive are the runtime contract M3.3c implements;
M3.3c's review may revise them. Every task definition is **`skip_destroy`**: a new digest is a new
revision, and the provider's replacement forgets the old revision without deregistering it, so every
earlier revision stays registered for rollback.

**A finding, recorded for M3.3c:** the existing web/API entry point (`control_plane/api/__main__.py`)
still loads `FIRMBATCH_AUTHENTICATOR_DATABASE_URL`, which the AWS-mode web/API task definition
does not supply by design (ADR 0011 decision 3). The image's default command is that entry
point, and it is not operational in AWS mode until M3.3c changes it.

ECS Exec is disabled on both services and absent from the cluster; the policy check refuses it.

### 4. Secret containers only — including the Cognito client secret's

No `aws_secretsmanager_secret_version` exists in the repository. The four database URL
containers are written by the bootstrap task (M3.3c), which alone may `PutSecretValue` on them.
**The Cognito client secret also gets a container with no value.** The topology's secrets table
said Terraform writes that value; M3.3b's instruction is that Terraform creates containers and
never secret values, so **who writes the Cognito client secret into its container is M3.3c's
decision**, and the bootstrap task's permissions deliberately do not cover it yet. The client
secret remains in Terraform state regardless, because Terraform creates the confidential client
— the acknowledged exception of ADR 0011 decision 7.

### 5. Authority is split: humans own the trust anchors, the pipeline applies workloads inside a contract

No IAM condition can limit what a trust policy says, what value a secret update carries, or which
image, command and secret references a task definition names. The split follows from that: what
IAM cannot bound is a human's; what the pipeline applies is bounded twice — by IAM where IAM can,
and by a check of the saved plan itself where it cannot.

**The human AWS SSO/MFA bootstrap owns the trust anchors:** the GitHub OIDC provider; the plan,
apply and artifact-publish roles, their trust policies, permission policies and permissions
boundaries (all in the bootstrap root); the workload boundary and the operator policy; the ECS
execution and task roles and their policies; every KMS key, key policy and alias; every Secrets
Manager container; the state, plan and release-record buckets; the release registry and its
policies; initial secret values; and the unavoidable security bootstrap operations (service-linked
roles, the first apply of each root).

**The apply role's permissions boundary admits; it does not subtract.** Its Allow statements are
the ceiling, and an action outside them is outside the role whatever its own policy grants: the
staging service families; three release-verification reads on the one release repository; the IAM
reads refresh needs, named one by one; and `iam:PassRole` on exactly the ten pre-created workload
role ARNs, conditioned on `iam:PassedToService = ecs-tasks.amazonaws.com`. No IAM create, update,
delete, attach, detach, policy-version, trust-policy or boundary change is inside it. (An earlier
draft instead denied "every IAM change" with a `NotAction` of the IAM reads and `iam:PassRole` —
which, by definition, denied every non-IAM operation too, state access, EC2, RDS and ECS included.
It is gone; see decision 15 for how the checker now refuses that pattern by evaluating it.)

The boundary's denies then narrow what the ceiling admits: role passing to anything but the workload
roles and ECS tasks (defense in depth); identity and account administration; secret values and
secret-container writes, except the master secret RDS creates on the caller's behalf; key creation,
key policies, aliases, re-encryption and grants for anything but AWS services; decryption with any key
but the state, plan and release keys; one-off tasks, task sets and ECS Exec; **deregistering or
deleting any task-definition revision**; service changes outside the two services; **either service
running a task definition outside its own family** (`ecs:task-definition`, when the request names one)
and **ECS Exec on any service change** (`ecs:enable-execute-command`); image publication, re-tagging,
deletion and every registry change; release-record writes; data export and log reads; reserved
purchases, alarm suppression and budget actions; any database class but the reviewed one; compute
outside Fargate; Cognito user administration; every bypass of the state and plan buckets; and, through
the only two `NotAction` statements, any request outside the staging and certificate regions.

**The apply role's own policy** registers task-definition revisions of the five exact families only —
**no `ecs:DeregisterTaskDefinition`** — creates and updates each service only with a task definition of
its own family, in the one cluster, and never with ECS Exec (`ArnLikeIfExists` and
`StringEqualsIfExists`, so a request that changes neither passes, and one that names another family or
ECS Exec does not); passes only the ten workload roles to ECS tasks; and reads exactly the release-record
version and the release digest it re-verifies before applying (decision 15). `delivery.py plan-summary
--mode apply` refuses a saved plan that changes an IAM, KMS, Secrets Manager, ECR or S3 resource, or a
budget action, before anything is applied.

**The plan role is under its own permissions boundary** (added in the fourth correction pass, human-applied in
the bootstrap root like every delivery identity). Its ceiling is exactly the actions the plan role's own policy
grants; its denies refuse secret values and SSM parameters, decryption with any key but the state key and the
release key through S3, encryption with any key but the state and plan keys, saved-plan reads, history and
retention bypass, state writes, and any object but state, its lockfile, new saved plans and release records.
So a policy attached to the plan role by a later mistake still cannot read a secret, and state reads, the
lockfile, saved-plan writes and refresh are unchanged. The checker and a mocked bootstrap test evaluate it with
the plan role's policy and against a side door granting every action.

**After the first human apply, staging-apply applies verified saved plans for** approved
task-definition revisions, service updates, immutable image-digest rollout, and ordinary network,
edge, database, identity, observability and budget changes. IAM cannot see inside a task definition,
so `plan-summary` checks every task-definition and service change — at plan, before the plan is
stored, and again before apply — and refuses: an image other than the verified release digest (a tag,
another digest, another repository); an execution or task role other than the family's own
pre-created role; an unapproved family or service; a secret reference outside the family's approved set
(by environment name and by secret container); a privileged container, host or bridge networking, any
volume, mount point or host device, an added capability or one not dropping `ALL`, a missing or root
user, a writable root filesystem, a shared host PID or IPC namespace, non-Fargate compatibility, ECS
Exec, a public IP, a revision that is not `skip_destroy` or a change that would deregister one, and
any value still unknown while planning. The protected apply environment and its human approval stay
mandatory. The budget is pipeline-managed because changing its amount or threshold is not an
escalation; budget actions are.

**The first full staging apply, at M3.3d, is a human's** (runbook), because the ECS roles, keys and
secret containers and the resources that use them are created together. Ordinary changes afterwards
use the protected saved-plan pipeline; a plan with a non-zero human-applied count is applied by a human
instead.

#### The privilege and resource ownership matrix

| Resource or capability | Human bootstrap (SSO/MFA) | Pipeline, plan-readable (`staging-plan`) | Pipeline, apply-managed (`staging-apply`) | `artifact-publish` | Application / runtime | Explicitly prohibited |
| --- | --- | --- | --- | --- | --- | --- |
| GitHub OIDC provider; plan, apply and artifact-publish roles; their trust and permission policies and boundaries (bootstrap root) | creates, changes | reads | — | — | — | any pipeline change; removing a boundary; broadening a trust; a replacement identity |
| Workload boundary, operator policy (staging root) | creates (first apply), changes | reads | — | — | — | any pipeline change |
| ECS execution and task roles and their policies | creates (first apply), changes | reads | `iam:PassRole` on the ten exact ARNs, to `ecs-tasks` only | — | ECS assumes them | create, update, attach or detach by the pipeline; passing any other role |
| KMS keys, key policies, aliases (state, plan, release; workload and refresh-token) | creates, changes | reads metadata; decrypts release records through S3 | encrypts and decrypts state and plans; decrypts release records through S3; grants for AWS services only | `GenerateDataKey` and `Decrypt` on the release key **through S3 only** — no key permission for ECR, whose grant encrypts layers | decrypts secrets through Secrets Manager; broker refresh-token encryption; **no key permission to pull** | key policies, aliases, deletion and non-service grants by the pipeline |
| Secret containers | creates (first apply) | describes | — (the RDS-managed master secret is created by RDS) | — | bootstrap task writes the database URLs; tasks read their own | every pipeline read or write of a value |
| Initial secret values | writes (Cognito client secret writer is M3.3c's) | — | — | — | bootstrap task (database URLs) | the pipeline, always |
| State bucket | creates, changes | reads the state key and its lockfile | reads and writes the state key and its lockfile | — | — | deleting a version; changing retention, versioning or policy |
| Saved-plan bucket | creates, changes | **creates new plan objects — the only principal that may** | reads plan versions under the prefix **by an ID it already holds** (IAM cannot confine it to one version; the workflow reads only the authorized one) | — | — | writes by any other principal; overwrite; retention bypass; version listing; deletion |
| Release repository, its lifecycle and repository policies; release-record bucket | creates, changes | describes images by digest; reads the current record | describes images by digest; reads **the exact authorized record version** | pushes one `git-<commit>` tag once; reads back what it pushed; creates records once and reads them back | execution roles pull | re-tagging, deletion, registry or replication changes, record writes by anyone else, by anyone without a human policy change |
| Network, edge, database, identity, observability, budget | first apply | reads | applies verified saved plans | — | — | budget actions |
| ECS cluster, task-definition revisions, services, image-digest rollout | first apply | reads | applies inside the delivery contract; registers revisions and **never deregisters one** | — | runs | tags, unverified digests, another family on a service, ECS Exec, unapproved roles or secrets, privileged/root/writable containers, host networking or mounts, added capabilities |
| One-off tasks (migrate, bootstrap, identity-binding) | an operator runs them (the identity-binding operator policy) | — | — | — | run under their own roles | `RunTask` by any pipeline role |
| ECS Exec | — | — | — | — | — | everyone |

Every trust policy requires `aud` exactly `sts.amazonaws.com` and `sub` exactly
`repo:chamsrut/firmbatch:environment:<name>` with `StringEquals`; the workflows additionally check
the pinned repository ID (`1349512121`). **What remains:** an apply session still holds the power
to reconfigure what the pipeline does apply — security groups, the load balancer, the database
instance's settings, and workload rollout inside the contract — so the apply credential is as
powerful as that, and the reviewed saved plan, the protected environment, the bound deployment
authorization and the pinned workflow are the controls around it. The IAM action lists are scaffolding
scoped to the accepted staging resource families and **have never been exercised against AWS**; where
an action's resource-level or condition-key support is uncertain (task-definition registration by
family ARN; the ECS condition keys on service requests), the grant still names the exact resource, so
a mistake fails closed at M3.3d. They are refined against the first real saved plan.

### 6. The workflows fail closed until humans have prepared them

`artifact-publish.yml`, `staging-plan.yml` and `staging-apply.yml` are `workflow_dispatch` only,
with empty top-level permissions, `bash -eo pipefail`, SHA-pinned actions and concurrency groups
(plan and apply share one). Each begins with
a **preflight job that references no environment and requests no OIDC token**, so an environment
GitHub has not been given cannot be created by reference and no token exists before these hold:

- the event is `workflow_dispatch`, the ref is `refs/heads/main`, GitHub reports the ref
  protected, the repository name and ID match, and the event is not from a fork;
- `infra/delivery/readiness.json` attests every human prerequisite. **It is committed with every
  value false and no deployment authorization**;
- the GitHub API shows the environment exists with required reviewers, self-review prevention,
  no administrator bypass and a deployment-branch policy of exactly `main`;
- the source commit is the merge commit of exactly one pull request into `main` and reachable from
  `origin/main`, **approved**: only reviews submitted before the pull request's `merged_at` count; only
  from an account other than the author's whose association the review reports as `OWNER`, `MEMBER` or
  `COLLABORATOR` — which is not itself proof of write access, and whose timing (at submission or at the
  read) is unobserved — and which **holds write permission when the preflight runs**; no such reviewer's
  latest review requests changes; and one approves the final head (every page of reviews is read). This
  is the rule for a commit about to act — the one being published, and the source commit a plan or apply
  runs Terraform from. Because the permission is read then, a revoked approver of `main`'s head blocks
  publication, plan — rollback included, which also plans from `main` — and apply from that commit until a
  newly approved merge lands; that is deliberate. A published release keeps the approval frozen into its
  record (decision 15);
- the workflow's own readiness prerequisites are attested (`WORKFLOW_PREREQUISITES` in `delivery.py`):
  publication does not require `human_applied_resources_applied_by_human`, which is attested only after
  the first staging apply that deploys the first release; plan and apply require every prerequisite;
- for apply, readiness.json **as `origin/main` holds it now** records exactly one unexpired deployment
  authorization naming exactly the dispatched plan and release (decision 15).

The environment-bound job needs preflight and carries exactly the guard
`github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.repository_id ==
'1349512121'` — the checker refuses any other spelling, any status function, `continue-on-error` and any
step-level `if` but the final cleanup's `always()`. **A repository file cannot prove a GitHub setting**;
the preflight re-checks what the API shows, and branch protection itself (which the workflow token
cannot read) rests on the attestation and on `GITHUB_REF_PROTECTED`.

### 7. A saved plan is one immutable object version, verified independently at apply

The plan job writes the plan and every other file into a private runner directory (decision 15),
shows only action counts, the count of human-applied changes and the count of checked ECS changes,
uploads the plan with `--if-none-match '*'` to `plans/staging/<40-hex commit>/<64-hex SHA-256>.tfplan`,
and prints the deployment tuple — the key, version ID and SHA-256, and the release's commit, image,
record version ID and record SHA-256 — in the job summary. The plan bucket policy refuses a
pipeline-role `PutObject` that lacks `If-None-Match`, so, while a current version exists at a key, a
pipeline role cannot lay a new version over it; and it refuses `PutObject` to **every principal but the
exact plan role** — the apply role, any other staging role and an operator included — so nothing in
the bucket was written by anything but the plan job. Once lifecycle expiry leaves only a delete marker
the key can be written again — necessarily with the same content, since the key carries its SHA-256,
and under a new version ID no authorization names. Neither condition has been observed against S3.

The apply job is dispatched with that tuple, shown in the run name and so in the approval request. It
re-derives and re-verifies the source commit, its reachability and its approval, and the deployment
authorization, before any OIDC token; installs and checks the pinned Terraform; re-verifies the release
immediately before applying (decision 15); refuses the plan object unless S3 returns the named
version, KMS-encrypted, under governance retention that has not lapsed and younger than the configured
age (at most 24 hours); recomputes the SHA-256; compares the plan archive's embedded
`.terraform.lock.hcl` with the approved commit's; refuses a change to a human-applied resource type, a
plan whose `release_image` is not the verified reference, and any task-definition or service change
outside the delivery contract (decision 5); and runs `terraform apply` on that file. It never plans, and
it never builds, tags or pushes an image. Terraform refuses a stale saved plan itself.

**The accepted IAM limitation.** The apply role needs `s3:GetObjectVersion` on the plan prefix,
and IAM cannot restrict it to one version: **the role can read any plan version under the prefix whose
version ID it already holds.** The compensating controls: no pipeline role can list versions, so an ID
cannot be discovered; access is scoped to the plan prefix; lifecycle removes plan versions about two
retention periods after creation; the workflow reads only the version the authorization names; and
apply refuses any version past the allowed age. Someone who already holds an old version ID inside
that window could read that plan with the apply role; nothing here claims otherwise.

### 8. Deployment values stay outside the repository

The account ID, region, role ARNs, bucket names, key ARNs and maximum plan age are GitHub
**environment variables**, each environment holding only its own role; the check refuses a
workflow that can see another role. The plan-time Terraform variables, reviewer CIDRs included,
are the `staging-plan` environment **secret** `STAGING_TFVARS_JSON` — a secret for masking, not a
credential — written to a private runner file only after the independent allow-list check accepts it
and its account and region match. No valued `tfvars`, no reviewer CIDR and no AWS access key is
committed or held anywhere. Deployment authorizations are the one deployment fact in the repository:
a reviewed pull request to `main` records them in `readiness.json`, bound to exact identifiers
(decision 15), never to a value.

### 9. CI builds the image; the static gate never needs Docker

`scripts/verify-repository.sh` gains one gate that runs `infra/terraform/scripts/static-checks.sh`
and fails when Terraform is missing or not the pinned version. `ci.yml`'s `verify` job installs the
pinned Terraform for it; a new `container` job is written to build the image from the pinned
digests and locks, to check that it runs as UID 10001, imports the web/API and migration entry points
and holds no test code or environment file, and to log in to no registry and push nothing. It has
not run; the policy check verifies only its shape. It is to be made a required status check by the
human. Locally, where Docker is absent, the image has not been built.

### 10. The container

A three-stage build: the portal with Node 24 from `portal/package-lock.json` with `npm ci`; Python
dependencies from `requirements-v1-lock.txt` with `--require-hashes --no-deps --only-binary=:all:`;
a runtime stage on the same pinned Python base with only `firmbatch/__init__.py`,
`control_plane/` (without `tests/` or `testing/`) and the built `portal/dist`, running as
`10001:10001`. `.dockerignore` denies the whole context by default. The compiled portal is copied
in for M3.3c; today's API does not serve it. The image contains no broker, bootstrap or binding
program. The image is published only by `artifact-publish` (decision 13), which adds its provenance
as labels at build; CI's `container` job builds it to check it and pushes nothing.

### 11. The policy guard: no AWS, bounded Terraform, no push, no M3.3 staging evidence

ADR 0011 decision 8 said extending the guard "is not this slice's". This slice extends it anyway,
because the M3.3b instruction required it and the human approved the exact change: that sentence
is superseded here, not rewritten there. Agents' commands now refuse:

- **every AWS CLI call except `aws`, `aws --version` and help pages** (`aws help`,
  `aws <service> help`, `aws <service> <operation> help`; a `help` after further operands is an
  ordinary argument and refused) — read-only calls included, because they print account state,
  secrets or identity data into a transcript. A narrowly scoped set may be authorized in M3.3d once
  the account, role, region and operation are confirmed;
- every Terraform subcommand except `fmt`, `validate`, `version`, `providers lock` and `init` whose
  last `-backend` value is `false` — `plan`, `apply`, `destroy`, `import`, `refresh`, `taint`,
  `untaint`, `force-unlock` and state mutation as `cloud-mutation`; `test`, `output`, `show`,
  `console`, `workspace`, `login`, other `providers` subcommands, state reads and a backend `init`
  as `terraform-bounded`. The mocked tests run only through `static-checks.sh`;
- registry login and push for `docker`, `podman`, `buildah`, `nerdctl`, `finch`, `skopeo`, `crane`
  and `oras`, including `buildx` registry outputs, `imagetools` and the tools' tag, copy, delete and
  attach verbs; `gh variable set|delete`, `gh run rerun` and `gh workflow enable`;
- any write under **`docs/evidence/m3/aws-staging/`**, and any command other than a read that names
  a path there, the location ADR 0011 decision 10's M3.3d evidence now uses. Every other evidence
  location, M3.1 and M3.2 captures under `docs/evidence/m3/` included, is unaffected. The guard can only
  recognise the location; the policy check adds a repository-level refusal of any file there before
  the readiness file records a deployment authorization, and the `record-evidence` skill says so.

**After the independent review (2026-09-14)**, with the same approval scope, the guard also:

- parses each command prefix by its own grammar — `timeout -s SIGNAL`, `--signal`, `-k`,
  `--kill-after` and its DURATION operand; `env -u`, `-C`/`--chdir` (which moves the directory later
  paths resolve against) and `-S`/`--split-string` (whose string it splits into the command it runs);
  `nice -n`, `stdbuf -i/-o/-e`, `ionice`, `time -f/-o`, `exec -a` — attached or separate;
- refuses every `gh api` request but a plain `GET` or `HEAD` with no field and no input: `-XPOST`,
  `-X=POST`, `--method` in any spelling, `-f`, `-F`, `--field`, `--raw-field` and `--input`, attached or
  separate, and the `graphql` endpoint;
- normalizes program names — the last path component, `.exe` removed, lowercased — and routes
  `terraform.exe`, `tofu` and `opentofu` through the Terraform rules and `aws.exe` and `aws2` through
  the AWS rules.

**After the review's verification of those corrections (2026-09-14, third pass)**, with the same approval
scope, the guard also:

- reads a `gh api` short-flag cluster letter by letter by gh's own grammar — `-if state=approved` is `-i`
  and a field, `-iXPOST` a method — never scanning a value flag's value (`-H`, `-p`, `-q`, `-t`) as a flag;
- routes the files `find -fprint`, `-fprint0`, `-fprintf` and `-fls` and `tree -o`/`--output` write through
  the write rules, so neither reaches `docs/evidence/m3/aws-staging/` or overwrites existing evidence, and
  refuses `find -ok` and `-okdir` like `-exec`;
- resolves a wrapper's long options as GNU `getopt_long` does, by unique prefix (`timeout --sig`,
  `env --ch=DIR`, `env --spl=…`), and refuses an ambiguous prefix as unparseable.

The guard remains an accident-prevention guardrail, not a security boundary.

### 12. The human bootstrap

The buckets, keys, OIDC provider and delivery identities, then the release registry, then every
human-applied resource of decision 5, are created by a human with an existing administrator role —
preferably assumed through AWS SSO with MFA — whose profile, account and authorization are confirmed
separately at M3.3d, in that order and only after the three GitHub environments are protected. That
role is named nowhere in the repository, is trusted by nothing the repository defines, and is never
assumable by GitHub Actions, ECS or a workload. The permanent plan, apply, artifact-publish and ECS
roles stay least-privileged and separate from it.

### 13. Build once, promote by digest

This supersedes the earlier decision that initial image publication is a manual human action.

**The canonical release repository** is the artifacts root's: private, tags `IMMUTABLE` with no
exclusion filter, KMS-encrypted under the bootstrap root's release key, scanned on push, never
force-deleted. Its lifecycle policy expires **untagged** manifests only, so every tagged release —
every deployed and rollback digest — is retained; its repository policy denies image deletion and
tag-mutability changes to every principal, so pruning is a reviewed human change to that policy first.
There is no `latest` tag and no environment-specific build or repository (the repository name is
refused if it names an environment). The registry account is a variable: today the staging account,
later a dedicated artifact account, with nothing in the deployment contract changing.

**`artifact-publish`** is a distinct GitHub environment and role, created by the bootstrap root,
separate from the human bootstrap identity, the plan and apply roles and every ECS role. Its trust is
exactly this repository's `artifact-publish` environment (audience `sts.amazonaws.com`); protected
`main` is bound by that environment's main-only deployment branch policy, which the preflight
verifies, because IAM sees only the environment in GitHub's default subject. Its boundary allows
image push to, and the reads a resumed publication needs from, the release repository — image details,
the manifest, the configuration blob — creating and reading back release records, and the release key
**through S3 only**, and nothing else; it cannot plan, apply, deploy, change infrastructure, delete or
re-tag, pass or assume a role, or read a secret. It is disabled behind `readiness.json` like the other
workflows. **Key permissions, as resolved:** ECR encrypts and decrypts image layers under the grant it
takes on the release key when the repository is created, so neither the publisher nor a pulling
execution role holds a key permission for images, and no consumer account is granted anything on the
key; S3 SSE-KMS needs the publisher's `kms:GenerateDataKey` for a new record and `kms:Decrypt` to read
one back, and each reader's `kms:Decrypt` through S3.

**`artifact-publish.yml`** runs only on a manual dispatch of an approved merge commit on protected
`main` — never from a pull request or a fork — and publishes as a resumable state machine (decision 15).

**The release record** (`firmbatch.release-record`, `schema_version` 1) binds the source repository,
ref and full commit; **the approval that admitted the commit** (decision 15); **the original publish
run ID and attempt** and the image's build time, from the image's own provenance labels; the
repository, tag, OCI digest, full image reference, media type and configuration digest of each
artifact; a component-to-artifact map (every component runs the one control-plane image today); the
Dockerfile, dependency-lock and base-image digests and the (empty) build arguments; the SBOM's key —
addressed by the image's configuration digest — and SHA-256; the scan status (`pending` at
publication); and a `signatures` list, empty today, so signing extends the record without changing what
deployment reads. It holds no credential, plan or environment configuration; its schema is exact, so a
record carrying any other key is refused. Every field is a deterministic function of the pushed image,
the stored SBOM and the commit, so a retry regenerates exactly the same bytes.

**Versioned contracts.** Each supported `schema_version` has a frozen contract in `delivery.py` — the
release's immutable historical contract: component names, required lock files, workflow identity, the
names of the gate and publication jobs its exact publish attempt must show, the approval rules its frozen
approval is validated by (the record's keys, qualifying associations and write permissions), and the
validation rules. A later component (the M6 GPU worker), lock file, renamed CI job or changed approval
rule is a new version beside it; records keep validating under the version they declare, so rollback to
an earlier release stays possible: verification reads the attempt's workflow path, job names and approval
rules from the record's own contract, so a later version neither invalidates nor reinterprets an earlier
record. An unknown version is refused, never
guessed, and a version is retired only by removing its contract in a reviewed change that records the
compatibility decision.

**The live security overlay is not part of any contract.** `infra/delivery/admission-policy.json` —
security stops, digest-scoped exceptions and their expiry, the finding maxima — is read from
`origin/main` whenever a release is promoted or applied, never from the checked-out commit and never from
the record. At apply the checkout is the plan's source commit, which can predate a stop or an exception's
removal; reading `main` makes a revocation merged after the plan refuse the apply. An overlay whose schema
the checkout's code does not know is refused, so an older plan cannot apply under a newer overlay it
cannot read.

**Promotion.** `staging-plan` takes a `release_commit`, which the preflight requires to be reachable
from `main`. The plan job reads the record and `delivery.py verify-release` refuses it unless decision
15's checks hold — the contract, the frozen approval, the exact publish attempt, the digest by digest
in the immutable repository with exactly `git-<release_commit>`, and admission under the committed
policy. Terraform receives the full digest-qualified reference from the record alone — `write-tfvars`
refuses one in environment configuration — and both the staging root and the compute module refuse a
tag or another repository. `staging-apply` re-verifies the same release before applying and refuses a
plan that runs any other image. Neither job builds, tags or pushes. Production later promotes the same
record and digest through its own plan and approval.

**Rollback** is a new plan of an earlier `release_commit` whose digest is still retained; a digest
no longer in the registry is refused, never rebuilt; its task-definition revision is still registered.

**Cross-account or cross-region promotion** is not enabled. When it is needed, destination
repositories and policies are created explicitly by a human, images arrive by controlled replication
or digest-preserving copy, and deployment waits for `delivery.py verify-destination-digest` to prove
the destination holds the same digest.

### 14. An incidental reliability and security correction: the password-hash contract (migration `0007`)

M3.3b's canonical verification failed once in the PostgreSQL suite with `PasswordPolicyError` from
`hash_password`. The cause is M3.1's: `security/passwords.is_well_formed_password_hash` and three
database entry points — `signup_account`, `complete_account_recovery`, `change_account_password` —
applied the generic secret-shape recogniser to the Argon2id PHC hash, whose random base64 salt and
digest can form an AWS access-key-id shape. A valid hash of a valid password was refused at random.

A validated Argon2id PHC hash is structured credential material, not arbitrary metadata, so the
correction removes **only** the shape scan from password-hash validation: in Python, and in the three
database functions by forward migration `0007_password_hash_contract` (`CREATE OR REPLACE`, restoring
the earlier bodies exactly on downgrade, with owner, ACL and hardening unchanged). NULL, length and
exact Argon2id PHC structural validation remain. The recogniser itself is unchanged and still
applies everywhere else it applied — metadata, audit fields, credential labels, names, slugs,
idempotency keys and the API's inputs — and raw passwords are still validated before hashing, as
before. Migrations `0001`–`0006` are unedited. Deterministic tests use a valid hash whose salt
encodes the formerly refused shape. **This correction takes migration number `0007`; the M3.3c
identity mapping that ADR 0011 and the M3.3 topology document first assigned to `0007` becomes
`0008`**, and both documents now carry that number with a pointer here; ADR 0009's M3.1 record is not
rewritten.

### 15. Publication, promotion and apply bind to exact, immutable facts

The independent review of the staged tree found that publication could not recover from a partial
failure, that promotion trusted mutable GitHub state, and that apply trusted what the plan job had
verified. Each is corrected, and each property is unit-tested against in-memory fakes of GitHub, ECR
and S3 — none has run against either.

**Publication is an explicit, resumable state machine.** Before any AWS credential: a check that this run
attempt's own preflight and verification jobs succeeded **in this attempt** — the same predicate promotion
later applies to the attempt a record names, so a partial rerun whose gates GitHub lists under an earlier
attempt stops here instead of publishing a release promotion would refuse forever; one build whose labels
embed its provenance — repository, repository ID, commit, workflow identity, run ID, attempt and build
time — and whose BuildKit metadata (`--metadata-file`) records its configuration digest; a local inspection
refusing anything but a single linux/amd64 image whose local ID is exactly that configuration digest (an
image store that reports a manifest descriptor, or a manifest digest as the ID — Docker's containerd store —
is refused, because the SBOM would be stored under a digest no resume looks for); the SBOM of that image;
and a release draft binding that configuration digest, its provenance, the SBOM, the frozen approval and
the committed build inputs. The SBOM is addressed by the draft's digest, never the local image ID. Then
the role, and one of two paths:

- **fresh** — `git-<commit>` does not exist: the image's SBOM is created first, under its
  configuration digest, so an image is never pushed without the SBOM a later attempt would need; the
  tag is pushed once; and the registry's own bytes — a manifest that hashes to the digest, a
  configuration blob that hashes to the digest the manifest names — must be exactly the image this
  attempt built;
- **resume** — `git-<commit>` exists: nothing is pushed, deleted or overwritten; the registry's bytes
  must carry this commit's release provenance from whichever attempt pushed it, and that attempt's SBOM
  must be stored. **Incompatible provenance, another tag or a different digest stops for explicit human
  recovery**; nothing is ever rebuilt for an environment.

Both paths then generate the release record deterministically and create it with `If-None-Match`. **A
412, or a response that never arrived, reads back that exact key and succeeds only if the stored
object's full SHA-256 and its stored semantic identity** — object metadata naming its kind, commit,
digest and SHA-256, and KMS encryption — **are this release's**; otherwise publication fails closed. A
repeat dispatch of a completed publication changes nothing. An attempt that fails after its SBOM but
before its push leaves an SBOM no record names; the next attempt publishes afresh.

**The exact publish attempt.** The record names the original run ID and attempt — the attempt that
pushed the image, from its labels. Verification queries that attempt's own endpoint and its jobs, never
the run's aggregate conclusion: it must be a completed `workflow_dispatch` of `artifact-publish.yml` on
`main` for the commit, in this repository, with its preflight and every required verification job
succeeded and its publication job run. A later rerun, failed or not, is never consulted, and so cannot
invalidate a published release. (A publication completed by a later dispatch names an attempt whose
publication job failed after pushing; the immutable record is the proof that publication completed.)

**Approval is historical and frozen.** The publish preflight computes the approval as decision 6
describes and outputs it as evidence; the record freezes it: pull request number, merge commit,
`merged_at`, the pull request's head and author, the approver's ID and login, the qualifying review's ID,
time and commit, and the association and permission verified. Promotion, apply and rollback validate
that recorded approval by the rules of the contract its record declares — its keys, qualifying
associations and write permissions — and cross-check only the pull request's immutable facts — merge
commit, `merged_at`, head, author — never a reviewer's current permission or a later review. (The
deployment source commit a plan or apply runs from is a different thing: decision 6 requires its approver's
write permission when the job runs.)
**Revoking a release is an explicit security stop**, never a rewrite of historical approval: a
CODEOWNERS-reviewed entry in `infra/delivery/admission-policy.json` naming the exact digest and commit,
which refuses promotion and apply outright.

**Admission, with digest-scoped, expiring exceptions.** Zero critical and zero high findings remain the
default. An exception is committed in the admission policy — never a workflow input or option — and
names one exact image digest, exact CVE or GHSA identifiers (at most ten), a reason, its approver, the
reviewed pull request, and a creation and a mandatory expiry at most thirty days apart. The whole policy
is validated on every use: a malformed, overly broad or not-yet-created entry refuses every admission;
an expired exception, or one for another digest or identifier, admits nothing. The scan must be complete
for exactly the release digest, and its listed findings must agree with its severity counts, so a finding
cannot be hidden by truncation. Plan and apply each evaluate admission independently, at their own time.

**Apply re-verifies the release immediately before applying**, trusting nothing the plan job wrote:
exactly the release-record version and SHA-256 the authorization names, its stored identity, and — under
the contract of the version the record declares — its frozen approval and exact publish attempt; a fresh
query of the repository's configuration, the digest's tags and its scan; admission, exceptions and
security stops re-evaluated now under the admission policy **as `origin/main` holds it** (decision 13's
live security overlay), never the plan's older checkout; and a saved plan whose `release_image` is that
same digest and whose `release_registry_*` inputs declare that digest's repository. Any relationship that changed refuses the apply. The apply role holds
only the ECR describe actions and the exact record-version read this needs.

**Deployment authorization is bound to one plan and one release.** The bare boolean is gone.
`readiness.json` records authorizations, each naming the plan object's key, version ID and SHA-256, the
release commit and image digest, and the release record's version ID and SHA-256, with the authorizer, the
reviewed pull request and an expiry at most 24 hours after the authorization. The apply preflight and the
apply job — before any OIDC token — read `readiness.json` from `origin/main` and require exactly one
unexpired authorization naming exactly the dispatched tuple, which the run name, and so the approval
prompt, shows in full. A previous authorization never authorizes a later plan.

**Runner files.** Every credential-bearing job keeps every file — plans, logs, release documents,
variables, Terraform's data directory — in a private directory created with `umask 077` and mode 700,
and ends with one step that runs whatever happened (`if: always()`, the only step-level condition allowed)
and removes that directory and any `errored.tfstate` or crash log Terraform left in the working
directory. The cleanup is a separate step, so it cannot turn a failure into a success; nothing is printed
or uploaded.

**The checker evaluates, and fails closed on what it cannot read.** `infra/terraform/policy/check.py`
resolves the apply, artifact-publish and — since the third pass — plan policies against synthetic bindings
and decides representative requests, each carrying the keys AWS attaches to every request
(`aws:SecureTransport`, `aws:RequestedRegion`), so an always-true condition is decided as AWS would decide
it, and a condition on a key no request models fails closed rather than being read as absent. The plan role,
under its own permissions boundary since the fourth pass, must refresh, read state, create a saved plan and
verify a release, and must never read a secret value, a saved plan or its history, write state or a record,
push, pass or assume a role, roll out or run a task. Every policy a resource can hold is read — a literal, a
local, or `each.value` over a local map — and a policy of a type or form the checker does not read is refused,
never skipped. **The delivery identities' whole policy graph is checked, not their named policies:** each
identity may hold exactly one literal inline policy and one boundary in the bootstrap root; any other inline
policy, managed or exclusive attachment, `managed_policy_arns` or `inline_policy` on a role, policy held in a
local or built by `for_each`, or attachment anywhere to a role not proven to be declared beside it, is refused.
**Only the bootstrap root declares or owns a delivery identity** — the staging plan, staging apply and
artifact-publish roles. Every other root and module may declare only its explicitly allow-listed workload roles
(the compute module's `execution` and `task`, each with its reviewed name template), and a role is judged by its
effective `name` and `name_prefix`, resolved through locals, interpolation, variables and module values, not by its
resource label: an effective name ending in a delivery identity's suffix, in any letter case, is refused, and a name
that cannot be resolved, or plan-time text that could complete one, fails closed. An additional, unresolved or
indirectly attached policy on a delivery identity likewise fails closed. **Terraform `import` blocks are refused
everywhere under `infra/terraform`:** adopting an existing AWS identity or resource into state is a separate,
explicitly reviewed human procedure, never hidden inside an environment's ordinary configuration.
Every admitted document is read in full: no delivery policy may grant every action, a secret value, a
parameter, or decryption beyond the state, plan and release keys; and each boundary is evaluated alone against
a side-door policy granting every action, so an attached policy still cannot read a secret or a parameter —
and, for the plan role, cannot decrypt with another key, read a saved plan or write state. The representative
requests — state and exact-plan access, EC2 and VPC, RDS, task-definition registration, both services'
rollout, the workload role assignment, observability, the budget and release re-verification must be
effective; IAM mutations, another role or service for `iam:PassRole`, deregistration, another family or
ECS Exec on a service, one-off tasks, pushes, record writes, secret values, other regions and budget
actions must not be. It judges every `NotAction` and `NotResource` statement in every delivery, publication
and workload policy by what it does: a `NotAction` deny passes only if, in the staging region, it applies to
none of a set of ordinary actions; a `NotResource` deny only if it names its service's actions; neither
form may allow. The mocked bootstrap tests evaluate the rendered policies the same way. The workflow rules
read the parsed workflows — triggers however spelled, every permission, environments reserved to their own
files, checkout settings — and the YAML reader refuses quoted keys and every construct a real YAML parser
could read differently.

## Amendments to ADR 0011

ADR 0011 is not rewritten; its header declares these amendments and points here. Where the two
disagree, this record governs.

- **Deployment authority.** ADR 0011 decision 9 kept application deployment as a fourth stage "whose
  identity and approval are specified when M3.3b's delivery structure is reviewed, and neither the plan
  approval nor the apply approval authorizes it". That specification is decisions 5 and 15: workload
  rollout — task-definition revisions, service updates, digest rollout inside the ECS delivery contract —
  is applied by `staging-apply` from a reviewed saved plan, and is authorized by a deployment
  authorization recorded in `readiness.json` on `main` naming exactly that plan object and one release,
  together with the `staging-apply` environment approval. The apply approval alone still authorizes
  nothing.
- **Migrate before rollout.** ADR 0011 decision 9 says the migration task runs before service rollout and
  a failed migration aborts the rollout. The pipeline does not guarantee that: the apply role cannot run a
  task. Until one-off task execution in the pipeline is specified ("Still open"), an operator runs the
  `migrate` task, and confirms it succeeded, before applying a plan whose release needs it. The ADR 0011
  requirement stands as the target; this slice does not meet it in the pipeline.
- **A third environment.** ADR 0011 decision 9.1 names two environments. `artifact-publish` is a third,
  with its own role trusting exactly that environment and its own protections (decision 13).
- **Plan-version reads.** ADR 0011 decision 9.1's table and 9.3 say neither pipeline role can retrieve
  arbitrary historical plan versions. The apply role can read any plan version under the environment's
  prefix whose version ID it already holds — the accepted IAM limitation of decision 7, with its
  compensating controls.
- **Image build.** ADR 0011 §9.3's closing paragraph builds "one immutable container image … per
  deployment". An image is instead built once per approved release commit by `artifact-publish` and the
  same digest is promoted to every deployment (decision 13).
- **The policy guard.** ADR 0011 decision 8 describes the guard as allowing `fmt`, `init`, `validate`, `test`
  and `plan`, and says extending it is not that slice's. With the human's approval M3.3b extended it
  (decision 11): agents may run only `fmt`, `validate`, `version`, `providers lock` and
  `init -backend=false`, and `terraform test` only through `infra/terraform/scripts/static-checks.sh`.
- **Policy results and the cost summary.** ADR 0011 §9.2 has GitHub display policy results and the cost
  summary beside the action counts, and decision 10 lists both in the M3.3d plan summary. The plan job
  produces neither and its sanitized summary says so; the current cost estimate is produced by the operator
  during the separately authenticated plan review (`runbooks/staging-delivery.md`, part D) and recorded at
  M3.3d ("Still open").

## M3.3a open questions this settles

- The OIDC `aud` condition is `sts.amazonaws.com` exactly; `sub` names the repository by name,
  and the workflows verify the numeric repository ID (a `sub` template change would be a
  repository setting, which M3.3b does not make).
- An environment is never referenced before a job that references none has proven it exists and is
  protected (decision 6). The delivery identities are created only after the three environments are
  protected (the bootstrap runbook's order).
- The first apply of the staging root, and every change to a trust anchor, is a human's; ordinary
  changes — workload rollout inside the delivery contract included — use the saved-plan pipeline
  (decision 5; runbook).
- The plan file sits only in a private runner directory and is removed when the job ends; the only reader
  of plan JSON is `plan-summary`, which emits counts. No external policy or cost tool reads the plan.
  Where an operator keeps a plan copy during review is stated in the delivery runbook.
- The plan role's lockfile permission names the exact `<key>.tflock` object; its refresh reads are
  enumerated describe, get and list actions, with secret values, plan objects and user reads denied.
- ECS Exec is ruled out for every service and task.

## Still open

- **One-off task execution in the pipeline** (the migrate task before a rollout) is not specified:
  the apply role cannot run a task, and an operator runs one-off tasks at M3.3d — including `migrate`,
  before applying a plan whose release needs it. Until this is specified, ADR 0011 decision 9's
  migrate-before-rollout guarantee is amended to that operator obligation ("Amendments to ADR 0011").
- **Replication, signing and a production registry** (decision 13) are designed for, not built. A
  dedicated artifact account would get its own bootstrap apply creating only the artifact-publish
  identity and release key — a reviewed change to the bootstrap root.
- **The admission policy's thresholds** (no critical or high findings) are a starting point, not a
  measured one; the first real scan may require a reviewed change or an exception.
- **External assumptions, each to be qualified at M3.3d before the first use it governs.** None has been
  observed; readiness is all false, so no workflow can yet act on one. Each fails closed, and — since the
  third correction pass — each that gates publication does so **before any credential and so before the
  irreversible push**:
  - *AWS:* whether ECS accepts task-definition registration scoped by family ARN; whether
    `ecs:task-definition` and `ecs:enable-execute-command` are present, and in what form, on the service
    requests Terraform makes; whether ECR's `BatchGetImage` returns the manifest bytes that hash to the
    digest; the bucket policies' conditional-write and principal conditions. Each fails closed at the
    request it governs.
  - *GitHub:* the job names the attempt-jobs endpoint reports for a reusable workflow's jobs, and whether
    a "re-run failed jobs" attempt lists the jobs it carried over under itself — `check-publish-attempt`
    refuses before the build and any credential if not (a new dispatch, not a partial rerun, remains the
    supported way to resume a publication); whether a review's `author_association` is the association at
    submission or at the read (approval does not rely on it for write access); whether the workflow token
    can read an environment's protection fields (the preflight refuses if not).
  - *The runner:* which image store Docker uses, and whether BuildKit's `containerimage.config.digest` in
    `--metadata-file` equals the local image ID — `release-draft` refuses before any credential if the
    store reports a manifest descriptor, the metadata lacks the digest, or the two differ; and whether a
    `fetch-depth: 0` checkout of a commit provides `origin/main` for the security overlay and deployment
    authorization reads — both refuse if it does not.
- **Egress** through the NAT gateway is internet-routed and not narrowed by security groups.
- **The ALB is IPv4-only.** IPv6 reviewer entries are admitted by the Cognito WAF but cannot reach
  the ALB until it becomes dual-stack with IPv6 subnets.
- **The cost summary** is not produced by the plan job.
- **The IAM action lists** are refined against the first real plan.
- **Who writes the Cognito client secret value** (decision 4) is M3.3c's.
- **The OIDC trust binds the environment, not the workflow file.** A `sub` template carrying
  `job_workflow_ref` would bind both; it is a repository setting, not made here. The checker instead
  reserves each environment to its own workflow file.
- **`infra/terraform/scripts/static-checks.sh` and `infra/terraform/policy/`** underpin the guard's
  "tests only through static-checks" rule but are not on `AGENTS.md`'s ask-before list; adding
  them is an `AGENTS.md` change for the human to decide.
- **`npm ci --ignore-scripts`** in the image build is not applied: without Docker locally, whether
  the portal build still works without dependency lifecycle scripts cannot be checked here.
- **Whether the workflow token can read** an environment's `can_admins_bypass` and
  `prevent_self_review` fields is one of the external assumptions above, qualified at M3.3d: if it
  cannot, the preflight refuses, failing closed, and M3.3d revisits the check before the first dispatch.

## What this decision does not claim

It creates no AWS resource, GitHub environment, branch protection, ruleset, variable, secret,
image, deployment or evidence. It does not claim that any GitHub or AWS setting exists because a
test checks its shape. It does not claim the IAM policies, the bucket policies' conditions or the
workflows have run anywhere: they are statically checked, evaluated against synthetic requests by a
repository evaluator and by mocked Terraform tests, and unit-tested against fakes — none of which is AWS
or GitHub. It does not claim the image builds: that is CI's to show. It verifies nothing live, and
nothing here is VERIFIED LIVE.
