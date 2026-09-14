# Terraform — the protected AWS staging foundation

Milestone 3.3b scaffolding for the architecture in ADR 0011 and
`docs/architecture/m3-3-aws-staging-topology.md`; the implementation decisions are ADR 0012.

**Nothing here has been planned against AWS, applied, pushed or deployed.** The staging root
cannot plan its task definitions until M3.3c's programs pass review, the delivery workflows
refuse until humans have prepared GitHub and AWS, and creating any resource is M3.3d's, after a
reviewed plan, a current cost estimate and explicit authorization.

## Layout

| Path | What it is |
| --- | --- |
| `.terraform-version` | The one pinned Terraform version (1.15.8) |
| `bootstrap/` | The account trust root, applied first: the state bucket and the separate Object-Locked saved-plan bucket, the state, plan and release KMS keys, the account's GitHub OIDC provider, and every GitHub delivery identity — the staging plan and apply roles and the artifact-publish role with their policies and permissions boundaries. Applied by a human (`runbooks/bootstrap.md`) |
| `artifacts/` | The canonical release registry, applied second: the immutable, scanned, KMS-encrypted release repository and its policies and the Object-Locked release-record bucket. It creates no identity or key, and refuses to plan until every role it names exists. Applied by a human, never by a workflow |
| `environments/staging/` | The staging composition of the eight modules; its own state key |
| `environments/production/` | A placeholder. Production is a separate root, account and state, and Milestone 3 does not create it |
| `modules/network` | VPC over two zones, public, private and isolated database subnets, one NAT gateway, the S3 gateway endpoint, the security groups |
| `modules/edge` | Route 53, the regional certificate, the ALB, the 80 (redirect only) and 443 listeners and the path rules, and the structurally validated reviewer allow-list |
| `modules/compute` | The ECS cluster, the web/API and identity-broker services, the migrate, bootstrap and identity-binding task definitions (every revision `skip_destroy`), and their roles |
| `modules/database` | RDS PostgreSQL 16 and its parameter and subnet groups |
| `modules/identity` | The Cognito user pool, custom domain (certificate in us-east-1), app client, managed-login branding and the Cognito WAF |
| `modules/secrets` | Secrets Manager containers with no values, and the workload and refresh-token KMS keys |
| `modules/observability` | Log groups, alarms, the alert topic and the budget (alerts, not a cap) |
| `modules/delivery` | The workload permissions boundary and the operator's identity-binding policy. The GitHub delivery identities are the bootstrap root's |
| `policy/` | The repository's independent policy checks, its IAM policy evaluator and their tests (standard library only) |
| `scripts/static-checks.sh` | Everything the verification gate runs for this tree |
| `runbooks/` | The human bootstrap and staging-delivery procedures |

## Checking it

```bash
bash infra/terraform/scripts/static-checks.sh     # or ./scripts/verify-repository.sh
```

It needs exactly the pinned Terraform and Python 3.11, and it fails rather than skips without
them. It removes every AWS credential from its environment, disables instance metadata, runs the
policy checks — including the proof that every Terraform test mocks every provider — then `fmt
-check`, and for all three roots `init -backend=false -lockfile=readonly`, `validate` and `terraform
test`. It makes no AWS API call; `init` downloads the pinned provider from the Terraform Registry
if a root does not already hold it.

## Rules the checks enforce

- One provider, `hashicorp/aws` 6.64.0; one Terraform, 1.15.8; the lock files are read-only.
- Separate roots and state keys, the S3 backend with `use_lockfile`, no workspaces, no DynamoDB.
- `allowed_account_ids` and a caller-identity postcondition on every root.
- No `*.tf.json` configuration, Terraform override file or directory, plugin mirror or CLI configuration
  anywhere under `infra/`.
- No provisioner, PostgreSQL provider, `random_password`, secret version, IAM user or access key,
  Cognito Identity Pool, group or user, ALB authentication, WAF on the ALB or CloudFront.
- No `dynamic` block (the nested blocks it generates are invisible to these checks), no provider
  configuration inside a module, and no module source that does not resolve — from the calling file's own
  directory, as Terraform resolves it — to `infra/terraform/modules/<module>`.
- The canonical artifact registry is declared, never derived: the bootstrap root's release ARNs and
  release-key conditions name `artifact_registry_account_id` and `artifact_registry_region`, never its own
  account or region, and refuse a registry declared outside the account and region where it creates the
  publisher and the release key.
- No valued `tfvars`, state, plan or crash log in the repository; example files hold no values.
- Tests: HCL `.tftest.hcl` files only (a `.tftest.json` is refused), in a root's `tests/`,
  `mock_provider` for every provider configuration, `command = plan`.
- ECS: no public IP, no ECS Exec, circuit-breaker rollback, images by digest only, every revision kept
  (`skip_destroy`), one credential boundary per task, nothing plannable before `runtime_contract_reviewed`.
- RDS: private, encrypted, `rds.force_ssl = 1`, Single-AZ, seven-day backups, deletion protection,
  final snapshot, RDS-managed master secret, an explicit 16.x minor.
- Ingress from a CIDR only through the validated reviewer allow-list, on 80 and 443.
- Delivery identities: all in the bootstrap root; exact OIDC audience and subject; distinct plan, apply and
  artifact-publish roles, each under its own boundary and holding exactly one literal inline policy — any
  other inline policy, managed or exclusive attachment, `managed_policy_arns`, `inline_policy`, policy held
  in a local or built by `for_each`, or attachment to a role not proven to be declared beside it is refused;
  no delivery policy grants every action, a secret value, a parameter or decryption beyond the three
  bootstrap keys, and each boundary alone refuses a secret or parameter read a side door could grant; no plan-history or
  retention bypass for either staging role; saved plans created only as new objects, and only by the plan
  role. Only the bootstrap root declares or owns a delivery identity; any other root or module declares only
  its allow-listed workload roles (the compute module's `execution` and `task`), judged by effective
  `name`/`name_prefix` resolved through locals, interpolation, variables and module values rather than the
  resource label; a name not proven clear of `-github-plan`, `-github-apply` and `-artifact-publish` fails
  closed, as does any additional, unresolved or indirectly attached policy on a delivery identity.
- No `import` block anywhere under `infra/terraform`: adopting an existing AWS identity or resource is a
  separate, explicitly reviewed human procedure, never part of an environment's ordinary configuration.
- The authority split (ADR 0012 decision 5): trust anchors — IAM, KMS, secret containers, the release
  registry, buckets, budget actions — are human-applied. The apply boundary admits only the staging
  service families, exact IAM reads and `iam:PassRole` on the ten workload roles to ECS tasks; the apply
  role registers but never deregisters revisions of the approved families and rolls out each service only
  with its own family and never with ECS Exec; `delivery.py` and the policy check agree on the delivery
  contract.
- Policy semantics: the apply, artifact-publish and plan policies are evaluated against representative
  requests they must and must never make — the plan role never reading a secret value — each request
  carrying the keys AWS attaches to every request, and a condition on a key no request models fails closed.
  Every policy a resource holds is read (a literal, a local, or `each.value` over a local map); one the
  checker cannot read, or of a type it does not read, is refused, never skipped. Every `NotAction` or
  `NotResource` statement is judged by what it does, so a deny of everything but a short allow-list is
  refused whatever it is called.
- Build once, promote by digest (decisions 13 and 15): one release repository, immutable without
  exceptions, untagged-only expiry, only artifact-publish pushes, no replication; publication checks its own
  attempt's gate jobs and builds once before any credential, with its provenance in its labels and its
  configuration digest from the build's own metadata (never the local image ID), and resumes rather than
  rebuilds; plan and apply never build, tag or push, resolve images by digest only, re-verify the release,
  and read the admission policy from `origin/main`; plan checks its variables' registry declaration before
  its token; no workflow a pull request or fork can start gets a token, and each protected environment
  belongs to its own workflow file, named literally — an expression or another letter case is refused.
- Workflows: triggers, permissions, environments and checkout settings read from the parsed files; the
  exact credential-job guard; no status function, `continue-on-error` or step-level `if` but the final
  cleanup, none in a preflight job, and none at all in `ci.yml`, whose jobs are publication's gates; every
  file in a private runner directory that the cleanup removes; a YAML reader that refuses what GitHub's
  parser could read differently.
- Readiness: each workflow requires only the prerequisites it depends on, so publication never waits for
  the first staging apply it precedes; `readiness.json` records exactly those prerequisites.

## What is deliberately not here

A deployable identity broker, database bootstrap or identity-binding program (M3.3c); any value
for a deployment parameter; any real reviewer CIDR; any GitHub environment, variable or secret;
any image; any evidence. State and saved plans are equally sensitive — state holds the Cognito
client secret and a plan carries the prior state — and `sensitive` outputs remove neither.
