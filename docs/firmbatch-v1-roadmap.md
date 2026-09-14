# Firmbatch v0 to v1 implementation roadmap

**Status:** Canonical implementation sequence
**Product repository:** `chamsrut/firmbatch`
**Marketing repository:** `chamsrut/firmbatch-site`
**Target architecture:** `docs/architecture/v1-target-architecture.md` — **revision D.1**, 6 September 2026
**Review register:** `docs/architecture/rev-d-decision-register.md` — the rev D review items with their D.1 resolutions, and the choices that genuinely remain
**Adopting decision:** ADR 0008; the Milestone 3.3 staging, Cognito and Terraform architecture by ADR 0011
**Confirmed code baseline:** `main` at `ae61747`, PR #10 merged; Milestones 2, 3.0, 3.1 and 3.2 complete and merged, none deployed
**Last consolidated:** 13 September 2026 (Milestone 3.3a); previously 6 September 2026 (Milestone 3.0) and 2 September 2026 at revision C, both recoverable from this file's git history

This roadmap sequences the work required to move the current Firmbatch v0 prototype toward the approved v1 target. It includes the customer account, portal, and billing work needed to make the target execution architecture usable as a product, and since revision D it sequences the **Phase 0 purchased-capacity launch** ahead of any signed-supplier, endpoint or frontier work. Revision D.1 resolved the contract and commercial rules the rev D adoption had carried open, so the slices below name the rule they implement and the authority it comes from.

Authority is deliberately separated:

- `docs/STATE.md` says what the code does now.
- `docs/architecture/v1-target-architecture.md` says what v1 must become. Its §17 invariants are the acceptance criteria carried into every milestone.
- This file says in what order to build and prove it.
- `docs/architecture/rev-d-decision-register.md` says which rules revision D.1 settled, from which authority, and which implementation choices are still open and who owns each.
- `docs/architecture/v0-to-v1-migration-audit.md` is the code-cited retain/harden/replace/delete matrix (Milestone 1).

There is no timeline encoded here. A milestone is complete only when its entire gate passes with repository evidence. Everything from Milestone 3.3c onward is **PLANNED** (M3.0–M3.3a are merged, M3.3a as documentation; M3.3b is statically tested scaffolding on its branch, unmerged and deployed nowhere), including anything the target describes as "built but dark" — that phrase is a required future release state, not a claim about today's repository.

Selecting this sequence or accepting a document authorizes nothing: cloud purchases, deployment, customer invitations, supplier contact and settlement payments remain human-owned actions under `AGENTS.md`. The business companions (settlement canon, plan v3.4, roadmap r2_4, the price register, the customer brief, the definitions register, the demand map, the operator's equation paper, the RFQs) inform this sequence; their figures are planning inputs at their capture dates, not configuration.

## Vocabulary: phases and milestones

- **Milestones M0–M8** are the engineering sequence in this file.
- **Business Phase 0** is the purchased-capacity launch track: first paying jobs on spot capacity Firmbatch buys, with explicit spend controls and measurements.
- **Phase P** is the signed-supplier extension: operator capacity agent, nominated classes in production, two-sided settlement statements.
- **Endpoint extension** follows a signed endpoint supplier.
- **Phase B** is the frontier and multi-GPU lane and firm-tier activation.
- **Business Gates** run 0 → 1 → 3 → 2 (plan v3.4 §5): census; qualification on bought capacity; paying customers; the supplier signature, triggered by the second paying customer.

"Milestone 0" and "Phase 0" are different things.

## Product surfaces

### Public marketing site

- Repository: `chamsrut/firmbatch-site`
- Domain: `firmbatch.com`
- Purpose: explanation, trust, documentation, and conversion.
- Primary actions point to signup and login in the customer application (proposed production hostname `app.firmbatch.com`, a Milestone 8 decision).
- It contains no authenticated product or billing management.

### Customer product application

- Product repository: `chamsrut/firmbatch`
- Suggested location: `apps/customer-web`
- Proposed production domain: `app.firmbatch.com` — a Milestone 8 decision. Milestone 3.3 establishes only the staging browser origin, `https://staging.app.firmbatch.com` (ADR 0011 decision 3).
- Purpose: identity, workspaces, credentials, evaluation, jobs, quotes, monitoring, results, billing and invoices.
- It calls the native Firmbatch API for authorization and metadata — **same-origin**, under `/v1/*` on its own host, never through a second browser origin (ADR 0010 decision 1; ADR 0011 decision 3). The browser and SDK move payload bytes directly to and from the object store through **authorized presigned URLs**; the application holds no raw storage credential, no database access, and no direct provider or worker control. (This corrects the earlier "never accesses S3 directly" wording, which was overbroad: presigned object access is the design.)

### Product API

- Proposed production domain: `api.firmbatch.com` — a Milestone 8 decision, like every production public hostname.
- Used by the Python SDK, CLI, and customer automation. If a separate production API hostname is introduced, it serves non-browser clients or reviewed edge routing; the customer portal always reaches the API same-origin, and no pair of browser and API hostnames is an accepted browser architecture (ADR 0011 amends ADR 0002 decision 5 on this point).
- Customer payload bytes move directly between the customer and the object store through presigned URLs.

### Internal and supplier surfaces

Customer accounts never grant access to provider credentials, capacity offers, raw supplier information, pool identities, bridge budgets, operator settlement, internal routing controls, certification administration, provider reconciliation, or execution infrastructure. Those capabilities require separate identities, permissions, and interfaces (target §17 invariant 11; ADR 0003). A customer's `provider_policy` is a constraint the customer states, not an internal capacity console; in v1 it governs execution placement only, not the payload plane (target §5.4, invariant 13). The internal **qualification** service tier (target §5.5) is never customer-visible.

The **operator capacity agent** is separate operator-side software, built in Phase P when a supplier signs. It is never a customer-portal feature.

## Implementation-language boundary

- Python remains the control-plane language: one image, three roles.
- The execution worker is a signed, digest-pinned OCI image. Python plus vLLM is acceptable.
- The operator capacity agent is a static Rust or Go binary. Select exactly one in a focused design ADR when Phase P is commissioned — not as a prerequisite for Phase 0 or Milestone 3.
- Firmbatch-authored C++ is not required for v1. Upstream CUDA/C++ dependencies inside the inference image do not change that boundary. Revisions D and D.1 add no new native requirement.
- TypeScript is the default recommendation for the customer web application.

Hosting: AWS continues to host the control plane and the initial S3 payload plane. GPU execution is multi-cloud; the target's starting preference is Google Cloud, followed by Azure and AWS, and Verda as qualified. Provider prices, SKUs, regions, quotas, notice periods and cost examples in the target and the price register require fresh verification before use; they are not configuration and not a spending approval.

## Roadmap at a glance

| Milestone | Deliverable | Customer-visible outcome / completion gate |
| --- | --- | --- |
| M0–M2 | **Complete.** Canonical plan; v0 audit; the shared PostgreSQL foundation, merged through PR #7 at `4511f7d` | Not reopened because revision D changes supply |
| M3 | Accounts, membership-bound identity, customer portal, protected AWS staging | Real signup, login, settings and credentials; the first hosted, protected visual review |
| M4 | Commercial rules, evaluation allowance, billing, bridge budget and price model | Sandbox billing; immutable quotes; auto-accept consent semantics; no paid admission yet |
| M5 | Native job contract, payload path, evaluation and paid flows | Submit, upload, status and download contracts; no live paid admission on placeholder throughput |
| M6 | Purchased execution, qualification tier and Gate 1 measurement, three ledgers, cost-aware admission, four VM drivers, dark contract paths | Capped, authorized qualification and evaluation jobs, then working paid flex execution |
| M7 | Both customer journeys integrated in staging | Free evaluation with report, and paid flex to invoice, demonstrated end to end |
| M8 | Production release and Phase 0 qualification | Controlled Phase 0 launch on measured, authorized capacity |
| Phase P | Supplier-triggered agent, residual routing, production operator settlement | Shared supply replaces eligible purchased work |
| Endpoint extension | Signed endpoint supplier | Per-request endpoint adapter with token meters as evidence; never Gate 2 proof |
| Phase B | Certified multi-GPU and frontier lane; firm activation | Later capabilities pass their own capacity, price and recovery gates |

M4 and M5 build and test contracts against explicit fixtures. Real paying admission stays off until M6 provides measured certification, cost inputs and purchase enforcement. A complete live paid M5 workflow is not a prerequisite for starting M6.

## Milestone 0 — establish the canonical product plan — **complete**

Converted the target into `docs/architecture/v1-target-architecture.md` (then revision C), added this roadmap and `docs/architecture/v1-capability-baseline.md`, marked `docs/firmbatch-pilot-roadmap.md` superseded, recorded authority and language boundaries in ADR 0002, and aligned `README.md`, `docs/STATE.md` and `docs/tasks/current.md`. Documentation only.

## Milestone 1 — audit v0 against the target — **complete, merged at `6b4f341`**

`docs/architecture/v0-to-v1-migration-audit.md` accounts for every v0 product module with a retain, harden, replace or delete decision, code citations, destination, required proof and migration order. ADR 0003 records the build-beside-and-retire strategy. No v0 result is pilot-ready customer proof; the local chaos run is diagnostic evidence about durability under process kill, nothing more.

## Milestone 2 — shared product foundation — **complete, merged through PR #7 at `4511f7d`**

Built beside frozen v0 under ADR 0003, in four slices:

| Slice | Merged | Delivered |
| --- | --- | --- |
| M2.1 PostgreSQL and tenant-isolation spine | `712b51a` (PR #4) | Configuration boundary, Alembic migrations into a dedicated schema, tenants and workspaces, forced row-level security, separated roles with a verified runtime principal, disposable-cluster attestation. ADR 0004 |
| M2.2 Idempotent mutations and transactional outbox | `b028f21` (PR #5) | Tenant-scoped idempotency records and append-only outbox, one committed effect and one linked event. ADR 0005 |
| M2.3 Authenticated context, authorization, audit, secrets | `dca2d49` (PR #6) | Tenant context resolved from a credential the runtime cannot forge; closed permission catalogue; immutable audit; secrets and configuration boundaries. ADR 0006 |
| M2.4 Persisted lifecycle state machines | `4511f7d` (PR #7, implementation `d91e4f2`) | Versioned, sealed lifecycle graphs; compare-and-swap transitions writing every artifact or none; protected provenance; a dedicated `NOLOGIN` lifecycle writer. ADR 0007 |

The completion gate — cross-tenant reads and writes fail closed in automated tests, and duplicate mutations produce one contractual effect — was met by M2.1 and M2.2, re-established by M2.3 on a mechanism a compromised runtime cannot drive, and the milestone's declared scope was closed by M2.4. The post-merge verification transcript reported 14 gates passed with 97 required files; the last detailed local foundation-suite count was 1,746 collected, 1,745 passed, 1 skipped. Those are reported test results at that commit, not deployment evidence: **Milestone 2 is implemented and tested, not deployed, and not VERIFIED LIVE**. `docs/STATE.md` has the property-to-test maps and every correction pass.

Milestone 2 is **not reopened** by revision D or D.1. Later domain work extends the foundation through new migrations; merged migrations `0001`–`0004` are history. Its completion is not proof of S3 access isolation, billable job contracts, cloud launch caps, supplier settlement, production secret integration or customer launch readiness — each has its own later gate.

## Milestone 3 — accounts, membership-bound identity, customer portal, protected staging

### M3.0 — revision D.1 documentation adoption and review register — **complete, merged at `116b5ee` (PR #8)**

A bounded documentation task following completed M2, not another foundation implementation:

1. Record M2 merged at `4511f7d` / PR #7 in `docs/STATE.md` and `docs/tasks/current.md`; preserve correction history and evidence classifications.
2. Adopt this revised roadmap and integrate revision D.1 into the canonical target, keeping verbatim source snapshots of D.1 (current) and D (historical reviewed input) and a review register that records each rev D review item with its D.1 resolution and source authority; choose no contract term the authorities do not settle, and invent no value they leave to configuration.
3. Preserve target §17 and its eleven existing invariants; append the purchased-capacity invariant and the provider-policy scope as D.1 states them, without weakening isolation or customer/operator separation.
4. Add ADR 0008 for Phase 0 purchased capacity, staged delivery and phase triggers, without rewriting historical ADRs.
5. Replace the stale active "GUC blocker" prose below with the remaining membership and issuance requirement, linking the M2.3 closure and retaining its adversarial tests.
6. Read the business companions supplied with D.1 and hash-reference them in the source manifest; treat their figures as planning inputs, never as configuration or authorization.

**Gate:** one active implementation sequence; correct M2 status; traceable revision D and D.1 changes; every review item resolved with its source or listed as a genuinely remaining choice with an owner; no code change and no historical migration edit; `./scripts/verify-repository.sh` passes.

### M3.1 — identity, workspace membership and credential issuance — **complete, merged at `87159d5` (PR #9)**

Implemented at `f92ecb9` and merged at `87159d5` (PR #9); ADR 0009 records the design and `docs/STATE.md` what it proves. Not deployed and not VERIFIED LIVE. The slice as it was specified:

Implement signup, login, email verification, credential recovery, browser sessions, logout and revocation. Add membership creation, invitation and removal, roles, workspace creation, rename, selection and lifecycle. Build the **trusted issuance path** from a verified identity and an active membership to the protected M2.3 database context, so that the credential-issuing authority is separate from the runtime and bound to membership. Browser sessions and scoped API credentials are **distinct credential types**: neither is accepted at the other's authentication boundary, and neither is converted or redeemed into the other. A verified browser session may explicitly authorize an audited API-credential create, rotate or revoke operation, only after active membership and the requested scopes are rechecked; that operation issues a new credential rather than exchanging a token. An account-level session exists before any workspace does, so a verified account can create its first workspace; the session binds to a workspace only through active membership. Creation, one-time display, rotation, revocation and last-use and audit records are customer-accessible.

Design the customer UI alongside this slice; it may be built in M3.2.

**Gate:** two unrelated tenants and a removed or non-member user cannot obtain or reuse unauthorized workspace access through the UI, the API, the credential issuer or the database. Every existing runtime-context, scope, replay and lifecycle-provenance protection continues to pass. `AUTH-MEMBERSHIP-BOUND-IDENTITY` below is met.

### `AUTH-MEMBERSHIP-BOUND-IDENTITY` — blocks customer-facing availability

**This task blocks customer-facing production launch.** Nothing in Milestones 4 to 8 may be served to a real customer until it is complete.

**What is already closed, and stays closed.** The earlier roadmap tracked `AUTH-BOUND-TENANT-CONTEXT`: M2.1's runtime role could call `set_config('app.tenant_id', <any uuid>, true)` and row-level security would evaluate against whatever tenant it was told. **Milestone 2.3 closed the database half of that gap** (ADR 0006): tenant context is now acquired only by presenting a credential to a `SECURITY DEFINER` function that writes a protected context row no runtime role can read, write or clear; `app.tenant_id` is read by nothing. Completion cases 1 to 4 of the old task — arbitrary context, a leaked runtime credential, SQL injection reaching arbitrary statements, and replay or forgery of a capability — are met and tested adversarially against real PostgreSQL 16 (`control_plane/tests/test_authenticated_context.py`, `test_authorization.py`, `test_ownership_boundary.py` and the migration policy tests). Those tests are **retained**; this milestone extends them and does not rebuild the mechanism.

**What remains.** Today a credential *is* the membership: a binding names one tenant and the database will not issue a context for any other. That is sufficient while credentials are provisioned out of band and there are no user accounts. It stops being sufficient the moment a person can sign in and choose a workspace, because something then has to decide which workspaces that person may choose from — and nothing does yet. An authenticated customer identity must be **proven to be an active member of the selected workspace and tenant** before a browser session or an account credential is issued for it, and the runtime must not hold the authority to mint one for an arbitrary workspace.

**Completion gate.** Adversarial tests, against a real PostgreSQL 16 server, each of which must fail closed:

1. A verified account without membership in a workspace may retain its account-level browser session, including the ability to create its first workspace, but cannot bind that session to the unauthorized workspace or obtain any credential scoped to it, by any route the API exposes.
2. Revoking a membership stops the identity acting in that workspace, on the same linearisation terms the credential path already states.
3. An invitation accepted for one tenant grants nothing in another.
4. Browser sessions and API credentials are distinct credential types and are never accepted at one another's authentication boundary or directly converted or redeemed into one another. A verified browser session may explicitly authorize an audited API-credential create, rotate or revoke operation only after active membership and the requested scopes are rechecked; that operation issues a new credential and is not a token exchange.

Until every one of those passes, this task is open and customer-facing deployment is blocked.

### M3.2 — customer application and evaluation-oriented onboarding — **complete, merged through PR #10 at `ae61747`**

Implemented at `ce097cb` and merged at `ae61747` (PR #10, status commit `59d82a7`); ADR 0010 records the design and `docs/STATE.md` what it proves. Implemented, tested and independently reviewed; not deployed and not VERIFIED LIVE. The slice as it was specified:

Build the authenticated layout, account, workspace, team and permission settings, and credential management. Create clear navigation for Evaluation, Jobs, Results and Billing. Evaluation may be visibly unavailable until M5–M6; do not simulate a completed job or an invoice as a working backend feature. Capture the customer's desired policy, profile and preferences for later use without claiming a quote or an execution. Design the first journey around trying the 1,000-request evaluation and then converting to paid flex. Draft the consent and subprocessor text so that it states `provider_policy`'s v1 scope exactly — execution placement only; the payload plane is S3; a customer who excludes Amazon altogether cannot be served — as the target requires.

**Gate:** the journeys through accounts and settings work, with honest empty states for later features. Supplier capacity, pool identities, bridge budgets and operator settlement have no customer administrative route.

### M3.3 — protected AWS staging — explicitly pulled forward from Milestone 8, in four bounded slices (ADR 0011)

Deploy a minimal customer frontend, API and RDS PostgreSQL staging environment through repeatable infrastructure and delivery configuration, on **one customer origin**, `https://staging.app.firmbatch.com`. The earlier proposal of a second host, `staging.api.firmbatch.com`, is **superseded**: the M3.2 `__Host-` cookie contract cannot span two hosts, so the browser reaches the API same-origin under `/v1/*` and the identity broker under `/auth/*` (ADR 0010 decision 1; ADR 0011 decision 3). Use synthetic and test accounts only.

Before exposing even this authenticated staging environment, implement its necessary subset of M8 controls: TLS, network isolation, real secrets delivery, separated runtime, migration and issuer credentials, safe metadata-only operational logging, migrations as an explicit step, backups and a restore procedure, session, cookie, CSRF and origin protections, and access restriction. These are pulled-forward staging requirements, not permission to treat M8's deferred controls as solved.

Qualify M2.4's dedicated `NOLOGIN` lifecycle writer and the migration and role installation on managed RDS permissions. Prove that its ownership, membership and `FORCE` row-level-security guarantees survive deployment; local PostgreSQL success alone is insufficient. Preserve writable-primary routing for authenticated transactions; read replicas remain a later qualification (M8).

**Cognito authenticates; Firmbatch authorizes.** One Cognito User Pool per environment behind a Firmbatch identity broker: a confidential app client, authorization-code grant with PKCE, invite-only users with password plus required TOTP, tokens exchanged and validated server-side, every callback ending in a clean `303` redirect, an `(issuer, subject)` identity mapping bound explicitly by a manually invoked `identity-binding` one-off task and never by email, and the browser holding only the opaque Firmbatch session credential — renamed `__Host-fb_session` — and the CSRF secret, plus a short-lived `Lax` transaction handle during login that is not a session. No Identity Pools, no ALB `authenticate-cognito`, no Cognito groups for roles, no JWT at the core API. In AWS mode password authentication, recovery and verification email are Cognito's, and the portal signs out through `/auth/logout`; the local M3.1 paths, `/v1/account/logout` included, remain for development and test. ADR 0011 decisions 4 and 5; the topology in `docs/architecture/m3-3-aws-staging-topology.md`.

**Deployment is planned, not authorized.** A reviewable infrastructure plan, a current cost estimate and explicit deployment authorization precede creating any resource. No GPU driver is enabled by this preview. The slices:

#### M3.3a — AWS, Cognito and Terraform architecture adoption — **complete, merged through PR #11 at `86d4195`**

Documentation only, on `docs/milestone-3-3-aws-terraform-architecture` from `main` at `ae61747`: ADR 0011, the topology document, target §14.1, the register's AWS row, and the status reconciliation recording M3.2's merge. No AWS resource, no Terraform, no application code, no migration, no CI change, no evidence.

**Gate:** the decisions above are recorded with their deferrals and deployment parameters; no active recommendation names a second browser API origin; source snapshots and migrations `0001`–`0006` unchanged; `./scripts/verify-repository.sh` passes.

#### M3.3b — Terraform foundation, task scaffolding, container-build foundation and delivery structure — **implemented and statically tested on `feat/milestone-3-3b-terraform-foundation`; not merged; nothing planned, applied, pushed or deployed**

ADR 0012 records the implementation decisions and their refinements of ADR 0011; `docs/tasks/current.md` records the gate's status.

**Scaffolding only.** `infra/terraform/` with the bootstrap root, the artifacts root, the eight modules and the staging root (separate roots and state keys, no workspaces; a KMS-encrypted, versioned state bucket with the native S3 lockfile; a separate KMS-encrypted plan bucket with versioning, Object Lock governance retention, content-addressed plan keys, and lifecycle expiry of current and noncurrent plan versions and of delete markers, none of which ever applies to state; pinned versions and a committed `.terraform.lock.hcl`; provider aliases for `eu-central-1` and `us-east-1`; account-ID enforcement; Git excludes for state, plans, valued `tfvars`, crash logs and override files). ECS task-definition and service scaffolding for the two services and the three one-off tasks (`migrate`, `bootstrap`, `identity-binding`), parameterized by the verified release reference (by digest), command and secret reference, with the operator's run permission limited to the `identity-binding` task definition and its own roles. The container-build foundation. Build once, promote by digest (ADR 0012 decisions 13 and 15): a human-applied canonical release registry with immutable tags, a separate `artifact-publish` environment and role that alone publishes — resumably, never overwriting — one image per approved commit with a write-once, versioned release record freezing the approval and the exact publish attempt, and plan and apply that each re-verify and promote only that digest under a committed admission policy, with apply bound to a deployment authorization naming one plan and one release. The authority split (ADR 0012 decision 5): trust anchors are human-applied; workload rollout runs through the saved-plan pipeline inside an ECS delivery contract, revisions retained for rollback. The delivery structure: the pull-request static checks — `fmt -check`, `init -backend=false`, `validate`, lint and policy, `terraform test` with mocks; the manually dispatched publish, plan and apply workflows; the `main`-only `artifact-publish`, `staging-plan` and `staging-apply` environments; distinct plan, apply and artifact-publish IAM roles, created with the OIDC provider by the human-applied bootstrap root, whose OIDC trust names the exact repository and environment, the apply role under a permissions boundary that admits no IAM change. The reviewer CIDR allow-list validation, as Terraform variable validation plus a separately tested policy check. Workflow files, `CODEOWNERS` and a verification gate are protected-file changes needing explicit approval.

**Gate:** static and local validation passes; the container-build foundation builds from the pinned locks and passes every existing gate; and each of these **required acceptance tests** passes, and fails when its property is absent:

- **Environments.** `staging-plan`, `staging-apply` and — since ADR 0012 decision 13 added it as a third environment — `artifact-publish` each permit deployments from `main` only, require reviewers, prevent self-review where GitHub supports it, and hold no environment secret containing a permanent AWS credential.
- **Workflows.** The plan and apply workflows are manually dispatched from the default branch. They refuse any `github.ref` other than `refs/heads/main`, verify that the selected source commit is reachable from and currently approved on protected `main`, are covered by `CODEOWNERS` and branch protection, and cannot run from a fork or a pull-request context.
- **Roles.** Each OIDC trust policy names the exact repository and environment. The plan and apply roles are distinct, the apply role has a permissions boundary, and it cannot be assumed through `staging-plan`.
- **Plan bucket.** The plan role can create new plan objects but cannot overwrite an approved object version, change or bypass retention, read any saved plan or its versions, or apply infrastructure. Neither role can bypass retention or list versions; the apply role can read a plan version under the environment's prefix only by a version ID it already holds — ADR 0012 decision 7's accepted limitation, amending ADR 0011 decision 9.3. Lifecycle rules expire current and noncurrent plan versions and delete markers after the approved retention, and never touch state.
- **Apply verification.** Given the deployment tuple — the plan object's key, version ID and expected SHA-256 and the release's commit, image and record version ID and SHA-256 (ADR 0012 decision 15) — and one unexpired deployment authorization on `main` naming exactly that tuple, the apply job fails closed on a checksum, source-commit, provider-lock-digest or Terraform-version mismatch, on a missing version, on a plan older than the allowed age, on a source commit no longer reachable from or approved on `main`, and on a release that no longer verifies — including under a security stop or exception change merged to `main` after the plan. It never generates a new plan.
- **No exposure.** No binary plan or full plan rendering reaches a GitHub artifact or log.
- **Allow-list.** The validation and the policy check each reject an empty list, a non-canonical or invalid CIDR, an IPv4 prefix shorter than `/24` or an IPv6 prefix shorter than `/64`, more than the maximum number of entries, an unspecified, multicast, loopback, link-local or otherwise non-routable range, a duplicate or overlapping entry, and a list exceeding the maximum address-space allowance.

And **no cloud `plan`, no `apply`, no credential in the repository, no resource created, and no deployable identity-broker, database-bootstrap or identity-binding implementation**. **M3.3b cannot be applied, and its task definitions are not operational, until the M3.3c programs, dependencies and image have passed review.**

#### M3.3c — the programs, dependencies and tests the scaffolding runs

Everything executable: the production database bootstrap command; the identity-binding command and its dedicated database boundary — a login role with no table privilege and no role membership, holding `EXECUTE` on exactly one narrowly scoped `SECURITY DEFINER` binding function, with a separate `NOLOGIN` owner where review finds an owner boundary is needed; the Cognito identity-broker entry point; the Cognito authorization, callback, refresh, revocation and logout clients; JWT and JWKS verification; the KMS encryption and decryption integration; the staging environment configuration mode; the `__Host-fb_session` rename, with every affected test and setting; the AWS-mode route changes — `/v1/account/logout` and the local authentication routes disabled for the browser, `/auth/logout` in their place; every callback outcome ending in a `303` to a fixed clean URL with the handle cleared, `Cache-Control: no-store` and `Referrer-Policy: no-referrer`; metadata-safe access and unhandled-error logging; migration `0008` (renumbered: `0007` is M3.3b's incidental password-hash correction, ADR 0012 decision 14) with the protected `auth_identity` relation, the authenticator-only entry points for federated session opening and logout, and the identity-binding function and role; the portal's `/auth/*` adaptation; the web/API entry point serving the compiled portal; the production runtime dependencies — **the HTTP client, the JOSE/JWT library and the AWS SDK, each selected, pinned and reviewed here** — with `requirements-v1.txt`, `requirements-v1-dev.txt` and both lock files; the runtime-import gate's module inventory; the container entry points and tests for every one-off and long-running command; the browser-evidence tooling M3.3d runs — the Playwright configuration with trace, video, screenshot and storage-state persistence disabled for authentication tests, the allow-listed summary collector, and the evidence scanner. Adversarial tests against real PostgreSQL 16 for every refusal ADR 0011 decisions 4 and 5 name. Extending `REQUIRED_FILES`, the runtime-import inventory, and the test bootstrap's role set as the verification script and skill describe it needs the human's explicit approval, as at M3.1 and M3.2.

**Gate:** every M3.1 and M3.2 protection passes unchanged with a federated session; an unbound identity and an email match are refused; the identity-binding login role executes its one function and nothing else, and arbitrary SQL as that role can open no session, issue no credential, change no membership, assume no role and write no table; binding is idempotent for an identical request, refuses a conflicting one, and commits its success or refusal audit event atomically; the evidence scanner fails on a planted secret, cookie, bearer value, query-string URL or email address; no token, verifier or callback parameter reaches a response body, log or row; local authentication remains for development and test; **nothing deployed**.

#### M3.3d — reviewed plan, cost estimate, explicit authorization, apply, migrations, identity binding, browser tests, restore drill, evidence

The deployment parameters confirmed (account, region, domains, CIDRs including the reviewer allow-list and its address-space allowance, SES identity, alert recipient, budget threshold, RDS sizing and minor, the saved-plan lifetime and the three delivery environments' reviewers (`artifact-publish`, `staging-plan`, `staging-apply`), the declared canonical artifact registry (account, region, repository, record bucket), the staging identities to bind, the retention of AWS-managed identity logs); a trusted plan stored only as a content-addressed, Object-Locked object in the plan bucket and reviewed in a separately authenticated operator session, with GitHub showing only its sanitized summary; a current cost estimate; **the human's explicit deployment authorization, recorded before `apply`**; a release published once by `artifact-publish` and verified by digest; an apply the human starts with the deployment tuple — that object's key, version ID and expected SHA-256 and the release's commit, image and record version ID and SHA-256 — which the apply job verifies independently, together with the recorded authorization and the release under the admission policy `main` holds at apply; bootstrap, migrations; controlled synthetic staging identities bound through the `identity-binding` task using only the dedicated binding credential; the RDS qualification of migrations `0001`–`0008`, `FORCE` RLS, function ownership, the `NOLOGIN` writer, grants, downgrade and reconciliation and clean teardown; synthetic identity and tenant-isolation tests; a Playwright journey against the real URL whose retained output is only an allow-listed, secret-scanned summary and any separately approved screenshot of a clean route showing synthetic data; the backup restore drill; the resource and secret inventory; the inventory and review of AWS-managed records that can hold identity data (CloudTrail, Cognito logging and export, SES records, the Cognito WAF's logs and their destinations); post-deployment cost and alarm checks; evidence under `docs/evidence/m3/`, never including the binary plan, a full plan rendering or any raw browser artifact.

**Gate:** the real customer portal can be opened and reviewed on AWS with verified test identities, exercising isolation, without exposing secrets or internal operations — with the evidence captured. **Only this slice may create a resource, and only after its authorization.**

**M3.3a, M3.3b and M3.3c are not deployment authorization.** The customer can see the real hosted portal only after M3.3d.

### Milestone 3 completion gate

A new customer can register, verify identity, create a workspace, invite a member, and create a scoped API credential without gaining access to supplier or internal operations; `AUTH-MEMBERSHIP-BOUND-IDENTITY` passes; and the protected staging preview exists under the controls above — which is M3.3d's gate, so **Milestone 3 closes only after M3.3d**. Registering and authenticating a customer is not the same property as being unable to serve them somebody else's data, and this milestone is not complete until both hold.

## Supply-readiness preparation alongside M3–M5

Prepare the driver contracts, the measurement schema and the Gate 1 protocol (target §8.3: one instance per pool per zone for seven days on the smallest single-GPU SKU, running a qualification job, with the pass and fail thresholds D.1 states and the plan owns), the qualification workloads and profile allow-list, the price-register loader for `gpu_price_register_1.xlsx` (source, currency, billing unit, captured date and freshness per row), region and subprocessor eligibility, and the credential and quota checklist. This preparatory work runs alongside portal work; it launches no instance.

Before any billable probe, specify its account, region, SKU, duration, maximum loss and cleanup, obtain the required human authorization, and use the qualification tier in M6. A "capacity probe" that allocates a real VM is a purchase, not a read-only check.

Business Gate 1 measures purchased-pool viability with the protocol above; a single passing run is not "Gate 1 passed" without the plan's evidence requirements, and the plan may revise the thresholds. Business Gate 2 proves supplier participation and terms; neither purchased spot nor an endpoint arrangement is evidence that Gate 2 passed.

## Milestone 4 — commercial, evaluation and budget foundations

### M4.1 — commercial decisions and immutable records

Define immutable, versioned quotes and accepted contracts; record explicit and automatic acceptance. `auto_accept_below` is required v1 scope, with D.1's rule (target §5.4): the quote is always issued and stored; it is auto-accepted when its total excluding VAT and payment fees, in the tenant's billing currency (USD unless the contract says otherwise), is less than or equal to the amount; the consent is the JobSpec field, bound to the submitting credential and recorded on the quote, lapsing at quote expiry and never carried to another job. Automatic acceptance removes a round trip, not the quote or the acceptance record. **Remaining choice, owned here:** the quote validity duration — every authority requires one, none states it.

Define the dormant firm contract at the same time: the hedge budget, region- and provider-eligible hedge terms, the missed-deadline credit policy and a customer-named deadline in the 24-to-under-72-hour range. Build and test these terms behind a release flag; do not postpone their schema to Phase B.

Define evaluation with D.1's rules (target §5.3): free; one per tenant per corpus, with a second on the same corpus needing a recorded Firmbatch approval; at most 1,000 requests; per-evaluation caps on input tokens, output tokens and purchased spend in its envelope; the report always produced, including for zero accepted units and for failed, partial and cancelled jobs, carrying pass rate, each failure's rejecting rule, cost per thousand accepted units at list, and the escalation rate `x` as roadmap r2_4 D4 defines it; no self-conversion to paid. **Remaining choice, owned here:** the numeric values of the per-evaluation token and spend caps, recorded on the evaluation policy. Do not invent a reset period; the rule is per tenant per corpus with recorded approval.

### M4.2 — billing and collection

Build billing identity and address, payment-method setup, Firmbatch invoices and credits, and collection state. Provider-signed webhooks plus reconciliation are authoritative for provider payment state; Firmbatch remains authoritative for its contracts, accepted units and invoices. Browser redirects and success pages are never payment evidence. Implement signed webhook verification, idempotent immutable webhook ingestion, reconciliation and backfill, and an internal payment-state projection.

Build the billing UI in the product, using sandbox transactions at this stage. Evaluation must not require a charge or create an invoice. Paid billing consumes real accepted-unit records only after M6–M7. Billing belongs only in `app.firmbatch.com`.

### M4.3 — bridge budget and price model

Specify and persist job and tenant envelopes plus the platform bridge envelope with D.1's accounting (target §8.1): monthly, total and supplier-account caps enforced as **gross accrued spend** — every launch reserves its envelope's maximum hours at the frozen rate, usage records replace the reservation, provider invoices reconcile monthly — and **reported** net of customer billings invoiced in the same calendar month, before credits, refunds and taxes, in USD at the ECB reference rate of the day; evaluation and qualification spend gross; a launch that would breach any cap refused at admission; numeric retirement (no new purchase for a job once a shared placement is eligible; none after twelve months from the first purchase without a recorded re-authorisation); weekly reporting against the caps and monthly at reconciliation. Reservations and reversals must be race-safe and must account for uncertain, pending and orphaned provider operations rather than freeing budget on a timeout.

**The cap values are not this milestone's to invent.** Plan v3.4 carries $3–5k a month net of billings and $10k in total as a planning range; the exact configured monthly cap, total cap and per-supplier sub-caps are spend and deployment decisions a human records on the envelope before the first purchase. Model them as configuration with an audit trail; ship no default that could be mistaken for the decision.

Define the versioned price register, loaded from `gpu_price_register_1.xlsx` and its successors, with source key, currency, billing unit, captured date and freshness per row, including transfer, storage and retry costs. Never hard-code the target's illustrative prices and never accept an untrusted workbook edit as live spending authority.

**Gate:** sandbox billing is replay-safe; duplicate and out-of-order webhooks cannot double-charge, regress payment state or alter an accepted quote; evaluation has no quote and no invoice; contracts freeze consent and terms; budget reservations and reversals are race-safe in tests and refuse a breaching launch. Paid quotes and admission remain disabled until actual cost and throughput inputs are qualified in M6.

## Milestone 5 — job contract, evaluation and payload path

Implement declarative, versioned acceptance policies in the customer brief's rule types (JSON schema; required values and regular expressions; grounding; bounds and label sets; a customer-hosted validator endpoint), returning the rejecting rule with every rejected output; and the native endpoints for draft creation, submit, explicit quote acceptance, status, cancel and results. Register the job lifecycle machine (target §5.1) with the job tables — M2.4 registered none.

- Align job-state spelling with revision D's `uploaded`; M2.4's generic kernel needs no rewrite.
- Freeze inputs and manifests, model and profile, policy version, absolute deadline, region policy, provider exclusions, commercial consent and `movable_to_shared` at the appropriate contractual event.
- `provider_policy` may exclude classes or named subprocessors; it never selects a placement. In v1 it governs **execution placement only** — first placement, every retry, every move to shared capacity and every hedge — and not the payload plane; a customer who excludes Amazon altogether is refused at submission with the reason, and the consent text says so (target §5.4, invariant 13).
- Use presigned direct uploads and downloads; payload bytes do not enter the API, the scheduler, PostgreSQL or logs.
- Paid flex follows `quoted -> admitted`, including a recorded automatic acceptance when eligible.
- Evaluation bypasses quoting and invoicing and admits under the evaluation and bridge caps. Specify cancellation, partial and failure paths and expiry as well as the happy path; the report is produced in every terminal state. **Remaining choice, owned here:** the corpus identity rule for "one free evaluation per tenant per corpus" and the recorded-approval path, which must not become a cross-tenant oracle.
- Carry `service_tier = qualification` in the contract as an internal, never customer-submittable tier (target §5.5); its admission path is M6.1's.
- Provide the Python SDK and CLI and OpenAI-style per-request JSONL bodies through the same native API.
- Persist firm-tier fields behind a flag: a customer-named deadline of at least 24 hours and under 72. It is not an enabled fixed-24-hour promise.

**Gate:** isolated customers can prepare and submit contractual metadata, validate policies and use scoped object access in staging, without payload bytes entering the metadata plane. Fixture-based tests exercise quotes and job lifecycles. Actual execution and real paid-quote readiness depend on M6; do not mark that integration complete early.

## Milestone 6 — measured purchased execution and accounting

Deliver bounded slices, not one combined multi-cloud and operator rewrite. The M6 domain ADR records the attempt, execution, purchase, measurement and window schemas and the frozen-terms-versus-measured-outcomes split (target §10.1).

### M6.1 — execution and spend enforcement with a local or fake provider

Implement immutable shards and attempts and the attempt-to-execution binding, monotonic lease fencing, short-lived worker registration, the signed worker image, structural validation, per-request canonicalization and the three distinct execution, delivery-valid and accepted-unit ledgers. Provider credentials belong to the controller only. One execution never serves two tenants concurrently. SQS only wakes consumers of the authoritative outbox. Register the window-offer, attempt, lease and execution machines with their tables.

Integrate M4 reservations with admission and launch, including evaluation, qualification, supplier sub-caps, simultaneous and cumulative launches, kill-by and orphan reconciliation. Implement the **qualification tier** (target §5.5): an internal tenant, an allow-list of profiles, admission through the same caps and credentials as any purchase, per-run human authorisation recorded on the job, and output confined to the certification registry and the pool's measurement records; it must not become a public bypass of certification or paid admission. No speculative duplication: a replacement follows confirmed loss or the documented deadline-forecast exception within its budget.

**Gate:** local failures, duplicate messages, concurrent reservations and ambiguous launch responses cannot corrupt results or grant extra spend. Qualification admission is reviewed before live use. The retained v0 diagnostic assets (local provider, echo engine, fault harness) operate through target interfaces.

### M6.2 — first purchased driver and Gate 1 measurement

Implement Google Cloud spot first, per the stated Phase 0 preference and subject to current price, SKU, region and quota eligibility. The launch contract remains quote or capacity, launch, observe, cancel, usage and reconcile. Run only **specifically authorized, admitted qualification jobs** under the existing spend controls and the caps a human has configured, on the allow-listed test profile, to collect certification data; they do not claim that an unmeasured profile is certified for customers.

Run the Gate 1 protocol as the target states it (§8.3): one instance per pool per zone for seven days on the smallest single-GPU SKU, running a qualification job; pass on a median lifetime above sixty minutes, three or fewer preemptions a day per instance, and grants on at least four attempts in five; fail on a median within a factor of two of `W_min` or grants failing more often than one in five, and move to the next supplier. Record actual allocation requests, grants and stockouts, time to grant, lifetime and reclaim observations, notice seen, hour-of-day distribution, warm and cold loading, measured prefill and decode throughput, delivery efficiency and lost tail, and measure the 27–35B candidates beside the 8B profile so the model band is a measurement. Preserve sample counts, observation windows and censored live instances when deriving P10/P50/P90; missing measurements are not zero failure.

Write the immutable launch snapshot (account, region and zone, SKU, rate) and append usage and rate intervals from the provider's records and invoice adjustments at reconciliation; never recompute a past cost from today's register or a single final price (target §8.2).

**Gate:** bounded, authorized work produces attributable cost and measurements, cleans up capacity, and supports a reviewed decision to certify a pool and profile or move to the next candidate under the protocol. A single passing run is not "Gate 1 passed" without the plan's evidence requirements.

### M6.3 — measured pricing, admission and routing

Use the certification key (model and image digests, runtime version, precision, GPU class and count, parallelism, provider, region) with measured throughput and `W_min` inputs. Phase 0 execution remains `gpu_count = 1`; schema capacity to identify a node is not multi-GPU support.

Size shards from measured work, not a token-throughput placeholder. Admit purchased work under the approved workload-shape and margin rule, provider and region policy and every spend cap. Route eligible purchased candidates by expected delivery-valid work per cost, including egress, loading and retries. Apply policy, certification and deadline constraints before preferring shared supply where it exists. Persist the decision, the cost and measurement versions and the reason; units in cost-versus-value comparisons must match. Report gross costs, net bridge use and remaining reservations without double counting, weekly and monthly.

**Gate:** real evaluation and paid flex admission are enabled only for qualified profiles with approved price and budget inputs. Replay, preemption and cost changes cannot reprice an accepted contract.

### M6.4 — remaining VM drivers and cross-provider recovery

Add Azure, AWS and Verda as separate reviewed slices behind the same execution contract, implementing their actual allocation, reclaim, termination and usage behavior rather than renamed calls. Measure each enabled pool under the same Gate 1 protocol and enforce least-privilege credentials per cloud and account. Exercise recovery with the same permitted workload and the immutable-output and canonicalization rules.

All four VM drivers remain Phase 0 target scope; the first Google Cloud path is an incremental qualification slice, not a reduction of that scope. Record unavailable pools as unavailable and gate them off. No endpoint adapter is required until an endpoint supplier signs.

### M6.5 — accounting and future contract paths, tested but dark, to the canon

Implement and test dormant firm admission: completion-coverage and probability requirements, eligible regional and provider hedge availability, atomic capped hedge reservations and the agreed credit-policy calculation. Without adequate evidence or capacity it fails closed; synthetic admission tests are not a production release qualification. Keep the flag off throughout Phase 0; Phase B qualifies and activates this built path.

Keep provider consumption, delivery-valid work and customer acceptance separate. Purchased supply is cloud cost of goods: no operator revenue-share, floor or cancellation payable is generated. Keep `usage_basis` explicit; no invented GPU-hours for request-based supply.

Build and test nomination window offers, acceptance, revocation, frozen terms, nominated classes and operator statement calculations behind flags, **to the settlement canon as D.1 renders it**: the twelve-cause enum with `operator_platform_failure`; revocation by `operator_reclaim`, `operator_blackout` and an operator-asserted `security_stop` only; the `max` once per operator-month across all supply classes with per-class grouping as a contract parameter and never pooled across operators; the 90-day true-up with floors and credits paid on the statement and share legs on collection at the frozen `s_u`, nothing clawed back; frozen terms and measured outcomes kept apart on every attempt. Phase 0 includes these dormant paths; deferring the agent does not delete this test scope. Per-contract parameters — the grouping, `f_c` — are fixtures here and are set when a supplier signs.

**Gate:** the full Phase 0 execution target and its tests pass; generic M2 security remains intact; real purchased costs reconcile; forced duplicate delivery, stale workers, worker loss and ambiguous provider operations cannot corrupt canonical results, retroactively change commercial terms or exceed admitted spend; dormant supplier paths cannot create production obligations.

## Milestone 7 — evaluation and paying customer journeys

Exercise two full journeys on the hosted staging product:

```text
1. Visit firmbatch.com -> sign up -> verify -> create workspace -> policy and profile
   -> capped evaluation -> execution -> results and report
   (no quote, no charge, no invoice; cost still consumes the evaluation and bridge budgets)

2. Sign up -> workspace and billing -> policy and input -> paid flex submission
   -> explicit or automatic quote acceptance -> execution and progress -> canonical results
   -> accepted-unit usage -> invoice -> provider-confirmed payment state
```

Test zero accepted units, partial jobs, cancellation, expired quotes, duplicate submit and webhooks, revoked access and provider loss. Use polling initially unless a measured need justifies a realtime channel. Support recurring customer automation through the SDK, API and auto-accept; neither revision D nor D.1 authorizes a built-in scheduling product by itself.

**Gate:** both journeys complete with traceable contractual and accounting records and without internal operator intervention except for an explicitly retained commercial or operational decision. Synthetic and sandbox outcomes stay distinguishable from real measured execution and payment observations.

## Milestone 8 — production release and Phase 0 qualification

Promote the staged deployment pattern into an isolated production environment: customer frontend, `firmbatch.com` and the production public hostnames, which are decided here (proposed `app.firmbatch.com` and `api.firmbatch.com`; whatever is chosen, the customer portal reaches the API same-origin, and any separate API hostname serves non-browser clients or reviewed edge routing), ALB and TLS, three ECS service roles, RDS PostgreSQL, S3 and KMS, SQS and the transactional outbox, Secrets Manager, CloudWatch and OpenTelemetry, explicit migrations, restore and runbooks, metadata-only logging, and read-replica routing if qualified. Deploy only after cost, access and region decisions and operational approval. M3.3 staging is a subset of this deliverable; M8 is not the first time the portal becomes visible.

Prove: account and workspace isolation; production-specific identity, role and secret tests; payment-webhook idempotency and recovery; quote immutability; spend-envelope, reservation and purchase reconciliation; worker interruption and cross-provider recovery; canonical-result correctness; complete accepted-unit reconciliation; no payload or credential leakage; the observed customer journeys in production. Collect reproducible evidence under the repository's evidence rules and track VERIFIED LIVE at the capability, commit and environment level.

### Release boundary

Enable evaluation and the 72-hour flex tier under approved caps on qualified single-GPU profiles. Keep firm, nominated supply and production operator settlement dark until their separate gates. A Phase 0 launch is not proof of the residual-supply business thesis or of Business Gate 2.

## Later extensions, each with an explicit trigger

### Phase P — supplier agreement, or an equivalent operator capacity endpoint

After a supplier signs approved terms and provides capacity visibility, activate the tested nomination and settlement paths. Build the outbound-only signed-capacity agent in the supplier cluster where required, selecting Rust or Go by ADR; it handles scheduler availability, offers and reclaim, never payloads or customer sessions. An equivalent operator-owned capacity endpoint may supply the interface without the agent; its authentication and contract proof still need qualification.

Implement production supplier statements, confirmed Structure A and B terms with that contract's grouping parameter and quoted `f_c`, cause evidence and cross-operator routing. Migrate only eligible remaining work marked `movable_to_shared`; retain existing attempts, commercial snapshots, tenant, region and provider policy and every budget. Retire purchased usage job by job, never by overwriting history. Agent completion is not a prerequisite for the purchased launch.

### Endpoint extension — endpoint supplier agreement

Implement Lyceum or another agreed endpoint only after terms, drop signals and usage evidence exist. One execution per attempt and per-request accounting from the supplier's usage records, with raw token meters retained as evidence and the contract's pricing unit — a share of NCR or a per-token price, whichever the supplier quoted — frozen on the attempt (target §12.2), must preserve the three ledgers. Endpoint participation does not pass Business Gate 2 and cannot claim nomination premiums.

### Phase B — frontier and multi-GPU lane, and firm release

Certify GPU count and topology, tensor and expert parallelism, model, image and profile, region, load and cache economics and recovery before activating nodes or whole-node windows. Single-card certification does not transfer to nodes. Activate firm deadlines in the 24-to-under-72-hour range only after the same workload survives measured loss and cross-provider recovery with eligible hedge capacity, admission coverage and the agreed credit policy. These can share a business phase without pretending that every firm job requires multi-GPU execution.

## Remaining decisions

The rev D review items D1–D10 are resolved by revision D.1 against the settlement canon, plan v3.4 and roadmap r2_4; the register records each resolution and its source. What remains are choices the authorities leave open on purpose — none is a discrepancy between sources, none is invented here, and none blocks Milestone 3:

| Decision | Nature | Owner and slice |
| --- | --- | --- |
| Exact configured bridge monthly cap, total cap and per-supplier sub-caps (plan range $3–5k a month net of invoiced billings, $10k total) | Spend and deployment decision recorded on the envelope by a human | Before any M6.2 purchase; modelled in M4.3 |
| Numeric per-evaluation caps on input tokens, output tokens and purchased spend | Evaluation-policy configuration | M4.1 |
| Quote validity duration | Commercial configuration | M4.1 |
| Corpus identity rule and recorded-approval path for "one evaluation per tenant per corpus" | Implementation choice | M5 |
| Qualification tenant and profile allow-list; per-run authorisation | Operational configuration; human per run | M6.1, M6.2 |
| Model band default (8B vs 27–35B) | Measurement outcome of the evaluation harness and Gate 1 | M6.2 |
| Gate 1 threshold revisions | Owned by the business plan; a revision is a plan change | Plan |
| Settlement grouping parameter and `f_c` per contract | Set when a supplier signs | Phase P |
| Endpoint pricing unit per supplier | Quoted by the endpoint supplier | Endpoint extension |
| AWS staging deployment parameters — the account ID; the region (recommended `eu-central-1`, unconfirmed); the domains (hosted zone, customer origin, Cognito custom domain with its callback and logout URLs); the CIDRs (VPC and subnets, and the reviewer allow-list for ports 443 and 80 with its maximum address-space allowance, reviewed explicitly and never committed); the SES identity; the alert recipient; the budget threshold; RDS sizing and the PostgreSQL 16 minor; the saved-plan lifetime (24 hours recommended) and the reviewers of `staging-plan` and `staging-apply`; the staging identities to bind; the retention of AWS-managed logs that can hold identity data — the current cost estimate and explicit deployment authorization. The architecture itself is decided (ADR 0011) | Human deployment decision | M3.3d, confirmed immediately before plan and apply |
| Rust vs Go for the operator agent | Focused ADR | Phase P |

## Explicitly deferred

Do not put these on the v1 critical path:

- OpenAI Batch translation adapter.
- Embeddings, training, and multimodal inference.
- Customer-supplied validator containers.
- Calibrated forecasting and statistical quality certification.
- Fragment harvesting and yield pricing.
- Marketplace functionality.
- Polished enterprise billing or highly granular enterprise RBAC.
- A built-in job scheduling product (recurring automation goes through the SDK, API and auto-accept).

## Product-level integration acceptance path

```text
Create account
-> verify identity
-> create workspace
-> [evaluation]  define acceptance policy -> submit capped evaluation -> download results and report
-> [paid flex]   configure billing -> define acceptance policy -> submit job
                 -> accept quote (explicitly, or automatically under auto_accept_below)
                 -> monitor execution -> download canonical results
                 -> inspect accepted-unit accounting -> receive invoice -> observe payment status
```

These are the integration tests connecting identity, commercial terms, execution, accepted-unit accounting, and collection.

**Immediate order:** M3.0 documentation adoption (merged) → M3.1 identity, membership and issuance (merged) → M3.2 customer application (merged) → M3.3a architecture adoption (merged, PR #11) → **M3.3b Terraform and task scaffolding (implemented and statically tested on its branch)** → M3.3c the broker, bootstrap and binding programs, identity mapping and dependencies → M3.3d authorized deployment and evidence, with supply preparation alongside. No remaining decision requires discarding completed work, and no slice before M3.3d creates a resource.
