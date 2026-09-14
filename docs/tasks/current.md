# Current tasks

Active work and open questions. Updated at the end of each task, alongside `docs/STATE.md`.

Last updated: 2026-09-14, on `feat/milestone-3-3b-terraform-foundation` from `main` at
`86d4195`, with **Milestone 3.3b — the Terraform, container and delivery foundation — as the
current slice, implemented, statically tested and independently reviewed at implementation commit
`cff27c8`, every actionable review finding closed, and awaiting pull-request CI and merge** (ADR 0012).
Its final local canonical run was **16 gates passed, 0 failed**, with **257** required files; the image has
not been built locally because Docker is unavailable, and the first actual container build remains a required
PR CI condition. **Milestone 3.3a is merged** through PR #11 at `86d4195` (documentation only, ADR 0011). No
Terraform plan or apply has run, no AWS or GitHub resource has been created, no image has been pushed, and no
deployment or evidence artifact exists for Milestone 3.3; nothing is VERIFIED LIVE. **Milestone 3.3 remains
active; M3.3c is next.**
**Milestone 3.2 is merged** through PR #10 at `ae61747` (implementation commit `ce097cb`,
status commit `59d82a7`), implemented, tested and independently reviewed with every
actionable finding closed. **Milestone 3.1 is merged** at `87159d5` (PR #9, implementation
commit `f92ecb9`, status commit `c841f77`) — after two review correction passes closing ten
findings and two gaps (Codex) and six findings (GPT-5.6 Sol), and a third, clean independent
review (GPT-5.6 Sol at xhigh effort) that verified all six of those findings as fixed and
raised no actionable regression. M3.2 is not deployed and not VERIFIED LIVE, and no evidence
artifact has been captured; **no AWS deployment or deployment evidence exists**. Milestone 1 merged at
`6b4f341`; M2.1 merged at `712b51a` (implementation commit `521870b`, plus the bootstrap
trust-boundary correction `78eae1d`); M2.2 merged at `b028f21` (implementation commit
`d362717`); M2.3 merged at `dca2d49` (implementation commit `89fbdd9`), after a fourth
security correction pass; **M2.4 merged at `4511f7d` (PR #7, implementation commit
`d91e4f2`)**, after three review correction passes closing six, five and two findings.

**Milestone 2 status: complete and merged.** Its four slices — **M2.1, M2.2, M2.3 and
M2.4 — are implemented, tested and merged to `main`**. Milestone 2 is **not deployed and
not VERIFIED LIVE**, and **no evidence artifact has been captured** for any of the four.
The verification recorded at implementation commit `d91e4f2` was **14 gates passed, 0
failed**, with **97** required files in the layout gate and the PostgreSQL foundation suite
at **1,746 collected — 1,745 passed, 1 skipped**; the supplied post-merge transcript
reported the same 14 gates and 97 files. Those figures are HISTORICAL to those commits; the
run at the current commit is recorded under "Active — Milestone 3" below. Migration `0003`
remains unchanged, and the operator capacity agent remains separate operator-side software,
now scheduled for Phase P.

**Architecture revision D.1 is adopted (Milestone 3.0, merged at `116b5ee`, PR #8, documentation only).**
`docs/firmbatch-v1-roadmap.md` carries the revised M3–M8 sequence and the Phase 0 / P / B
triggers; the target is at revision D.1 with verbatim source snapshots (D.1 current, D
historical) and a review register that records each rev D review item's D.1 resolution;
ADR 0008 records the decision; M3.0 merged at `116b5ee` (PR #8). **Milestone 3.1 —
membership-bound identity, sessions and credential issuance — is implemented, tested and
independently reviewed at `f92ecb9` and merged at `87159d5` (PR #9); it is not deployed and
not VERIFIED LIVE** (ADR 0009).

---

## Active — Milestone 3, accounts, identity, portal and protected staging

Milestones 0, 1 and 2 are complete. Milestone 3 is the active milestone, under the
revision D.1 roadmap. Its slices: **M3.0** documentation adoption (merged, PR #8), **M3.1**
identity, membership and credential issuance (merged, PR #9), **M3.2** the customer
application (merged, PR #10 at `ae61747`), and **M3.3** the protected AWS staging preview in
four slices under ADR 0011 — **M3.3a** the AWS, Cognito and Terraform architecture adoption
(documentation only, merged through PR #11 at `86d4195`), **M3.3b** Terraform and task
scaffolding with the delivery structure (**this branch**, implemented, statically tested and
independently reviewed at `cff27c8`, awaiting pull-request CI and merge, ADR 0012), **M3.3c** every program the scaffolding runs — database bootstrap,
identity binding, the broker — with the identity mapping, dependencies and tests,
**M3.3d** the authorized deployment with evidence. Nothing before M3.3d is deployment
authorization, and the customer can see the real hosted portal only after M3.3d.

### M3.0 — revision D.1 documentation adoption — **merged at `116b5ee` (PR #8)**

Documentation only. The branch first adopted revision D; D.1 superseded it the same day,
before anything was committed, and the staged documentation was corrected in place.
Reviewed on 2026-09-07 with one clarification applied afterwards: the
`AUTH-MEMBERSHIP-BOUND-IDENTITY` completion gate's non-member case and its
session-versus-API-credential case, in `docs/firmbatch-v1-roadmap.md` and this file, with
the M3.1 deliverable text aligned to the same distinction. No architecture decision, source
snapshot or register entry changed.
Changed: `docs/firmbatch-v1-roadmap.md` (revised M3–M8 at D.1, phase triggers, M2 closure,
the stale `AUTH-BOUND-TENANT-CONTEXT` GUC-blocker prose replaced by
`AUTH-MEMBERSHIP-BOUND-IDENTITY` with the M2.3 closure linked, each later slice naming the
D.1 rule it implements, a remaining-decisions table);
`docs/architecture/v1-target-architecture.md` (revision D.1 integrated under the existing
section numbers, §17 invariants 1–11 byte-identical to `main`, 12 and 13 appended as D.1
states them, new §5.5 qualification tier, no open-rule markers, §18 revision record);
`docs/architecture/rev-d-decision-register.md` (converted into the D-review/D.1-resolution
register); `docs/architecture/sources/` (D.1 snapshot added beside the historical D
snapshot, manifest with every reviewed authority's hash and stored-versus-referenced
status); `docs/adr/0008-phase-0-purchased-capacity-and-staged-delivery.md` (new, at D.1);
this file, `docs/STATE.md` and one status line in `README.md`. No code, migration, test,
dependency, evidence, deployment or provider change. No protected agent, policy, workflow
or verification file was touched.

**The rev D review items, resolved by D.1** (register D1–D10, each with its source): the
cancellation cause is `operator_platform_failure`; an operator-asserted `security_stop`
revokes an accepted window; grouping is once per operator-month with per-class as a
contract parameter and the 90-day true-up follows Amendment 4; endpoint execution is
accounted per request with raw token meters retained and the pricing unit frozen; the
bridge follows plan v3.4's $3–5k monthly and $10k total planning range, enforced as gross
accrued spend with reservations, usage replacement and invoice reconciliation, without
turning the range into a fixed production cap; Gate 1 runs the seven-day per-pool,
per-zone protocol with D.1's thresholds; evaluation is one per tenant per corpus unless an
approval is recorded, at most 1,000 requests, capped, with a report in every terminal
state; `auto_accept_below` compares the stored quote total excluding VAT and payment fees
in the billing currency, less than or equal, with consent bound to the submitting
credential and lapsing at quote expiry; `provider_policy` governs execution placement only
in v1, so a customer excluding Amazon altogether cannot be served; purchase launch terms
are immutable and usage and invoice adjustments append-only; frozen terms and measured
outcomes stay separate; and the internal qualification tier exists. The companions
(settlement canon, plan v3.4, roadmap r2_4, price register, customer brief, definitions,
demand map, operator equation, both RFQs) were read in full and are hash-referenced in the
manifest. **What genuinely remains** is listed with owners in the register's §3 and the
roadmap's "Remaining decisions": the configured bridge caps and sub-caps, the numeric
evaluation caps, the quote expiry, the corpus identity rule, the qualification allow-list,
per-contract settlement parameters, supplier-quoted rates, the model band as a
measurement, the staging authorisation and the agent language. No value for any of them
was invented. None blocks M3.1 or M3.2.

**Gate for this slice:** one active roadmap; correct M2 status; traceable rev D and D.1 changes;
explicit open rules; no code or migration diff; `git diff --check` clean;
`./scripts/verify-repository.sh` passing. **Result on 2026-09-06**, at `4511f7d`, run once
with the rev D changes uncommitted and again after the correction to rev D.1 with the
documentation changes staged, against the attested local PostgreSQL 16.15 cluster:
`git diff --check` and `git diff --cached --check` clean; **14 gates passed, 0 failed**
both times, 97 required files; the passing output prints no suite counts, so the
historical 1,746 / 1,745 / 1 figure is not restated as this run's. It is a run, not an
evidence artifact, and is recorded in `docs/STATE.md` "Asserted — artifact pending".

Order for the human, from here (item 1 done at the 2026-09-07 review):

1. Review ADR 0008, the review register, and the target's §17 (invariants 1–11 must read
   exactly as before; 12 and 13 are the additions, now stated as D.1 states them).
2. Check both snapshot hashes: `sha256sum docs/architecture/sources/*.md` must match
   `docs/architecture/sources/README.md` (D.1 `44e29e07…853f3`, D `ea09cb2e…a2a2c`).
3. Commit the reviewed branch, push, open the pull request, merge after checks pass. No
   evidence artifact is claimed by this change.
4. Before M4.1, M4.3 and M6.2 respectively: decide and record the evaluation caps and quote
   expiry, the configured bridge caps and sub-caps, and the qualification allow-list and
   per-run authorisations. These are the human's decisions; the documents leave them open on
   purpose.

### M3.1 — identity, workspace membership and credential issuance — **implemented, tested and reviewed at `f92ecb9`; merged at `87159d5` (PR #9)**

Implemented on `feat/milestone-3-1-identity-membership` from `main` at `116b5ee`,
**committed at `f92ecb9`** and merged to `main` at `87159d5` (PR #9, status commit
`c841f77`). Nothing is deployed, no provider is contacted and no cloud spend is incurred.
Migrations `0001`–`0004` are unchanged; migration `0005` carries the M3.1 implementation.
ADR 0009 records the design; `docs/STATE.md` "CURRENT — Milestone 3.1" records what it is
and what it proves.

**Where it stands:** implemented, tested, independently reviewed and **merged** (PR #9). It
is **not deployed and not VERIFIED LIVE** — no deployment exists
and no evidence artifact has been captured, so the standard's VERIFIED LIVE label does not
apply however green the suite is.

**Changed files** (commit `f92ecb9`, 47 files). New: migration
`0005_identity_and_membership.py`; `db/accounts.py`, `db/membership.py`, `db/credentials.py`;
`security/passwords.py`, `security/permissions.py`; `api/__init__.py`, `api/app.py`,
`api/settings.py`, `api/email.py`, `api/__main__.py`; `tests/identity_helpers.py` and nine
test modules (`test_identity_accounts`, `test_identity_membership`,
`test_identity_issuance`, `test_identity_protection`, `test_identity_migration`,
`test_identity_permissions`, `test_identity_concurrency`,
`test_identity_security_corrections`, `test_api_http`);
`docs/adr/0009-membership-bound-identity-sessions-and-credential-issuance.md`.
Modified: `config.py`, `db/models.py`, `db/roles.py`, `security/authorization.py`,
`security/secrets.py`, `testing/bootstrap.py`; `tests/conftest.py`,
`tests/test_migrations.py`, `tests/test_audit_events.py`,
`tests/test_protected_auth_state.py`, `tests/test_configuration.py`,
`tests/test_admin_escalation.py`, `tests/test_bootstrap_safety.py`,
`tests/test_bootstrap_lifecycle.py`; `requirements-v1.txt`, `requirements-v1-dev.txt`,
`requirements-v1-lock.txt`, `requirements-v1-dev-lock.txt`; `.env.example`; `README.md`;
`docs/STATE.md`; this file.

**Three protected files changed, each with the human's explicit approval and none of them a
gate**: `scripts/verify-repository.sh` (twenty-two more `REQUIRED_FILES` entries, taking the
layout manifest to 119, and a header comment describing the five-role test lifecycle — no
gate added, removed, reordered or weakened), `scripts/check-runtime-imports.py`
(`RUNTIME_MODULES` extended to name every new production module) and
`.agents/skills/verify/SKILL.md` (the same five-role lifecycle documented). No other
protected file was touched: no policy, agent, workflow or instruction file changed.

**Verification at implementation commit `f92ecb9` (2026-09-09, attested local PostgreSQL
16.15):** `./scripts/verify-repository.sh` passed **all 14 gates**, the layout gate over
**119** required files; the latest full foundation-suite result is **2,038 collected — 2,037
passed, 1 environment-dependent REPLICATION skip**; the final independent review's focused
verification of the same state passed **202 tests with no failures**; `git diff --check`
clean; no disposable `firmbatch_test_*` database, role or session left behind. No evidence
artifact captured, so nothing here is VERIFIED LIVE.

*Earlier runs, kept as history:* the working tree on 2026-09-07 was **1,962 collected —
1,961 passed, 1 skipped**, with the eight then-new modules collecting 182; the second
correction pass took the suite to the 2,038 recorded above.

**Gate mapping** — `AUTH-MEMBERSHIP-BOUND-IDENTITY`:

| Gate case | Test |
| --- | --- |
| 1. A verified non-member keeps its account session, can create its first workspace, and cannot bind the unauthorized workspace or obtain a credential scoped to it by any route | `test_identity_membership.py::test_gate_case_1_a_non_member_keeps_its_account_session_and_cannot_bind_the_workspace` |
| 2. Revoking a membership stops the identity acting in the workspace on the credential path's linearisation terms | `test_identity_membership.py::test_gate_case_2_revoking_a_membership_stops_the_identity_acting_in_the_workspace` |
| 3. An invitation accepted for one tenant grants nothing in another | `test_identity_membership.py::test_gate_case_3_an_invitation_accepted_for_one_tenant_grants_nothing_in_another` |
| 4. Sessions and API credentials are distinct types, never accepted at each other's boundary, never converted; issuance is an audited operation after membership and scopes are rechecked | `test_identity_issuance.py::test_gate_case_4_a_session_issues_a_credential_that_authenticates_as_its_membership_and_nothing_else` |

**Deferred, by design:** the UI (M3.2); password change while signed in (M3.2); deployment,
TLS, the separated issuer credential, real secrets delivery and managed-PostgreSQL
qualification (M3.3, not authorized); a real email provider, rate limiting and metrics (M8,
subset pulled forward by M3.3); account deletion and archival; account-level events in a
tenant audit trail; more than one workspace per tenant.

**Codex security correction pass — ten findings and two gaps, all closed.** A Codex diff
scan of the uncommitted M3.1 tree raised ten findings and two review gaps; all are corrected
on the branch with regression tests. The design-level change is a distinct **authenticator**
database login role holding the pre-authentication functions (login, session opening,
recovery) that the ordinary application role no longer holds, so raw SQL as the runtime role
cannot mint a victim session or reset a victim password. Its grant is the least that reaches
them — plus `auth_tenant_id` and the `auth_context` its invoker-rights body calls — with no
relation privilege and no role membership, asserted from the catalogue. (The second review
pass below moved the three mailbox-verification functions onto the same role, so the current
inventory is eight pre-authentication functions and ten in total.) Account recovery evicts
credentials
through a durable `accounts.security_epoch` checked at bearer authentication; issuance and
rotation share the workspace serializer and re-read membership under it; owner-only mutations
re-read the caller's role under the lock; Argon2 runs behind a bounded admission gate;
request bodies are capped while streaming; and an owner-run `purge_expired_unverified_accounts`
reclaims stale pending accounts. ADR 0009 "Security corrections" and `docs/STATE.md` record
the detail. The populated-data downgrade that failed with error 23514 is reconciled and
tested end to end, and `scripts/check-runtime-imports.py` `RUNTIME_MODULES` now names every
new M3.1 production module.

**Second review correction pass (GPT-5.6 Sol) — six findings, all closed.** All are
corrected on the branch with regression tests, and `0005` — then unmerged, merged since at
`87159d5` — was corrected in place; `0001`–`0004` are untouched. In one line each: the login challenge now carries the
account's password version (`security_epoch`) and `open_browser_session` compares it under a
lock that conflicts with recovery, closing the recovery/login race in both transaction
orderings; the three mailbox-verification functions moved onto the authenticator, because
minting *and* consuming a verification secret is the whole of the mailbox-control proof;
`firmbatch.workspace_membership_authority` is now the one membership revalidation and every
workspace-mode operation — rename, invitation revoke and manager listing, credential revoke,
credential listing and history — goes through it after taking its serialisation lock and
before any replay lookup, disclosure or mutation; the HTTP boundary authenticates before it
interprets a body, so absent, malformed, unknown and mixed credentials are one `401` whatever
the body is; `_refused_bind` carries the request's CSRF proof into its retry, so an incorrect
token is `401` and never `workspace_required`, and `keep_current` is a strict JSON Boolean;
and revoked and expired are one credential state, computed by PostgreSQL, with an expired
credential refused rotation rather than rotated into an unlimited successor. ADR 0009 "Second
review correction pass" and `docs/STATE.md` record the detail and the reasoning.

**Final independent verification (GPT-5.6 Sol, xhigh) — clean, nothing outstanding.** A third
independent review over the implementation at `f92ecb9` **verified all six outstanding
findings as fixed**: the recovery/login transaction race; the mailbox-verification authority;
stale workspace membership; HTTP authentication and CSRF ordering; strict `keep_current`
Boolean parsing; and credential-expiry consistency. The additional **authenticator-role
teardown leak** — the hand-written per-run role lists in `test_bootstrap_safety.py` and
`test_bootstrap_lifecycle.py`, which predated the authenticator — is **fixed** with them. The
review raised **no actionable regression**. The focused verification passed **202 tests with
no failures**, `./scripts/verify-repository.sh` passed **all 14 gates** over **119** required
files, and the cluster was left with no disposable database, role or session. This is a clean
review and a passing suite, not evidence: M3.1 stays **not VERIFIED LIVE**.

**No protected file is awaiting an approved update.** Both inventories are extended:
`scripts/verify-repository.sh` `REQUIRED_FILES` names every M3.1 module and test (the layout
gate reports 119 required files) and `scripts/check-runtime-imports.py` `RUNTIME_MODULES`
names every new production module. The paragraph that stood here said otherwise; it predated
the approval and is corrected. A follow-up lock regeneration could move the development
test-client pin from `httpx` to `httpx2`, which Starlette 1.6 prefers.

The slice as it was proposed, for the record:

- **Accounts and verification:** signup, login, email verification, credential recovery,
  browser sessions with logout and revocation.
- **Workspace membership:** create, invite, accept, remove; roles; workspace selection and
  rename; lifecycle.
- **The issuer:** a trusted issuance path from a verified identity and an active membership
  to the protected M2.3 database context (`firmbatch.auth_bindings`), held by an authority
  the runtime cannot impersonate. Browser sessions and scoped API credentials are distinct
  credential types, never accepted at one another's authentication boundary and never
  converted or redeemed into one another; a verified session may explicitly authorize an
  audited API-credential create, rotate or revoke only after active membership and the
  requested scopes are rechecked, and that issues a new credential rather than exchanging
  a token. An account-level session exists before any workspace does, can create the
  account's first workspace, and binds to a workspace only through active membership.
  Creation, one-time display, rotation, revocation, last-use and audit records.
- **Migrations:** new domain migrations after `0004`; `0001`–`0004` untouched.
- **Gate:** `AUTH-MEMBERSHIP-BOUND-IDENTITY` (roadmap M3.1) — four adversarial tests against
  real PostgreSQL 16, each failing closed — plus every existing M2 protection passing
  unchanged. Not blocked by any open register entry.

M3.1 merged at `87159d5` (PR #9). **M3.2 merged at `ae61747` (PR #10)** — see the section
below. **M3.3 is in progress as four slices**: its AWS staging needs a reviewed
infrastructure and cost plan and explicit authorization before any resource is created
(M3.3d), and the **Cognito adoption decision** — Cognito to own customer authentication,
Firmbatch retaining its server-side browser session, CSRF, workspace authorization, RLS,
audit, consent and API credentials — is now recorded in ADR 0011 (M3.3a), before anything
is built on it. The **operator capacity agent remains
separate operator-side software** and is not part of the customer portal — it is Phase P
work, after a supplier signs, and the M3.2 portal contains no route, navigation entry,
setting or scope that would reach one.

### M3.2 — the customer-only product portal — **implemented, tested and independently reviewed at `ce097cb`; merged at `ae61747` (PR #10)**

The authenticated customer application, `portal/`: TypeScript, Vite and React, with React and
ReactDOM as its only runtime packages (`portal/package.json` is the authority), served
**same-origin with the API** behind a proxy. Committed as implementation commit `ce097cb`
and merged to `main` at `ae61747` (PR #10, status commit `59d82a7`); not deployed and not
VERIFIED LIVE.
ADR 0010 records the design and the corrections made after its four review passes
(2026-09-10 to 2026-09-12), every actionable finding of which is closed; `docs/STATE.md`
records what it proves and what it does not claim.

- **Customer journeys:** signup and email confirmation; sign-in, sign-out and recovery; the
  first workspace, for a verified account that is a member of nothing; workspace selection and
  switching, revalidated by the server on every change; workspace details and rename; team,
  roles and invitations, with the two owner-only rules stated where they bite; the customer's
  stated policy, profile and preferences, and the consent statement; API credentials — list,
  create, show once, rotate, revoke, and audit history for a role that holds `audit:read`;
  the account, its verification status, its sessions, and the signed-in password change.
- **Honest empty states:** Evaluation, Jobs, Results and Billing are in the navigation,
  marked unavailable in text rather than only by styling, and contain **no fabricated job,
  result, figure, chart, invoice or sample row**. The first journey is described around the
  free 1,000-request evaluation and conversion to paid flex, with the steps that exist today
  linked and working and the steps that do not marked as such.
- **Schema:** forward migration `0006_preferences_and_password`. `0001`–`0005` untouched,
  byte for byte. Two relations — the tenant-plane `workspace_preferences`, on which the
  application role holds `SELECT` alone, and the transaction-scoped, protected
  `identity_expected_workspace` — one trigger, and six functions: the two mutation entry
  points `state_workspace_preferences` and `acknowledge_workspace_consent` (the authorization
  and audit boundary for the relation), the expected-workspace writer
  `identity_expect_workspace`, the consent trigger function as defence in depth, and the two
  password-change entry points on the trusted-issuer boundary. It states the account-plane
  lock order (`accounts` first, then tokens, passwords, bindings, sessions) and replaces the
  bodies of `0005`'s `verify_account_email` and `complete_account_recovery` under it, and of
  `workspace_membership_authority` to compare the recorded expected workspace with the
  binding, restoring `0005`'s text verbatim for all three on downgrade.
- **API:** five new routes. `GET /v1/consent` (public), `GET`/`PUT
  /v1/workspace/preferences`, `POST /v1/workspace/preferences/consent`, and
  `POST /v1/account/password`. Both preference mutations require `workspace_id` — the
  workspace the page loaded for — and answer `409 workspace_mismatch` when it is not the
  bound workspace.
- **Independent review, 2026-09-10:** eleven findings, all corrected at the root with tests
  that fail without the correction — the stale workspace form; application-role DML,
  read-bound contexts and the trigger as boundary (one `SECURITY DEFINER` mutation boundary,
  `SELECT`-only grant); the password-change/recovery deadlock (the lock order above, real
  overlap tests, no `40P01`); logout forgotten locally only after a successful logout or after
  one safe account read confirms the session is gone, a logout `401` proving nothing on its
  own (the P2 follow-up), the sign-out then made one provider-owned operation — single-flight
  across every control, fenced to the session generation it began under, its validity read
  under a real deadline (the three remaining logout findings, 2026-09-11) — and the same
  fence then extended to every route: a lease on every request, no unfenced `forget`, a
  mutation `401` checked rather than believed, an answer to a replaced session dropped (the
  session-generation race, 2026-09-11) — and, from a clean-context review's eight findings
  (2026-09-11), the replacement barrier (a replacement session adopted synchronously from
  the response that opened it, refusals deferred while one is in flight), sequenced and
  coherent account loads, the binding-first workspace switch, the expected workspace on
  every workspace mutation (`X-Workspace-Id`, compared inside `workspace_membership_authority`
  under the workspace lock, migration `0006`) and on every workspace read's envelope, page
  request tickets and keyed single-flight reads (ADR 0010 decision 11); one-time tokens safe
  under `StrictMode`; the public
  invitation landing page;
  audit atomicity; focus after every route transition; and the dependency wording here and in
  the other three documents. `docs/STATE.md` lists them one by one.
- **Final review, 2026-09-12:** two P3 findings, both corrected. A `next=` destination that
  is a path by every syntactic rule but normalises to a protocol-relative URL
  (`/..//evil.example`, `/.//evil.example`, `/a/..//evil.example` → `//evil.example`) is now
  refused: the destination rebuilt from the parser's parts is checked again, syntactically
  and by a second parse, before it is returned, with the three cases and their variants in
  the hostile corpus and asserted through every redirect helper, the router and a rendered
  link. And every count, name, comment, docstring and file reference the review found
  inaccurate was re-derived from the migration, the route tables, the diff and the
  verification script and corrected in place — `0006` adds two relations, one trigger and
  six functions and replaces three `0005` bodies; the application role gains three
  functions; six check constraints; nineteen registered routes and twenty pages in seven
  route modules; six existing test modules changed; the identity plane has fifty-one
  functions; the fail-closed "13 passed, 2 FAILED" figure included a foundation-suite gate
  starved of its database URL in the same experiment, so the missing dependencies alone fail
  one gate of fifteen. `docs/STATE.md` "Final review corrections" lists each site.
- **Verification (2026-09-12, after the review corrections, the centralised sign-out, the
  session lease on every route, the clean-context review's eight corrections and the final
  review's two P3 corrections):** **15 gates passed, 0 failed**, 167 required files; the
  foundation suite **2,188 passed, 1 skipped** of 2,189 collected; the portal suite **392
  tests across 10 files** (327 before the redirect corpus grew), on Node 24.21.0 LTS.
  Migrations `0001`–`0005` are byte-identical to `main`. `git diff --check` clean. No
  evidence artifact captured. That code is **implementation commit `ce097cb`**; the
  canonical script re-run at `ce097cb` on 2026-09-13, with only this status update in the
  working tree, reports the same **15 gates passed, 0 failed** over 167 required files.

**Two protected files were changed, both with the human's explicit prior approval**, and both
narrowly: `scripts/verify-repository.sh` gains the customer-portal gate and forty-eight
`REQUIRED_FILES` entries (forty-seven with the milestone, and one more, approved under the
same decision, for `portal/src/lib/one-time-token.ts` with the review corrections), and `.github/workflows/ci.yml` gains `actions/setup-node@v4` pinned
to Node 24 and an `npm ci` step. No gate was removed, reordered or weakened, and the new one
fails rather than skips when its prerequisites are absent — checked, not assumed.

### M3.3a — AWS staging, Cognito and Terraform architecture adoption — **merged through PR #11 at `86d4195`, documentation only**

On `docs/milestone-3-3-aws-terraform-architecture` from `main` at `ae61747` (Milestone 3.2,
PR #10). ADR 0011 records the decisions and
`docs/architecture/m3-3-aws-staging-topology.md` draws them; `docs/STATE.md` "CURRENT —
Milestone 3.3a" lists every document changed. No AWS resource, no Terraform, no application
code, no migration, no CI or verification change, no commit, no push, no deployment and no
evidence. No protected agent, policy, workflow or verification file was touched. The two
architecture source snapshots are byte-identical to `main`.

**Decisions recorded**, one line each (ADR 0011 has the detail):

1. M3.3 is four slices — **a** architecture (this); **b** scaffolding only: Terraform modules
   and roots, ECS task-definition and service scaffolding, the container-build foundation,
   ECR and the delivery workflow structure, static Terraform verification, and no deployable
   broker, bootstrap or binding implementation; **c** every program the scaffolding runs:
   the database bootstrap command, the identity-binding command, the broker entry point, the
   Cognito authorization, callback, refresh, revocation and logout clients, JWT and JWKS
   verification, KMS integration, the staging configuration mode, the `__Host-fb_session`
   change, metadata-safe unhandled-error logging, the runtime dependencies with both
   requirement files and both lock files, the runtime-import inventory, and the entry points
   and tests for every command; **d** reviewed plan, cost estimate, explicit authorization,
   apply, migrations, identity binding, browser tests, restore drill and evidence. M3.3b
   cannot be applied and its task definitions are not operational until M3.3c's programs,
   dependencies and image pass review; M3.3c selects, pins and reviews the HTTP, JOSE/JWT and
   AWS SDK dependencies. Milestone 3 closes only after M3.3d; a–c are not deployment
   authorization.
2. A dedicated staging AWS account, enforced by Terraform; `eu-central-1` recommended and
   confirmed immediately before plan and deploy; synthetic accounts and data only; no
   production data, supplier or operator-agent credential; Budgets alerts, not a cap.
3. One customer origin, `https://staging.app.firmbatch.com`, `staging.api.` dropped; M3.3
   establishes only that staging origin, and production public hostnames stay Milestone 8's,
   with the portal always same-origin; ALB routes `/` and `/v1/*` to the web/API service and
   `/auth/*` to the identity broker; port 80 on the same allow-list as 443, redirect only;
   two ECS services and three one-off tasks (`migrate`, `bootstrap`, `identity-binding`) with
   separate task roles and secrets from one image digest; the compiled portal served from
   the web/API image; CloudFront and static S3 deferred; no long-running service holds a
   schema-owner, migration or master credential.
4. One Cognito User Pool per environment, Managed Login v2 at a custom domain (certificate
   in `us-east-1`), a confidential client with the code grant and PKCE only, exact URLs,
   `openid email`, invite-only, email usernames, verified email, password plus required
   TOTP, `PreventUserExistenceErrors`, refresh rotation, five-minute tokens, an eight-hour
   window; no Identity Pools, ALB `authenticate-cognito`, groups for roles, JWT at the core
   API or social providers; no `aws.cognito.signin.user.admin`; the browser receives no
   Cognito token; the broker's single-use state, server-side exchange, validation, JWKS and
   no-logging obligations; the authentication host under the customer origin's registrable
   domain; `__Host-fb_session` staying `Strict` and the opaque single-use `__Host-fb_oidc`
   handle `Lax` deliberately and not a session; every callback a `303` to a fixed clean URL
   after clearing the handle, with `no-store` and `no-referrer`; in AWS mode `/auth/logout`
   replaces the browser's `/v1/account/logout`, revokes, clears Cognito's cookie and ends at a
   fixed clean URL.
5. `auth_identity(provider, issuer, subject, account_id, created_at, last_seen_at)
   UNIQUE (issuer, subject)`; explicit binding only through the manually invoked
   `identity-binding` one-off task, never by email. Its only database credential is a
   dedicated identity-binding login role with no table privilege and no role membership,
   holding `EXECUTE` on one `SECURITY DEFINER` binding function, with a separate `NOLOGIN`
   owner where review needs one; the function is idempotent, refuses conflicting bindings and
   commits its success or refusal audit event atomically. The task's command is assumed
   overridable, so arbitrary code inside it still cannot issue a session or reach broader
   authority; it holds the minimum Cognito read, takes only non-secret invocation identifiers
   (an invitation's row ID, never its token; no email address), has no endpoint or service,
   cannot start the broker, and is not the operator agent; no legacy-password
   migration; local authentication for development, tests and a bounded rollback window;
   refresh tokens KMS-encrypted with a bound context, in protected state, never in the
   browser, logs or the core API.
6. ALB 443 and 80 from the same human-reviewed, never-committed reviewer allow-list,
   validated structurally and fail-closed by Terraform validation and an independently tested
   policy check (canonical CIDRs, IPv4 `/24` or narrower, IPv6 `/64` or narrower, at most 16
   entries proposed, no non-routable, duplicate or overlapping entries, a maximum
   address-space allowance, never empty), no WAF added to the ALB; no public task IPs; RDS private and reachable only from the web/API,
   broker, bootstrap, migration and identity-binding security groups;
   Cognito behind a WAF IP allow-list of the reviewed CIDRs plus, added separately, the
   broker's NAT EIP as a `/32`,
   no CAPTCHA on TOTP enrollment; HTTP redirects to HTTPS; exact host and origin validation
   in the application.
7. RDS PostgreSQL 16 (exact minor checked before deployment), Single-AZ on subnets in two
   AZs, encrypted, an explicit parameter group with `rds.force_ssl=1`, `verify-full`,
   seven-day PITR, deletion protection, final snapshot, no replica; `rds_superuser` is not a
   superuser and M3.3d qualifies migrations `0001`–`0006`, `FORCE` RLS, function ownership,
   the `NOLOGIN` writer, grants, downgrade and reconciliation and teardown; the RDS-managed
   master secret for the bootstrap task only; a one-off task writes runtime passwords into
   pre-created Secrets Manager containers so they never enter Terraform state; no
   PostgreSQL provider, `local-exec` or `remote-exec`; the Cognito client secret is the
   acknowledged state exception, so remote state and saved plans are equally and highly
   sensitive.
8. `infra/terraform/` with `bootstrap/`, eight modules (`network`, `edge`, `compute`,
   `database`, `identity`, `secrets`, `observability`, `delivery`) and
   `environments/{staging, production/README.md}`; no workspaces; separate roots and state
   keys; a KMS-encrypted, versioned state bucket with `use_lockfile = true` and no DynamoDB,
   and a separate KMS-encrypted plan bucket with Object Lock governance retention whose
   lifecycle never touches state; an allow-list policy check beside the modules;
   the Cognito WAF in `identity` and none in `edge`; the five task definitions in `compute`; pinned versions and a committed `.terraform.lock.hcl`; provider aliases for
   `eu-central-1` and `us-east-1`; state, plans, valued `tfvars`, crash logs and override
   files excluded from Git; sensitive outputs with the state and plan caveat; no static AWS
   keys.
9. GitHub Actions through OIDC. Both `staging-plan` and `staging-apply` allow only `main`,
   require reviewers, prevent self-review where supported and hold no permanent AWS
   credential. The workflows are manually dispatched from the default branch, refuse any
   `github.ref` but `refs/heads/main`, verify the source commit is reachable from and
   approved on protected `main`, are protected by `CODEOWNERS` and branch protection, and
   are disabled for forks and pull requests. Each OIDC trust names the exact repository and
   environment; the plan and apply roles are distinct; the apply role has a permissions
   boundary and cannot be assumed through `staging-plan`. Each of these is a required M3.3b
   acceptance test. Approval of planning never authorizes an apply. Saved plans live in a
   dedicated plan bucket, separate from state, with content-addressed keys, versioning and
   Object Lock governance retention; the plan role creates objects but cannot overwrite an
   approved version, remove retention or apply. The human starts apply with the reviewed
   object's key, version ID and expected SHA-256, visible in the approval request; apply
   downloads that version, recomputes the SHA-256, verifies the source commit, recomputes
   the provider-lock digest, checks the Terraform version, relies on Terraform's saved-plan
   state checks, and fails closed on any mismatch, missing version, expired plan or
   unapproved commit, never re-planning; plan-produced metadata is no authority. Retention is
   one day proposed, tied to the 24-hour recommended lifetime; lifecycle expires current and
   noncurrent plan versions and delete markers; neither role bypasses retention or reads
   arbitrary history; apply refuses a plan past the allowed age; state keeps its own
   retention. No binary plan or full rendering in a GitHub artifact or public log; GitHub
   shows only a sanitized summary; the full plan is reviewed in a separately authenticated
   operator session; pull-request static checks, trusted plan,
   approved apply and application deployment kept apart; no credential for an untrusted pull
   request; one immutable image in ECR with immutable tags and scanning, deployed by digest;
   the migration task before rollout, abort on failure; ECS circuit-breaker rollback; a
   database downgrade never automatic.
10. Explicit-retention application log groups with allow-listed metadata only (no bodies,
    query strings, headers, cookies, codes, tokens, callback parameters, email addresses, SQL
    values, object identifiers or payload); ALB access logs off; CloudTrail, Cognito logging
    and export, SES records, the Cognito WAF's logs and their destinations recognised as
    possible holders of identity data and inventoried, access-restricted, encrypted and
    retention-limited at M3.3d, never copied into application logs; credential-safe browser
    evidence — synthetic identities and content only, no raw traces, HAR files, videos,
    storage state, console or network dumps or failure screenshots from authentication
    journeys, Playwright persistence disabled, an allow-listed summary, fixed failure
    classifications and opaque correlation IDs, sanitized callback and logout assertions,
    separately approved screenshots of clean synthetic routes only, a blocking secret scan
    before commit, raw artifacts never uploaded; every M3.3d evidence item, with the plan
    recorded only as its sanitized summary and the browser journey only as its sanitized
    summary and approved images.
11. Deferred, not claimed: production deployment, CloudFront, static S3 hosting, Multi-AZ,
    replicas or RDS Proxy, autoscaling, multiple NAT gateways, production identities or
    data, real GPU execution, operator capacity agent deployment, payload presigning and
    transfer, the SQS outbox dispatcher and workers, settlement, production disaster
    recovery. The operator capacity agent remains separate operator-side software.
12. Status: M3.2 merged through PR #10 at `ae61747`; implemented, tested and reviewed, not
    deployed and not VERIFIED LIVE; Milestone 3 active; M3.3a current; the hosted portal
    visible only after M3.3d; no AWS deployment or evidence yet.

**Deployment parameters requiring human confirmation** (no value chosen): the staging
account ID; the region (`eu-central-1` recommended); the domains — the Route 53 hosted zone,
the customer origin and the Cognito custom domain (proposed `auth.staging.app.firmbatch.com`)
with its callback and logout URLs; the CIDRs — VPC and subnet ranges, and the reviewer
allow-list for ports 443 and 80 with its maximum address-space allowance, explicitly reviewed
and never committed; the SES identity; the alert recipient; the budget threshold; RDS sizing
and the exact PostgreSQL 16 minor; the saved-plan lifetime (24 hours recommended) and the
required reviewers of `staging-plan` and `staging-apply`; the staging identities to bind; the
retention of AWS-managed logs that can hold identity data; the current cost estimate,
including the Cognito feature plan Managed Login requires; and the explicit deployment
authorization, recorded before `apply`.

**Findings from reading the code, for M3.3c** (nothing changed here, because no application
code changes in this slice):

- **The session cookie has no `__Host-` prefix.** `SESSION_COOKIE_NAME` in
  `control_plane/api/settings.py` is `fb_session` in every environment. M3.3c renames it to
  `__Host-fb_session` wherever cookies are `Secure`, keeping `fb_session` only as a
  development name, and updates the configuration and every test that names it. No
  deployed-cookie migration: nothing was deployed. The comment above the constant, which
  still describes `app.` and `api.` as two hosts of one site, is corrected at the same time.
- **Both API log lines record the raw request path.** The unhandled-error line logs
  `request.url.path`. The access line is meant to log the route template, but it reads a
  matched route from the request scope that the locked Starlette 1.6.0 does not record, and
  falls back to the raw path — checked after the review corrections; today's path parameters
  are identifiers, not secrets. M3.3c replaces both with route-template or
  fixed-classification metadata, tests both, and never logs a query string or a callback
  parameter.
- **The portal signs out through `/v1/account/logout`.** In AWS mode that route is disabled
  for the browser and the portal uses `/auth/logout`; M3.3c owns the route-mode change, the
  portal adaptation and their tests.
- **`Environment` has `test` and `production` only.** M3.3c defines the staging environment
  configuration mode without weakening any production control.
- **The ordinary transaction preamble calls two identity accessors.** `db/engine.py`
  asserts through `firmbatch.auth_tenant_id()`, which reads `auth_context`, and the
  authenticator's inventory in `db/roles.py` holds both for that reason. The dedicated
  identity-binding login role holds `EXECUTE` on one function only, so the binding command's
  database path must not rely on that preamble, and M3.3c's tests prove the role's whole grant
  from the catalogue.
- The URL parser already accepts `sslmode` and `sslrootcert`, so `verify-full` is
  configuration once the RDS certificate bundle is in the image.
  `FIRMBATCH_API_SESSION_TTL_SECONDS` already accepts the eight-hour value.

**Gate for this slice:** the decisions above recorded with their deferrals and parameters;
no active recommendation names a second browser API origin (`staging.api.firmbatch.com`
survives only as superseded history in the roadmap's own M3.3 text and in ADR 0011's
amendment note), and no production pair of browser and API hostnames is presented as an
accepted browser architecture; source snapshots and migrations `0001`–`0006` byte-identical to `main`;
`git diff --check` clean; `./scripts/verify-repository.sh` passing. **Result on
2026-09-13**, at the working tree over `ae61747` with the documentation changes uncommitted,
against the attested local PostgreSQL 16 cluster: `git diff --check` clean; both snapshot
hashes equal to the manifest's, and `git diff main -- docs/architecture/sources/
control_plane/db/migrations/` empty; §17 of the target byte-identical to `main`; **15 gates
passed, 0 failed**, 167 required files; the passing output prints no suite counts, so the
M3.2 figures are not restated as this run's; no disposable `firmbatch_test_*` database or
role left behind. It is a run, not an evidence artifact, and is recorded in `docs/STATE.md`
"Asserted — artifact pending". **Re-run after the review corrections**, the same day, at the
corrected working tree before it was re-staged, against PostgreSQL 16.15 and Node 24.19.0:
`git diff --check` and `git diff --cached --check` clean; only the eight documentation files
differ from `ae61747` and nothing is untracked; both snapshots and migrations `0001`–`0006`
unchanged; §17 byte-identical to `ae61747`, the target's only hunks at §14.1 and §18;
**15 gates passed, 0 failed**, 167 required files. Wording fixes prompted by the
post-correction reviews, all in these markdown files, came after that run.
The final correction pass is verified by the same script at the finished, staged tree; its
result is reported with that change rather than written here, so that the tree the script
verified is the tree recorded.

**Independent review corrections (2026-09-13) — four P2 and eleven P3 findings, all
accepted and applied** in these eight documentation files only; no code, migration, lock
file, CI, script, source snapshot or §17 text changed. `docs/STATE.md` "M3.3a review
corrections" summarises them and ADR 0011 "Review corrections" maps each to its decision:

- P2-1 — the saved plan is an encrypted, short-lived object under `plans/`, verified at
  apply, never a GitHub artifact or public log; GitHub shows only a sanitized summary;
  operator-session review; state and plans equally sensitive; the M3.3d evidence records
  only the sanitized summary. Superseded in part by items 3 and 4 of the final correction
  pass below: a separate Object-Locked plan bucket, independent verification at apply, and
  lifecycle expiry instead of deletion.
- P2-2 — `__Host-fb_session` for M3.3c; the host-only wording corrected; the `Lax`
  `__Host-fb_oidc` handle specified.
- P2-3 — the `identity-binding` one-off task, everywhere it belongs.
- P2-4 — M3.3b scaffolding only; every program and dependency M3.3c's; no library chosen.
- P3-1 to P3-11 — RDS ingress from five security groups; no WAF added to the ALB; hostname and cookie
  semantics; AWS-mode logout; `staging-plan` and `staging-apply`; broker code in M3.3c;
  AWS-managed identity records; port 80 on the same allow-list; clean callback redirects;
  the unhandled-error logging finding; the stale M3.0 wording and the production-hostname
  language.

**Final correction pass (2026-09-13) — six architecture questions decided** in the same eight
documentation files; no code, migration, dependency, Terraform, workflow, verification script,
source snapshot or §17 text changed. `docs/STATE.md` "M3.3a final correction pass"
summarises them, and ADR 0011 "Final correction pass" maps each to its decision:

1. The identity-binding task receives a dedicated one-function binding credential, never the
   authenticator's, and its command is assumed overridable.
2. `staging-plan` and `staging-apply` are `main`-only, reviewed and protected, with manually
   dispatched, `CODEOWNERS`-protected workflows, exact OIDC trust, distinct roles and a
   permissions-bounded apply role, all as required M3.3b acceptance tests.
3. Apply is started with a reviewed object's key, version ID and expected SHA-256 and verifies
   everything itself; the plan bucket is separate from state, content-addressed and
   Object-Locked.
4. Plan retention is one day proposed, with lifecycle expiry of every plan version and delete
   marker, an age check at apply, and state on its own retention policy.
5. The reviewer allow-list is validated structurally, reviewed by a human and never committed.
6. Browser evidence is credential-safe: sanitized summaries and approved images only.

The six items were removed from the open questions below, and the deployment-parameter lists
now hold only genuine human decisions.

Order for the human, from here:

1. Review ADR 0011 and the topology document — in particular the Cognito boundary and
   cookies (decision 4), the identity mapping and the identity-binding boundary (decision 5),
   the reviewer allow-list validation (decision 6), the Terraform state and plan sensitivity
   (decision 7), the delivery model and its acceptance tests (decision 9), the
   browser-evidence rules (decision 10), the review corrections table and the final
   correction pass.
2. Check the snapshot hashes: `sha256sum docs/architecture/sources/*.md` must match the
   manifest (D.1 `44e29e07…853f3`, D `ea09cb2e…a2a2c`).
3. Commit the reviewed branch, push, open the pull request, merge after checks pass. No
   evidence artifact is claimed by this change.
4. *(Superseded by the M3.3b section's own order below.)* For M3.3b, expect a request for explicit approval of protected files — the
   pull-request static-check workflow and the manually dispatched plan and apply workflows
   under `.github/workflows/`, `CODEOWNERS`, and a Terraform static gate in
   `scripts/verify-repository.sh` — before any is written, and expect to configure the
   GitHub branch-protection and environment settings its acceptance tests check. For M3.3c,
   expect the same approval request for the `REQUIRED_FILES` additions,
   `scripts/check-runtime-imports.py`'s module inventory, the test bootstrap's role set as the
   verification script and the `verify` skill describe it once the identity-binding role
   joins, and the `record-evidence` skill if the evidence scan is placed there; and a
   dependency review of the HTTP client, JOSE/JWT library and AWS SDK it selects.
5. Before M3.3d: confirm every deployment parameter above, review the plan and the cost
   estimate, and record the authorization. Nothing before that creates a resource.

### M3.3b — Terraform, container and delivery foundation — **implemented, statically tested and independently reviewed at `cff27c8`; awaiting PR CI and merge; nothing planned, applied, pushed or deployed**

On `feat/milestone-3-3b-terraform-foundation` from `main` at `86d4195` (M3.3a, merged through PR
#11). ADR 0012 records the decisions; `docs/STATE.md` "CURRENT — Milestone 3.3b" records what exists
and what it does not claim. No Terraform plan or apply ran against AWS, no AWS or GitHub resource
was created, no image was pushed, nothing was deployed and no evidence was captured. The implementation
is committed at `cff27c8`, every actionable review finding is closed, and it awaits pull-request CI and merge.

**Approval (2026-09-13).** The human approved the protected-file changes for the purposes proposed,
with amendments, all applied: no agent-run AWS CLI call except local commands such as `aws
--version` (the proposed read-only allow-list was not introduced); the evidence restriction confined
to M3.3 AWS staging evidence (`docs/evidence/m3/aws-staging/`), with M3.1 and M3.2 capture unaffected;
downloads limited to `hashicorp/aws` 6.64.0 for `linux_amd64` and `darwin_arm64` and read-only
metadata lookups for the base-image digests and action SHAs; the existing administrator role
recorded only as a later human bootstrap identity, preferably through AWS SSO with MFA, never named
or trusted by anything in the repository; and the section 4 design decisions accepted, including the
documented `GetObjectVersion` limitation and the need for a second qualified reviewer.

**Changed and new files, by area:**

- Terraform: `infra/terraform/.terraform-version`, `README.md`, `bootstrap/` (nine `.tf` files since
  the second correction pass, the example, the lock file, one test file), `artifacts/` (seven `.tf`
  files, the example, the lock file, one test file; the first correction pass),
  `environments/staging/` (five `.tf` files, the example, the
  lock file, two test files), `environments/production/README.md`, the eight modules, `policy/`
  (`check.py`, `hcl.py`, `yaml_subset.py`, `cidr_allowlist.py` and three test modules),
  `scripts/static-checks.sh`, `runbooks/bootstrap.md` and `runbooks/staging-delivery.md`.
- Delivery: `infra/delivery/delivery.py`, `infra/delivery/readiness.json`,
  `infra/delivery/tests/test_delivery.py`.
- Container: `Dockerfile`, `.dockerignore`.
- Protected, each approved: `.github/workflows/ci.yml`, `.github/workflows/staging-plan.yml` (new),
  `.github/workflows/staging-apply.yml` (new), `.github/workflows/artifact-publish.yml` (new, since the
  first correction pass), `.github/CODEOWNERS` (new),
  `scripts/verify-repository.sh`, `.agents/policy/guard.py`, `.agents/policy/test_guard.py`,
  `.agents/skills/verify/SKILL.md`, `.agents/skills/record-evidence/SKILL.md`.
- Documents: `docs/adr/0012-terraform-container-and-delivery-foundation.md` (new), `docs/STATE.md`,
  this file, `docs/firmbatch-v1-roadmap.md`, `README.md`; and `.gitignore` gains the Terraform
  exclusions ADR 0011 decision 8 lists.

**Versions.** Terraform 1.15.8 (installed; 1.15.9 and 1.16.2 published, not adopted); `hashicorp/aws`
6.64.0 (the Registry's latest stable at implementation); Node 24.19.0 and Python 3.11.16 base images
pinned by digest; `actions/checkout` v7.0.1, `hashicorp/setup-terraform` v4.0.1 and
`aws-actions/configure-aws-credentials` v6.2.4 pinned by commit SHA in the new workflows.

**Local limitations.** Docker and Podman are not installed, so **the image has not been built
locally**; the Dockerfile's shape is checked by the policy gate, and the first actual container build is
CI's `container` job, which has not yet run and remains a required PR CI condition. actionlint, tflint and checkov are not installed; the
workflows are checked by the repository's own structural rules.

**Verification (2026-09-13, the uncommitted working tree over `86d4195`; runs, not evidence
artifacts).** `./scripts/verify-repository.sh`: **16 gates passed, 0 failed**, **241** required
files at that run (historical; the manifest has been 256 since the first correction pass below and is 257,
current, since the second), against the attested local PostgreSQL 16.15 cluster and Node 24.19.0 — the new Terraform and
delivery foundation gate among them. Inside that gate, `infra/terraform/scripts/static-checks.sh`
reported, at that first full run: the policy check, **19 rules, no findings**; the policy unit
tests, **101**; the delivery unit tests, **29**; `terraform fmt -check -recursive` clean;
`init -backend=false -lockfile=readonly` and `validate` for both roots that existed then (`bootstrap` and
`environments/staging`; the `artifacts` root came with the first correction pass); `terraform test` against
mocked providers, **8 passed** for `bootstrap` and **40 passed** for `environments/staging` (24
reviewer allow-list refusals and acceptances, 16 composition and module runs); the agent policy
tests, **315 checks passed**. **After the independent reviews' corrections** the same checks
report: the policy check, **19 rules, no findings**; the policy unit tests, **114**; the delivery
unit tests, **31**; `terraform test`, **8 passed** and **40 passed**; the agent policy tests, **343
checks passed**; `ruff check .` clean; `git diff --check` clean. A wrong Terraform
version on `PATH` was checked to make the gate script exit 1. The final canonical run, on the staged
tree, is reported with the change rather than written here, so that the tree the script verified is
the tree recorded.

**The M3.3b gate, item by item** (roadmap M3.3b):

| Gate item | Status |
| --- | --- |
| Terraform roots, modules, lock files, mocked tests, fmt, init, validate | Statically tested, passing |
| Reviewer allow-list: Terraform validation and the independent check | Statically tested: every refusal case in both |
| Plan-bucket properties: create-only for the plan role, no retention bypass or history listing, lifecycle never touching state | Written in policy and checked as text and by mocked plans; never evaluated by AWS |
| Roles: exact OIDC trust, distinct roles, apply boundary, not assumable through `staging-plan` | Written and checked as text and by mocked plans; never evaluated by AWS |
| Apply verification: checksum, source commit, lock digest, Terraform version, missing or expired version, unapproved commit, no re-plan | Verification functions unit-tested; workflow structure checked statically; never run |
| No binary plan or full rendering in an artifact or log | Checked statically in the workflows as written; never run |
| Workflows manually dispatched, `refs/heads/main` only, no fork or pull-request context | Checked statically and in the preflight's unit tests; never run |
| Environments: `main` only, reviewers, self-review prevented, no permanent AWS credential | **Unmet until a human creates them** — the preflight refuses without them |
| Workflow files covered by CODEOWNERS **and branch protection** | `CODEOWNERS` written; **branch protection unmet until a human configures it** |
| Container build from the pinned locks | **Unmet locally** (no Docker); a CI `container` job is written and has not run; the first actual build is a required PR CI condition |
| "Lint and policy" | Policy checks written and passing; **no Terraform linter** (tflint is not installed and is not introduced) |

**Independent reviews before staging (2026-09-13).** A read-only `security-operations-reviewer`
and a read-only `test-evidence-reviewer` ran over the finished tree; every finding was applied or
recorded as open (`docs/STATE.md` "Independent review corrections"; ADR 0012). The verification block
above gives the counts from before and after these corrections. That pass widened the human-applied
set to every IAM resource, KMS key, secret container, ECS task definition and service and the budget;
**the human reviewed that and replaced it** in the correction pass below.

**Correction pass (2026-09-14), at the human's instruction.**

1. **Migration `0007_password_hash_contract`** — an incidental reliability and security correction
   found by this slice's verification (ADR 0012 decision 14; `docs/STATE.md` "The correction pass
   before commit"). Structural Argon2id PHC validation in `security/passwords.py` and in
   `signup_account`, `complete_account_recovery` and `change_account_password`, without the generic
   secret-shape scan on the hash; an exact downgrade; `db/roles.py` gains `M3_3B_REVISION` and a plan
   equal to `0006`'s; the head and ladder tests move to `0007`; `test_password_hash_contract.py` is
   new. **The M3.3c identity mapping becomes `0008`.**
2. **The authority split** (ADR 0012 decision 5, with the privilege and resource ownership matrix,
   and `infra/terraform/runbooks/bootstrap.md`). The human bootstrap owns the trust anchors; after the
   first human apply, `staging-apply` applies task-definition revisions, service updates, digest
   rollout and ordinary infrastructure and budget changes inside the ECS delivery contract, checked in
   IAM and in the saved plan. The OIDC provider moves to the bootstrap root.
3. **Build once, promote by digest** (ADR 0012 decision 13; `runbooks/staging-delivery.md`). A new
   human-applied `infra/terraform/artifacts/` root; a new protected workflow
   `.github/workflows/artifact-publish.yml`; `staging-plan` takes `release_commit` and `staging-apply`
   takes `release_image`; `ci.yml` gains `workflow_call`; `infra/delivery/admission-policy.json` and two
   readiness prerequisites are new. The staging root no longer creates a repository.

That pass's canonical run on its staged tree: **16 gates passed, 0 failed**, **256** required files.

**Second correction pass (2026-09-14): the independent M3.3b review.** Sixteen
findings and a regression sweep, all corrected (`docs/STATE.md` "The second correction pass"; ADR 0012,
decision 15 new). One new file, `infra/terraform/bootstrap/delivery_policies.tf` (the delivery
identities' policies and boundaries), was added to `REQUIRED_FILES` with the human's explicit approval,
taking the manifest to **257**; `scripts/verify-repository.sh` changed in no other way. The protected
files this pass changed, at the human's direction: the three delivery workflows,
`.agents/policy/guard.py`, `.agents/policy/test_guard.py` and, for that one entry,
`scripts/verify-repository.sh`.

**Which run verifies what.** The first correction pass's run above preceded every edit of the second
pass and verifies none of them. The second pass's component runs, locally, before its canonical run:
the policy check, **23 rules, no findings**; the policy unit tests, **193**; the delivery unit tests,
**83**; `terraform test` against mocked providers, **15 passed** for `bootstrap`, **12** for
`artifacts` and **41** for `environments/staging`; the agent policy tests, **408 checks passed**; the
password-hash contract and migration tests, **147 passed** against the local PostgreSQL 16 cluster;
`ruff check .` clean; migrations `0001`–`0006` byte-identical to `86d4195`. The canonical run on the
final staged tree is reported with the change rather than written here.

**Third correction pass (2026-09-14): the reviewer's verification of the second.** Nine
of the seventeen corrections were found incomplete, one at P1; each is corrected and the eight verified closed
are preserved (`docs/STATE.md` "The third correction pass"; ADR 0012, with "Amendments to ADR 0011" new).
In short: promotion and apply read the admission policy — the live security overlay — from `origin/main`,
apart from each release's versioned historical contract, which now also freezes gate-job names and approval
rules; readiness prerequisites are per workflow, so publication precedes the first staging apply without a
false attestation; the canonical artifact registry is declared, never derived; publication refuses a
manifest-digest image ID and a rerun whose gates sit under another attempt before any credential; the checker
and the guard close the confirmed bypasses; the documents are reconciled. No file was added, so
`REQUIRED_FILES` stays at **257**. The protected files this pass changed, at the human's direction: the three
delivery workflows, `.agents/policy/guard.py`, `.agents/policy/test_guard.py` and
`.agents/skills/verify/SKILL.md`; `scripts/verify-repository.sh` is unchanged.

**Which run verifies what, for the third pass.** No run above verifies any of its edits. Its component runs,
locally, before its canonical run: the policy check, **23 rules, no findings**; the policy unit tests,
**207**; the delivery unit tests, **97**; `terraform test` against mocked providers, **18 passed** for
`bootstrap`, **12** for `artifacts` and **41** for `environments/staging`; the agent policy tests, **460
checks passed**; `ruff check .` clean. The canonical run on the final staged tree is reported with the change
rather than written here. That run, on the third pass's staged tree: **16 gates passed, 0 failed**, **257**
required files.

**Fourth correction pass (2026-09-14): findings 14, 16 and 17 and two regression gaps.**
Publish-attempt verification uses the workflow identity of the record's own contract, with a renamed-workflow
version-2 test; every policy and attachment that could reach a delivery identity is checked against an explicit
graph and read in full, and the plan role gains a human-applied permissions boundary that refuses secret values,
parameters, other keys, saved-plan reads and state writes even to an attached side door; the remaining documents
are reconciled; and regression tests now cover the post-push configuration-digest comparison (closed finding 4)
and `check-deployment-authorization` reading `origin/main` rather than the checkout (closed finding 12)
(`docs/STATE.md` "The fourth correction pass"). No file was added, so `REQUIRED_FILES` stays at **257** and the
gates at **16**. The protected files this pass changed, each with the human's exact approval:
`scripts/verify-repository.sh` (a comment) and `.agents/policy/guard.py` (a message).

**Which run verifies what, for the fourth pass.** No run above verifies any of its edits. Its component runs,
locally, before its canonical run: the policy check, **23 rules, no findings**; the policy unit tests, **213**;
the delivery unit tests, **101**; `terraform test` against mocked providers, **19 passed** for `bootstrap`,
**12** for `artifacts` and **41** for `environments/staging`; the agent policy tests, **460 checks passed**;
`ruff check .` clean. The canonical run on the final staged tree is reported with the change rather than written
here.

**Fifth correction pass (2026-09-14): finding 17's delivery-identity adoption and two policy-checker test gaps.**
Only the bootstrap root declares or owns a GitHub delivery identity (staging plan, staging apply,
artifact publish); every other root and module declares only its explicitly allow-listed workload roles, judged by
effective `name`/`name_prefix` resolved through locals, interpolation, variables and module values rather than
Terraform resource labels; `import` blocks are refused under `infra/terraform`, so adopting an existing AWS identity
or resource is a separate, explicitly reviewed human procedure; and an additional, unresolved or indirectly attached
policy on a delivery identity fails closed (`docs/STATE.md` "The fifth correction pass"). `REQUIRED_FILES` stays at
**257** and the gates at **16**.

**Current final verification** (locally, no artifact; not AWS-live). Component runs: the policy unit and mutation
tests, **225** on the final tree (**221** at `cff27c8` and the fourth pass's **213** above are historical; the four
added tests guard the numeric `USER 10001:10001` of the PR CI container-build correction); the delivery unit tests,
**101**; `terraform test`
against mocked providers, **19 passed** for `bootstrap`, **12** for `artifacts` and **41** for
`environments/staging`; the agent policy tests, **460 checks passed**. The canonical run on that staged tree
(staged-diff SHA-256 `5f426da6869ce990b401218cd795ab48fa962d4ae1399f491a9a0d96efc66db6`): **16 passed, 0 failed**,
**257** required files. The documentation reconciliation came after that run; **the final local canonical run**, on
its staged tree (staged-diff SHA-256 `e6b90bc5efb35903bae89ef6f35933c9198a5a1ead2ee16788ccc66a1930dd0d`, the tree
committed as `cff27c8`): **16 passed, 0 failed**, **257** required files.

**Remaining M3.3c work** (ADR 0011 decision 1, unchanged): the database bootstrap command; the
identity-binding command and its one-function database boundary; the identity-broker entry point and
its Cognito, JWT/JWKS and KMS clients; the staging configuration mode; the `__Host-fb_session` rename;
the AWS-mode routes including `/auth/logout`; metadata-safe logging; the identity-mapping migration,
now `0008` (`0007` is this slice's password-hash correction); the portal's
`/auth/*` adaptation; the web/API entry point that serves the compiled portal and no longer needs an
authenticator URL; the reviewed HTTP, JOSE/JWT and AWS SDK dependencies with both lock files and the
runtime-import inventory; container entry points and tests for every command; the browser-evidence
tooling; and the decision on who writes the Cognito client secret value.

**Order for the human, from here:**

1. Review ADR 0012, the two runbooks, the three workflows, migration `0007` and the IAM policies —
   especially the privilege matrix, the bootstrap-owned delivery identities and their boundaries
   (`bootstrap/delivery_policies.tf`), the apply boundary's ceiling and `iam:PassRole` confinement, the
   ECS delivery contract, the release repository and record-bucket policies, the artifact-publish
   boundary, the plan bucket policy, the frozen approval rule, the release-record contract and the
   admission exceptions.
2. Committed at `cff27c8`. Push, open the pull request, confirm CI's `verify` and `container` jobs pass —
   the first actual image build is proven there or not at all — and merge.
3. Before any AWS trust: protect `main`, add a second qualified reviewer, create and protect the
   three environments (`infra/terraform/runbooks/staging-delivery.md`, part A).
4. M3.3c. At M3.3d, in this order: the bootstrap root and the `artifacts` root, each naming the declared
   canonical artifact registry; a reviewed attestation of both; the first release published through
   `artifact-publish`; the human's first staging apply of that release; its attestation; then the pipeline
   (`infra/terraform/runbooks/bootstrap.md`). Qualify each external assumption ADR 0012 "Still open"
   assigns to M3.3d before the first use it governs.

### Open questions carried into Milestone 3

- **Configuration the authorities leave to a human** (register §3): the configured bridge
  monthly cap, total cap and per-supplier sub-caps (before any M6.2 purchase; plan v3.4's
  $3–5k a month and $10k total are a planning range, not the number); the numeric
  per-evaluation token and spend caps and the quote validity duration (M4.1); the
  qualification tenant, profile allow-list and per-run authorisations (M6.1, M6.2). Not
  needed before M3.
- **AWS staging deployment parameters and authorization** (M3.3d): account ID; region
  (recommended `eu-central-1`, unconfirmed); domains; CIDRs, including the reviewer allow-list
  and its maximum address-space allowance; SES identity; alert recipient; budget threshold;
  RDS sizing and PostgreSQL 16 minor; the saved-plan lifetime and the reviewers of the three
  GitHub delivery environments — `artifact-publish` (publication only), `staging-plan` and
  `staging-apply` (the two deployment environments); the staging identities to bind; the retention of AWS-managed
  identity logs; the current cost estimate; the managed-RDS qualification;
  and the human's explicit go-ahead, recorded before `apply`. The access model and the
  architecture themselves are decided (ADR 0011).
- **The Cognito adoption decision** — **recorded** in ADR 0011 (M3.3a): Cognito owns customer
  authentication (password, required TOTP, recovery and verification email in AWS mode)
  behind a Firmbatch identity broker; Firmbatch retains its server-side browser session,
  CSRF, workspace authorization, RLS, audit, consent and API credentials; the browser
  receives no Cognito token; identities bind by `(issuer, subject)` and never by email; the
  local M3.1 path stays for development, tests and a bounded rollback window. What remains
  is M3.3c's implementation of it and M3.3d's cutover acceptance.
- **Raised after the M3.3a review corrections, and not decided here.** A security review and
  an evidence audit of the corrected documents (2026-09-13) raised further questions. Six
  were decided in the final correction pass: the identity-binding credential, the
  constraints on `staging-plan` and `staging-apply`, plan approval independent of
  plan-produced metadata, versioned plan retention, structural allow-list validation, and
  credential-safe browser evidence (ADR 0011 "Final correction pass"). The questions below
  remain; the owning slice is named. None blocks merging M3.3a, and each must be settled
  before its slice's gate.
  - **M3.3b — plans and delivery** (answered by the M3.3b implementation where marked; ADR 0012):
    - *Answered:* the OIDC trust requires `aud` exactly `sts.amazonaws.com` and a `sub` naming
      the repository and the environment exactly; the workflows verify the numeric repository
      ID (`1349512121`), because a numeric `sub` template would be a repository setting.
    - *Answered in the workflows as written (never run):* no job references an environment before
      a preflight job that references none checks, through the GitHub API, that it exists and is
      protected; the bootstrap runbook creates the roles only after all three delivery environments —
      `artifact-publish` and the two deployment environments, `staging-plan` and `staging-apply` — are protected.
    - *Answered, and corrected by the human on 2026-09-14:* the human bootstrap owns the trust
      anchors (IAM, the OIDC provider, boundaries, KMS keys and policies, secret containers and
      values, buckets, the release registry); the apply role applies workload rollout and ordinary
      infrastructure and budget changes inside the ECS delivery contract, passes only the ten
      pre-created workload roles to ECS tasks, and is refused any trust-anchor change or budget
      action; the first full staging apply is a human's (ADR 0012 decision 5).
    - *Answered (never run):* images are built once by `artifact-publish` and promoted by digest
      (ADR 0012 decision 13).
    - *Answered in the workflows as written (never run):* the plan file and its output are written
      to the runner's temporary directory with owner-only permissions and removed at the job's end; the only reader of plan JSON is
      `delivery.py plan-summary`, which emits counts; no external policy or cost tool reads it.
      The delivery runbook says where an operator's review copy goes and when it is deleted.
    - *Answered:* the lockfile permission names the exact `<key>.tflock` object; the plan role's
      refresh reads are enumerated describe, get and list actions, with secret values, plan
      objects and Cognito user reads denied. ECS Exec is ruled out for every service and task.
    - *Still open:* one-off task execution in the pipeline; replication, signing and a production
      registry; the admission policy's measured thresholds; narrowing every task's internet-routed
      outbound HTTPS through the NAT; a dual-stack ALB so IPv6 reviewer entries can reach it;
      the plan job's cost summary; and the IAM action lists, refined against the first real
      plan at M3.3d.
  - **M3.3c — identity and broker:**
    - Resolving a subject may need `ListUsers` with a filter IAM cannot scope, which would
      read every user's email.
    - Binding to an unused invitation must not reintroduce email matching.
    - `/auth/logout` with an expired or replaced session, or a lost CSRF cookie, must still
      clear Cognito's managed-login cookie or force re-authentication, or the next login
      can succeed silently.
    - A `Referrer-Policy: no-referrer` extended beyond callback responses would make browsers
      send `Origin: null` on the logout form, which the `Origin` check would refuse.
    - Cookie-name normalisation has bypassed the `__Host-` prefix in other stacks, so
      Starlette's cookie parsing needs a test.
    - ALB 5xx pages and middleware refusals before the handler would show a page at the
      callback URL without `no-store` or `no-referrer`.
    - Unauthenticated `GET /auth/login` writes transaction rows and needs a bound and a
      cleanup.
  - **M3.3d — evidence and identities:**
    - Where the test identities' passwords and TOTP seeds are kept is unrecorded.
    - Staging users should not be created by Terraform, whose state and plans would then hold
      their emails and temporary passwords.
    - The AWS-managed records inventory should record settings, not contents. RDS PostgreSQL
      logs and ECS task overrides can also hold identity data.
  - **The policy guard** — *answered by M3.3b*, with the human's explicit approval (ADR 0012
    decision 11): agents may run only `terraform fmt`, `validate`, `version`, `providers lock` and
    `init -backend=false`, and the mocked tests only through
    `infra/terraform/scripts/static-checks.sh`; every other Terraform subcommand — `test`,
    `force-unlock`, `output`, `show` and state reads included — is refused; every AWS CLI call
    except `--version` and help pages is refused, read-only ones included; registry login and
    push are refused; and a write under `docs/evidence/m3/aws-staging/` is refused until M3.3d.
    The guard remains an accident-prevention guardrail, not a boundary.
- **Evidence promotion:** Milestone 2 could be promoted to VERIFIED LIVE by capturing the
  foundation-suite run with `/record-evidence` under `docs/evidence/m2/`. Until then the
  **implemented and tested** classification stands for all four slices. M3.1 is
  **implemented, tested and independently reviewed** at `f92ecb9` and could be promoted the
  same way, by capturing its foundation-suite run under `docs/evidence/m3/` at or after that
  commit; until an artifact and a deployment exist it is not VERIFIED LIVE. **M3.2** is in
  the same position at `ce097cb`, and now has a commit to provenance an artifact against;
  until an artifact and a deployment exist it is not VERIFIED LIVE either.
- **M3.1 follow-ups needing approval:** whether the hash-harvest limitation of
  application-side password verification (ADR 0009 decision 6) is acceptable through M3.3 or
  needs a separated verifier process there. **ADR 0011 answers it for AWS mode**: a
  Cognito-bound account carries no Firmbatch password hash, the web/API service holds no
  authenticator credential there, and the limitation is confined to local development and
  test, where it stands as recorded. **M3.2 does not change this**: the signed-in
  password change reads one hash per call and does it on the same narrow authenticator
  principal, which neither worsens nor solves the limitation. The two protected inventories
  are no longer open: both were extended with the human's explicit approval, and the
  authenticator's grant has since been narrowed to the functions its call graph actually
  reaches — **twelve** at present, after mailbox verification joined it at M3.1 and the two
  password-change functions at M3.2 — closing the least-privilege follow-up that correction
  had left behind.
- **M3.2 follow-ups, carried to M3.3 — now M3.3c and M3.3d under ADR 0011:**
  - **A real-browser end-to-end suite.** Nothing here has been run in a browser. The cookie
    contract is asserted at the header level against real PostgreSQL and the client behaviour
    in jsdom with a real cookie jar, but the *browser's own* enforcement of the `__Host-`
    prefix and `SameSite=Strict` — vendor behaviour, not this repository's code — and the
    visual result of the stylesheet are both unobserved. M3.3's gate is already "the real
    customer portal can be opened and reviewed on AWS with verified test identities", which is
    the natural home for a Playwright suite covering reload, multiple tabs, session
    replacement, expiry and mismatch against a deployed environment. **M3.3d's gate** (ADR
    0011 decision 10) requires that journey against the real URL, through Cognito with TOTP.
  - **Same-origin is now a requirement on M3.3's infrastructure**, not a preference. The
    `__Host-` prefix forbids a `Domain` attribute, so a portal on `app.` could not read a
    cookie an API set on `api.`. The staging deployment must put both behind one origin —
    **decided** (ADR 0011 decision 3): one origin, `https://staging.app.firmbatch.com`, the
    API under `/v1/*` and the broker under `/auth/*`; `staging.api.` is not retained.
  - **No email is delivered**, so a human cannot complete the signup, verification, recovery
    or invitation journeys locally without reading the token out of the API process. In AWS
    mode, verification and recovery mail become Cognito's (ADR 0011 decision 4, through an
    SES identity that is a deployment parameter, whose delivery and event records can hold
    recipient addresses and fall under M3.3d's review of AWS-managed records); Firmbatch's
    own workspace-invitation mail
    still needs a delivery adapter, which is an M3.3c decision — an SES adapter, or the
    invitation journey honestly unavailable in staging. A general provider remains M8's.
  - **A follow-up lock regeneration** could still move the development test-client pin from
    `httpx` to `httpx2`, which Starlette 1.6 prefers. Unchanged by M3.2.

---

## Complete — Milestone 2, shared product foundation — **merged through PR #7 at `4511f7d`**

Milestones 0 and 1 are complete; Milestone 1 merged at `6b4f341`. Milestone 2 has four
slices, all merged: M2.1 (PR #4), M2.2 (PR #5), M2.3 (PR #6), M2.4 (PR #7). The sections
below are the record of each slice as it was delivered and reviewed; their "order for the
human" lists are historical and complete.

**Milestone 2's declared implementation scope is complete and merged** -- every item the
canonical roadmap lists under it is built, and all four slices are implemented and tested.
That is a statement about the code and not about a deployment: Milestone 2 is not deployed
and nothing in it is VERIFIED LIVE, because no evidence artifact has been captured for any
of its four slices.

### M2.1 — PostgreSQL and tenant-isolation spine — **merged at `712b51a` (PR #4)**

Delivered by PR #4: the configuration boundary, Alembic migrations into a dedicated
`firmbatch` schema, the `tenants`/`workspaces` spine, forced row-level security with a
transaction-local tenant context, three separated roles with a verified runtime principal,
minimal typed repositories, a disposable-cluster attestation, and a **382-check** pytest suite
against real PostgreSQL 16 wired into `scripts/verify-repository.sh` and CI. See
`docs/STATE.md` for what it does, and `docs/adr/0004-postgresql-tenant-isolation-foundation.md`
for why.

**Six review rounds found fifty-eight issues in total; fifty-seven were corrected and one was reclassified.** The first round found fifteen, the second ten, the third eight, the fourth ten, the fifth ten, the sixth five. The fifth-round "blocker" was PostgreSQL 16's creator-ADMIN membership row, which a non-superuser cannot revoke; it is **not a defect** but the boundary the architecture draws, and the bootstrap assertion built on it had to be withdrawn after it made CI fail. See "M2.1 CI correction" below, ADR 0004 section 8f, and `control_plane/tests/test_admin_escalation.py`. Six were
security or destructive-safety defects reproduced against a real server before being fixed:
temporary-table shadowing, inherited tenant context, ORM identity-map leakage, an unverified
runtime principal, a teardown that trusted its handle (which dropped a real database during
testing), and a generated password reaching exception text. Each now has a regression test.
The table in `docs/STATE.md` lists what was demonstrated and what closed it.

Order for the human at the time (all of it is now done; PR #4 merged at `712b51a`):

1. Review `docs/adr/0004-postgresql-tenant-isolation-foundation.md`, in particular the
   "What this does not claim" section — RLS bounds a query given a context; it does not yet
   bind the context to an authenticated credential.
2. Review the five protected-file changes: `AGENTS.md` (roadmap authority),
   `.agents/skills/milestone/SKILL.md` (canonical milestone + §17 invariants),
   `.agents/skills/verify/SKILL.md` (the pass is no longer side-effect free; attestation
   prerequisite), `scripts/verify-repository.sh` (thirteenth and fourteenth gates, no existing gate weakened),
   `.github/workflows/ci.yml` (PostgreSQL 16 service, hash-pinned lock, explicit attestation
   step, one script call).
3. Attest the local cluster once, if it is not already marked — and **only** if it holds
   nothing you would miss:

   ```bash
   cd "$(git rev-parse --show-toplevel)/.."
   FIRMBATCH_ENV=test python3 -m firmbatch.control_plane.testing.attestation --check
   ```

4. Run `./scripts/verify-repository.sh` with `FIRMBATCH_TEST_DATABASE_URL` set. Expect
   **14 gates, 0 failed**.
5. If promoting M2.1 to **VERIFIED LIVE**, capture the foundation-suite run with
   `/record-evidence` under `docs/evidence/m2/`. Otherwise retain the current
   **implemented and tested** classification.
6. Human commits the reviewed branch and merges PR #4 after all required checks pass.

### M2.1 CI correction — the bootstrap administrator is trusted, not isolated

PR #4 failed CI on the very first thing it did:

```
DisposableDatabaseError: the shared admin can still reach the per-run owner
(pg_has_role reports SET and USAGE)
```

`bootstrap._require_no_set_reachability()` refused to return a handle unless
`pg_has_role(admin, owner, 'SET')` and `(..., 'USAGE')` were both false. CI's bootstrap
administrator is the `postgres` **superuser** of an ephemeral `postgres:16` service
container, and a superuser satisfies `pg_has_role` for every role in the cluster by
definition. The assertion was unsatisfiable there — and it was asserting a property the
accepted test-infrastructure boundary never promised.

The mismatch was in the assertion, not in the architecture. Stated consistently now in
`bootstrap.py`, ADR 0004 §8f, `docs/STATE.md` and here:

- the bootstrap administrator is **trusted**;
- **CI** uses a superuser inside an ephemeral PostgreSQL service container;
- **local verification** uses an explicitly attested disposable cluster;
- PostgreSQL administrative reachability is **accepted only inside that boundary**;
- **customer and runtime roles remain untrusted and separated**.

`_require_no_set_reachability()` is replaced by `_require_temporary_membership_released()`:
the same catalogue reads, with the `pg_has_role` questions removed. The one-statement `SET`
grant is still taken and still given back in a `finally`, and an explicit `set_option` or
`inherit_option` row left where PostgreSQL permits revoking it still fails bootstrap —
which is a real property on either kind of admin.

`control_plane/tests/test_admin_escalation.py` now tests **containment** rather than the
escalation. The test that asserted the administrator could re-acquire the owner role and
perform an owner-only operation is removed; a passing test whose subject is a working
escalation proves nothing the product sells. In its place: bootstrap completes under either
kind of administrator; no revocable membership row or path carries `SET` or `INHERIT`; the
three per-run roles hold no administrative attribute, gain no route into the administrator,
and (for the runtime pair) none into the migration owner; the administrator's credentials
appear in no runtime URL. The PostgreSQL 16 `CREATEROLE` `ADMIN OPTION` limitation stays
asserted for a non-superuser administrator, and the two owner-only-refusal assertions that
are meaningless for a superuser now `skip` with a stated reason instead of silently
`continue`ing.

**Skip counts differ by cluster shape, and both are expected.** Locally: 1 skip (granting
`REPLICATION` needs a superuser). On CI: that test runs, and the two non-superuser-only
assertions skip instead.

### Blocking requirement carried out of M2.1 — `AUTH-BOUND-TENANT-CONTEXT`

M2.1 gives **structural** isolation: forced RLS, fail-closed transactions, no leakage
through pooled connections or ORM identity maps, separated application and migration
credentials. The application service remains a *trusted setter* of tenant context.

It does **not** protect against arbitrary SQL run with a compromised runtime credential:
the runtime role can `set_config('app.tenant_id', <any uuid>, true)` and RLS will evaluate
faithfully against whatever it was told. No partial mechanism was attempted here — a
convention or a second GUC would look like the property without being it.

**Customer-facing deployment is blocked** until tenant context is derived from an
authenticated, unforgeable capability rather than a caller-supplied workspace UUID. Tracked
as `AUTH-BOUND-TENANT-CONTEXT` in Milestone 3 of `docs/firmbatch-v1-roadmap.md`, with five
adversarial completion tests. ADR 0004 §8g and `docs/STATE.md` carry the detail.

Nothing in this repository asserts the limitation as a passing test; it is tracked in
prose, deliberately, so that it is fixed rather than deleted.

**Status at M2.3.** The database/GUC portion is closed: the limitation above no longer
holds, and completion cases 1 to 4 -- arbitrary context, a leaked runtime credential, SQL
injection, and replay or forgery -- are met and tested adversarially. Case 5, an
authenticated user with no membership in a workspace, needs memberships and is Milestone
3's. **The task stays open until both halves do, and customer-facing deployment stays
blocked.** The prose above was the tracking and is left standing; nothing had to be deleted
when the capability landed, which is what that paragraph was for.

### M2.2 — idempotent mutations and the transactional outbox — **merged at `b028f21` (PR #5)**

Delivered by PR #5, implementation commit `d362717`. Migration
`0002` adds two tenant-scoped, append-only tables — `idempotency_records` and
`outbox_events` — behind the same forced row-level security as the spine.
`control_plane/db/idempotency.py` is the typed primitive that claims a key scoped by
tenant and operation, fingerprints the request identity, replays an identical retry,
rejects a conflicting reuse, runs the mutation once, and commits the business state, the
completed claim and exactly one linked outbox event together.

**Two review correction passes were applied before that commit, and they changed the
design in the places below.** Read this list before the code:

- **The mutation callback no longer receives the caller's `Session`, and a commit reached
  around it is refused before it happens** (merge blocker, corrected twice).
  `Session.commit()` in SQLAlchemy 2.x commits the *outermost* transaction even inside an
  open `begin_nested()` SAVEPOINT, so a callback could have persisted its business row
  before the claim and the event were written. It now receives a `MutationUnitOfWork` that
  forwards ORM work and refuses `commit`, `rollback`, `close`, `begin`, `begin_nested`,
  `connection`, `get_bind`, `expunge_all` and the legacy bulk API.

  The first fix stopped there and re-checked the transaction *after* the callback. That was
  not enough: the real session is one `object_session(row)` away, and a check after `COMMIT`
  is too late — the business row is already committed with no claim and no event, and a
  retry collides with a row nothing explains. So a `before_commit` listener is now attached
  to the real session **for the duration of the callback only**, raising ahead of the flush
  a commit performs, and removed in a `finally` before the primitive releases its SAVEPOINT
  and before the caller commits. `_require_intact_boundary` stays as secondary detection of
  a rollback or other boundary destruction, and is no longer described as preserving
  atomicity.

  Unflushed ORM state at entry is also rejected, because `begin_nested()` flushes pending
  rows *before* opening the SAVEPOINT. That check covers pending state only; a write the
  caller already flushed cannot be detected and is outside the SAVEPOINT, so the rule is a
  contract: every business write for the operation goes inside `mutate`, and the primitive
  is called before any DML for that operation. ADR 0005 decisions 4a and 4b.
- **The payload-plane claim was overstated and is corrected** (merge blocker). The
  parameter is now `request_identity` — bounded metadata validated *before* the mutation
  runs — and the test that passed a raw prompt and an API key and treated hashing them as
  compliance is gone, replaced by an S3 manifest/object-reference example. The key denylist
  matches **whole names** rather than substrings, so `input_manifest_id`,
  `output_object_key` and `artifact_digest` are accepted. Three false claims were removed
  from the repository: that the absence of `bytea` prevents storing payload bytes, that a
  256-character string cannot be payload, and that bounded JSONB proves the absence of
  secrets or content. M2.2 proves that the primitive **persists only a fingerprint and
  bounded metadata**; the data-flow proof is Milestone 5's.
- **The outbox is decoupled from API idempotency.** `idempotency_record_id` is nullable and
  is an optional *causation* link, so the controller, reconciler, validator and lifecycle
  work of later milestones can commit an event with a state change without manufacturing a
  claim nobody can retry against. `append_outbox_event` is the one writer, and the
  primitive calls it. No dispatcher, SQS integration, delivery state, global events or
  fan-out was built.

The suite is **512 checks (511 passed, 1 skipped locally)**, up from 382, across three new
modules. `docs/STATE.md` has the property-to-test map;
`docs/adr/0005-idempotent-mutations-and-transactional-outbox.md` has the reasoning.

Seven things worth a reviewer's attention, in descending order of consequence:

1. **No durable "in progress" record, deliberately.** A two-phase claim needs a reaper to
   decide when a `pending` row is abandoned, and M2.2 does not build one. Everything
   commits together instead, so a process killed before `COMMIT` leaves nothing and the
   retry is an ordinary first attempt. ADR 0005 decision 2.
2. **The mutation contract is enforced by the handle and by a scoped pre-commit guard,
   not by a docstring.** See the correction list above. The known escape — the real
   `Session` behind a mapped row — is refused before the commit, so no partial state is
   created. It is still a guardrail and not a sandbox: a callback that opens its own
   engine or connection, drops to the DBAPI, or issues `COMMIT` as raw SQL is outside this
   transaction and outside anything the module can see.
5. **The loser of a race executes its mutation and has it rolled back to a savepoint.**
   Only one mutation *commits*; both may run. A `mutate` function must therefore confine
   itself to rollback-safe DML — no mail, no spend, no provider call, no session-scoped
   advisory locks. That is what the outbox is for.
6. **`READ COMMITTED` is required and anything stricter is refused.** The recovery path
   re-reads a row another transaction has just committed. Under `REPEATABLE READ` that
   read returns nothing and the caller is told a taken key is free — a wrong answer, so
   the level is checked rather than assumed.
7. **Append-only is enforced twice**: the application role holds `SELECT, INSERT` only, and
   the tables carry no `UPDATE`/`DELETE` policy at all, so even the owner reaches no row
   under `FORCE`. The one route left open by design is a tenant delete cascading, and no
   runtime role holds `DELETE` on `tenants`.
8. **"Exactly one event" is a property of the primitive, not of the constraint.** The
   unique constraint on `(tenant_id, idempotency_record_id)` enforces **at most one**
   linked event; a uniqueness constraint cannot require existence. The primitive writes
   exactly one, atomically with the claim, and the PostgreSQL tests count both after a real
   commit. A deferred constraint trigger would have made it a database fact and was
   deliberately not built — machinery to preserve a sentence is the wrong trade.
9. **Exactly-once delivery is not claimed anywhere.** The outbox records intent. A later
   dispatcher may deliver at least once.

Three existing tests were changed rather than added to, and all three were strengthened:
`test_there_is_exactly_one_head` now expects `0002`;
`test_every_tenant_scoped_table_has_an_isolation_policy` now handles both policy shapes
(the spine's `FOR ALL`, and the append-only read/append pair) **and** asserts `USING` and
`WITH CHECK` independently, where the first version's `qual or with_check` read only
`qual` for a `FOR ALL` policy and would have passed with a dropped or mis-scoped
`WITH CHECK`; and the binary-column test now says what it establishes (a shape check)
rather than what it does not (a payload-plane proof). No gate was removed, weakened,
renamed or duplicated.

Review is complete and the work merged at `b028f21`. What was reviewed, for the record: `docs/adr/0005-idempotent-mutations-and-transactional-outbox.md` — in
particular "What this does not claim" — and the one protected-file change,
`scripts/verify-repository.sh`, which gains six entries in `REQUIRED_FILES` (73 now, from
67) and **no new gate**, because the foundation-suite gate already runs the whole
`control_plane/tests` directory. Nothing else under `AGENTS.md`'s ask-first list was
touched.

All of that is now done and merged. M2.2 remains **implemented and tested** rather than
VERIFIED LIVE: no evidence artifact was captured for it, and merging is not evidence.

Deliberately deferred out of M2.2, and each one is somebody's later milestone: the outbox
**dispatcher** and SQS publishing (M6), delivery state, global (non-tenant) events and
fan-out (M6), idempotency-record **expiry** (pruning needs a `DELETE` policy these tables
deliberately lack), HTTP endpoints and `Idempotency-Key` header handling (M3), and the
**payload-plane data-flow proof** (M5) — M2.2 shows only that the primitive persists a
fingerprint and bounded metadata. Mutable delivery state, when it arrives, belongs in a
separate table so the event content stays immutable.

Known limits carried out of this slice, in prose rather than as passing tests:

- the mutation unit of work and the commit guard are a guardrail, not a sandbox: they do
  not bound arbitrary Python, an independently opened connection, or raw `COMMIT` (item 2
  above);
- business writes flushed before the primitive is called are outside its SAVEPOINT and
  cannot be detected; the rule that closes that is a contract, not a check;
- the metadata denylist and size bounds are defense in depth and prove nothing semantic —
  `TEXT` and `JSONB` hold text, so an encoded payload fits;
- the contention test depends on `pg_stat_activity` showing a blocked backend, so on a
  server where that view is restricted it fails rather than silently degrading.

### M2.3 — authenticated context, authorization, audit, secrets — **merged at `dca2d49` (PR #6)**

Delivered by implementation commit `89fbdd9`. It closes
the piece M2.1 deliberately left open: tenant context is now resolved from an authenticated
credential rather than accepted from a caller-set setting. `docs/STATE.md` has what it does and the property-to-test map;
`docs/adr/0006-authenticated-authorization-audit-and-secrets.md` has why.

**The one sentence that matters.** A transaction no longer chooses its tenant. It presents
a 244-bit credential to a hardened `SECURITY DEFINER` function, which hashes it, looks the
digest up in a table no runtime role can read or write, and — if the binding is known,
unrevoked and unexpired — writes one row into a protected relation no runtime role can
read, write, delete from or clear. Every policy reads that. `app.tenant_id` is read by
nothing, and `firmbatch.app_current_tenant_id()` is dropped.

(244 bits and not 256: PostgreSQL generates the value from two `gen_random_uuid()` values,
122 random bits each. The standalone Python generator uses 32 random bytes and is 256 bits.
Both share one 43-character format, and the 43 is a rendering rather than a measurement.)

Eight things worth a reviewer's attention, in descending order of consequence:

1. **The transaction context is a protected permanent relation, not a setting and not a
   temporary table, and the reason is worth reading before the code.** Any custom GUC is
   writable by the role holding the connection, so a settings-based scheme is either
   forgeable or circular. `firmbatch.auth_transaction_context` is an unlogged table in the
   pinned schema, keyed by the backend pid and carrying the `xid8` of the transaction that
   wrote it; it is read back only when that id equals `pg_current_xact_id_if_assigned()`.
   No runtime role holds any privilege on it, so nothing but the `SECURITY DEFINER` writer
   can touch it, and there is no clearing operation anywhere — none is needed, because an
   uncommitted row is invisible to every other transaction and a committed one can never
   match a future transaction's id. ADR 0006 decision 2.
2. **The first version put this in `pg_temp` and that was wrong**, which is recorded here
   rather than quietly replaced. `DISCARD TEMP` is legal for any role, needs no privilege,
   and drops every temporary table in the session including one owned by somebody else — so
   the context vanished and a *second* credential could be bound in the same transaction.
   Measured against a real server. There was no privilege to revoke and no check to add,
   which is why the design changed rather than being hardened. ADR 0006 decision 2 records
   the measurement; the rejected alternative is kept at the end of that ADR.
3. **ADR 0004's position on `SECURITY DEFINER` in a policy predicate is deliberately
   reversed**, and the reasoning is in ADR 0006 decision 3a. The 2.1 helper read a value
   the caller could write; the 2.3 reader reads a relation the caller cannot read, which is
   the entire point. Every definer function is owned by the schema owner, pins
   `search_path`, revokes `PUBLIC`, is granted minimally, contains no dynamic SQL and
   resolves no object by name at runtime — five properties, five separate tests.
3a. **Revoking from `PUBLIC` is not stating the access control**, and the review was right
   that it was all the first version did. `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>` grants
   at object-creation time, so the grant is on `auth_bindings` before the migration's next
   statement runs. The migration now sanitises every relation, function and type in the
   schema; `db/roles.py` runs the identical block before its grants; and `db/principal.py`
   refuses a connection that holds any privilege on protected state. Three measures, because
   a default-privilege rule outlives a migration and a database can be migrated without
   being wired. ADR 0006 decision 3b.
3b. **The bind refuses any isolation level but `READ COMMITTED`, in the database.** Under a
   stricter level the registry lookup reads a snapshot older than the statement, so a
   revocation committed in between is invisible. Expiry is compared against
   `clock_timestamp()` rather than `now()` for the same family of reason, and the
   linearisation point is stated and tested. ADR 0006 decision 3c.
4. **Provisioning can no longer name a tenant, including an existing one.**
   `begin_tenant_provisioning()` takes no arguments and generates the id itself. This is
   strictly narrower than M2.1, where the provisioning role could set context to any tenant
   and read or amend that row. **Registration takes no credential either**, for the same
   family of reason: a caller that could submit a candidate could learn from the outcome
   whether it already existed in another tenant. The database generates it and returns it
   once. ADR 0006 decision 7b.
5. **Appending an audit event requires no scope, and the cost is named rather than
   hidden.** An `audit:append` capability would make it possible to issue a credential that
   acts without leaving a trail. The price is that a credential with no scopes can write
   bounded, tenant-scoped, immutable audit rows. ADR 0006 decision 6a. **`occurred_at` is
   written by a trigger from `clock_timestamp()`**, not defaulted from `now()`: a caller
   backdates an event by opening its transaction early, without supplying anything, and a
   policy comparing against `now()` would have agreed with it.
6. **Authentication itself is not audited, and cannot be.** A failed bind has no tenant to
   scope a row to and aborts the transaction that would have written one; a successful bind
   happens per request. Credential registration and revocation are audited. Failure belongs
   in the application log, which is Milestone 8's. ADR 0006 decision 6d.
7. **`INSERT ... RETURNING` applies `SELECT` policies**, so a write-only credential cannot
   insert through the ORM. That is PostgreSQL behaving correctly; it is why the `tenants`
   read rule includes the provisioning scope, why the audit insert carries no `RETURNING`,
   and it is asserted as documented behaviour rather than left to be discovered.
10. **Four of the five `AUTH-BOUND-TENANT-CONTEXT` completion cases are met.** The fifth —
   an authenticated user with no membership in a workspace — needs memberships, which are
   Milestone 3's. The task is not closed here and this branch does not close it.

Deliberately deferred, and each is somebody's later milestone: signup, login, accounts,
memberships, invitations and portal UI (M3); product API credential CRUD and browser
sessions (M3); HTTP endpoints and an API framework (M3); jobs, quotes, billing and
lifecycle state machines (M2.4, M4, M5); S3 and the payload plane (M5); the outbox
dispatcher and SQS (M6); Secrets Manager and KMS adapters (M8); provider credentials and
execution (M6); the operator agent (M6, separate software).

Known limits carried out of this slice, in prose rather than as passing tests:

- a compromised **migration owner** credential defeats all of it, because that role owns
  the functions and the policies. `db/principal.py` refuses to let a runtime connection be
  or reach that role, and `test_ownership_boundary.py` asserts it — that is the boundary,
  not an absence of one;
- on authentication the raw credential travels to PostgreSQL once as a bound parameter, and
  on registration it comes back once in a result row. psycopg sends parameters out of line,
  so neither is in the query text or in `pg_stat_activity`, but a server configured to log
  parameters — or a client that logged result sets — would capture one exactly as it would
  a password. Deployment property, Milestone 8;
- the context costs **one upsert per authenticated transaction** and a primary-key lookup
  per policy evaluation. That is the cost the temporary-table design was avoiding, and the
  property it bought instead was not real. If the read ever matters the fix is a
  per-transaction cache, not a weaker check;
- `clock_timestamp()` is the *server's* clock. A wrong server clock produces wrongly dated
  audit events and nothing here detects that; what is excluded is a caller choosing the
  time;
- the secret-shape rules and the metadata bounds are defense in depth and prove nothing
  semantic, exactly as ADR 0005 decision 9 says of the denylist they extend. `hunter2` is a
  valid reference name and a valid metadata key, and there is a passing test whose subject
  is that limit.

One protected-file change, and only one: `scripts/verify-repository.sh` gains **thirteen**
entries in `REQUIRED_FILES` (86 now, from 73) and **no new gate**, because the
foundation-suite gate already runs the whole `control_plane/tests` directory. Nothing else
under `AGENTS.md`'s ask-first list was touched, and **none of the three security correction
passes changed either file again** — they added no files, so the manifest is unchanged
from the first pass. `scripts/check-runtime-imports.py` — which
is not on that list — gains seven entries in its `RUNTIME_MODULES` manifest so the new
runtime modules are covered by the import-boundary check; no gate logic changed, and the
change strengthens the check rather than relaxing it.

Order for the human at the time (all of it is now done; PR #6 merged at `dca2d49`):

1. Review `docs/adr/0006-authenticated-authorization-audit-and-secrets.md`, in particular
   "What this does not claim" and the rejected alternatives.
2. Review the one protected-file change and the `RUNTIME_MODULES` manifest entry above.
3. `./scripts/verify-repository.sh` was run with `FIRMBATCH_TEST_DATABASE_URL` set at
   `89fbdd9`: **14 gates passed, 0 failed**, and the PostgreSQL foundation suite **1,314
   passed, 1 skipped** — the one skip is the pre-existing REPLICATION skip. Skip counts
   differ by cluster shape; see the M2.1 CI correction above.
4. Push the branch, open the pull request, and merge after all required checks pass.
5. If promoting M2.3 to **VERIFIED LIVE**, capture the foundation-suite run with
   `/record-evidence` under `docs/evidence/m2/`. Otherwise retain the
   **implemented and tested** classification — no evidence artifact has been captured, so
   M2.3 is not VERIFIED LIVE today.

### The M2.3 security correction passes — twenty-three findings, all closed

Four independent reviews of the M2.3 implementation found twenty-three issues between
them, ten of them P1. Every one was confirmed against a real server before being fixed.
`docs/STATE.md` has the four tables of what was demonstrated and what closed it; the ones
worth a reviewer's attention here are the ones that changed the design rather than hardening
it.

1. **`DISCARD TEMP` defeated the temporary-table context** (P1). One statement, legal for
   any role, no privilege required: it drops every temporary table in the session including
   one owned by somebody else. The context vanished and a **second** credential could then
   be bound in the same transaction. The temporary table is gone; the context is an
   unlogged protected table keyed by the transaction's `xid8`, and there is no clearing
   operation anywhere. This is the architecture change, and ADR 0006 decision 2 records it
   as one.
2. **Default privileges could grant the credential registry to the runtime role** (P1).
   `REVOKE ... FROM PUBLIC` never touched a grant `ALTER DEFAULT PRIVILEGES` applied at
   object-creation time. Three measures now: the migration sanitises the whole schema, the
   role wiring sanitises again before granting, and the runtime principal check refuses a
   connection holding protected privileges.
3. **Registration took the credential as an argument** (P2), which made success-versus-
   failure a cross-tenant existence oracle. The database generates it now and returns it
   once.

From the second review:

4. **The principal check followed inheritance, and `SET ROLE` does not** (P1).
   `has_table_privilege` and `has_function_privilege` answer about *effective* privilege, so
   `GRANT other TO firmbatch_app WITH INHERIT FALSE, SET TRUE` left both saying "no" while
   one `SET ROLE` reached everything `other` held. Measured: the connection was certified
   safe and read the credential registry a statement later. Every reachable role is now
   enumerated with `pg_has_role(..., 'MEMBER')` and every object test runs against that set
   — and a runtime principal may hold **no membership at all**.
5. **`credential:manage` decided what the credentials it minted could do** (P1). A leaked
   credential holding nothing else could mint itself a successor holding `workspace:write`.
   Delegation is now bounded in the database: delegable scopes only, and never more than the
   issuer holds. There is no wildcard, and `tenant:provision` is delegable by nobody.
6. **Role wiring assumed the head schema** (P1/P2). After a controlled rollback to `0002`,
   provisioning failed with `UndefinedTable` on its first statement. `db/roles.py` is now
   revision-aware, with an explicit plan per supported revision and a refusal for anything
   else. Application code at head supports schema `0002` **only** for controlled rollback
   and provisioning — never for runtime operation.
7. **The audit metadata policy was bypassable** (P2). The application role held `INSERT` on
   the trail, and the table's constraints bound a document's size and shape and nothing
   about its content. The privilege is gone; `firmbatch.append_audit_event()` is the only
   way in and applies the whole policy inside the database.
8. **Authenticated work needs a writable primary** (P2), because acquiring a context writes
   a row. That is now a deliberate, named refusal rather than an unexplained write error,
   and it is a stated limitation: **read-replica routing is Milestone 8**.

The other four -- stale-snapshot revocation and `now()`-based expiry, echoed reference
identifiers, transaction-start audit timestamps, and echoed metadata keys -- are corrected
in the same pass and are covered in `docs/STATE.md`.

From the third review, three more:

11. **Column-level ACLs bypassed the protected-state boundary entirely** (P1). As the
   migration owner, `GRANT SELECT (backend_pid), UPDATE (tenant_id) ON
   firmbatch.auth_transaction_context TO <application role>` — and the hardened checkout
   accepted the connection. The application could then authenticate as tenant A, rewrite
   its own context row's `tenant_id` to tenant B, and read tenant B's rows. Column grants
   live in `pg_attribute.attacl`; the principal check asked `has_table_privilege` and both
   ACL sanitisers took their grantee list from `pg_class.relacl`, where a column-only
   grantee never appears. Both are corrected, and the column check is **independent** of
   the table check rather than folded into `has_column_privilege`, which conflates them.

   Worth recording because the review's diagnosis was not quite the defect: the report said
   `REVOKE ALL ON TABLE` does not remove a column grant. It does — measured. What never
   happened was the enumeration, so the `REVOKE` was never issued.
10. **Python `\s` and PostgreSQL `[[:space:]]` are different sets** (P2), so the metadata
    policy's two implementations disagreed on real values: a U+00A0 before `Bearer example`
    was refused at the boundary and accepted by the database, which is the half that holds
    when a runtime role writes the call itself. Confirmed and wider than reported — U+0085,
    U+00A0, U+2007, U+202F **and** the ASCII information separators U+001C–U+001F all
    diverge on this server. Whitespace is now an enumerated code-point set folded to ASCII
    by both implementations before any pattern runs, and the patterns say `[ ]`/`[^ ]` in
    both languages. Ordinary Unicode letters are untouched and stay valid.
11. **The standby diagnostic was unreachable on a standby** (P2). `auth_transaction_context`
    is `UNLOGGED`, and PostgreSQL refuses to *plan* a query against an unlogged relation
    during recovery — so the context read every entry path began with failed before the
    deliberate `auth_require_writable_primary()` guard could speak. A preflight naming
    nothing in the schema now runs first on every entry path, and the database guard is the
    first executed statement of both entry functions so raw-SQL callers fail safely too.
    **Authenticated reads remain primary-only; read-replica routing is Milestone 8**, and no
    live standby has been tested or claimed.

The suite is **1315 checks (1,314 passed, 1 skipped locally)**: 805 after the first
correction pass, 934 after the second, 1122 after the third, and 1314 after the fourth,
which added 192. Nothing was weakened to make any of them pass — the four tests whose subject was a mechanism that no
longer exists were rewritten to assert the property that replaced it, and each says so in
its docstring. Every test added by the third and fourth passes was run against the pre-fix
code and seen to fail for the intended reason.

### The case-fold half of finding 10 — closed in a fourth pass

Fixing whitespace left the identical defect one clause over, and the review that found it
was right that it is a defect rather than a design question: it is fixed, not deferred.

`re.IGNORECASE` on `str` is Unicode case folding; PostgreSQL's `~*` is locale case folding.
Measured on this server, with the whitespace fix already in:

| value | `looks_like_secret` | `firmbatch.secret_shape` |
| --- | --- | --- |
| U+017F + `ecret=x` (LATIN SMALL LETTER LONG S) | refused | **accepted** |
| `api` + U+212A + `ey=x` (KELVIN SIGN) | refused | **accepted** |

The direction is the dangerous one: the database is the half with no Python in front of it.

**The correction.** One pipeline in both implementations — fold the 29 enumerated whitespace
code points to an ASCII space, fold `A`–`Z` to `a`–`z`, then match **case-sensitive**
lowercase patterns. Nothing consults a locale or a Unicode table: `str.translate` here,
nested `translate()` there, and no `str.lower()`, `str.casefold()`, `lower()`, `upper()`,
`~*` or `(?i)` anywhere. `\b`/`\y` went the same way, replaced by an explicit
`(?<![0-9a-z_])`, because they are the same locale question in other clothes.

With every construct either engine has to look up removed, the pattern text itself is now
**identical in both places**, and a test compares it character for character rather than
comparing answers on samples somebody chose. Every caller inherits it: there are exactly two
implementations of the rule and everything goes through one of them.

**The limitation it buys, and it is a real one.** A Unicode homoglyph of a marker is now
recognised by *neither* implementation, where before it was caught by one. That is the
honest cost of an ASCII fold and the right trade — a Unicode fold cannot be reproduced by
`translate()`, so keeping it leaves the layer a caller can walk around stricter than the
layer that actually holds. The denylist is defense in depth against a credential pasted
where a reference belongs; it does not claim to detect a semantic secret and does not claim
to survive a homoglyph. Both homoglyphs sit in the **accepted** corpus so the limitation is
a test somebody has to change on purpose. See ADR 0006 decision 8c.

One behaviour change worth knowing: because the word boundary is ASCII-explicit now, a
non-ASCII letter counts as a boundary, so `ıtoken=x` is recognised where `\b` and `\y` both
used to say nothing. Stricter, and both implementations say it together.

### `AUTH-MEMBERSHIP-BOUND-IDENTITY` — Milestone 3, and it blocks launch — PLANNED

The successor to the identity half of `AUTH-BOUND-TENANT-CONTEXT`, recorded under its own
name because the old one now describes a gap that is closed. Naming the remainder after the
closed thing is how a finished piece of work gets re-litigated and an unfinished one gets
overlooked.

**What must become true.** An authenticated customer identity must be **proven to be an
active member of the selected workspace and tenant** before a browser session or an account
credential is issued for it.

Today a credential *is* the membership: a binding names one tenant, and the database will
not issue a context for any other. That is sufficient while credentials are provisioned out
of band and there are no user accounts. It stops being sufficient the moment a person can
sign in and choose a workspace, because something then has to decide which workspaces that
person may choose from — and nothing does.

**Why M2.3 could not close it.** There are no users, no memberships, no invitations and no
sessions in this repository. The old completion case 5 asks what happens to an
authenticated non-member; with no membership model there is no such person to test, and
building a partial one here would be the half-built capability ADR 0004 §8g argues against.

**Completion gate.** Adversarial tests, against real PostgreSQL 16, each failing closed:

1. A verified account without membership in a workspace may retain its account-level
   browser session, including the ability to create its first workspace, but cannot bind
   that session to the unauthorized workspace or obtain any credential scoped to it, by any
   route the API exposes.
2. Revoking a membership stops the identity acting in that workspace, on the same
   linearisation terms the credential path already states.
3. An invitation accepted for one tenant grants nothing in another.
4. Browser sessions and API credentials are distinct credential types and are never
   accepted at one another's authentication boundary or directly converted or redeemed into
   one another. A verified browser session may explicitly authorize an audited
   API-credential create, rotate or revoke operation only after active membership and the
   requested scopes are rechecked; that operation issues a new credential and is not a
   token exchange.

**Customer-facing deployment remains blocked** until Milestone 3 supplies identity,
membership and credential lifecycle together.

### M2.4 — explicit lifecycle state machines — **merged at `4511f7d` (PR #7)**

Delivered by implementation commit `d91e4f2` on `feat/milestone-2-4-lifecycle-state-machines`,
with the milestone and all three correction passes, and **merged to `main` at `4511f7d`
through PR #7** (status commit `290f715`). `docs/STATE.md` has what it does and the
property-to-test map; `docs/adr/0007-persisted-race-safe-lifecycle-transitions.md` has why.
The paragraphs below are the record as it stood at review; "awaiting merge" wording in the
history tables of `docs/STATE.md` describes that moment.

**An independent review found six issues in the first implementation, and all six are now
corrected at the root.** Their table is in `docs/STATE.md` ("The M2.4 review correction
pass"); the design consequences are ADR 0007 decisions 4a–4c, 8a-bis, 8c and 8d, and the
extension to 8b. In one sentence each: a transition can no longer commit without its outbox
event, because the database function writes every artifact and Python appends nothing;
`mutation:execute` no longer reads a lifecycle's framework records, because those rows carry
a derived machine tag their read policy consults; two identical concurrent requests now both
replay instead of one conflicting; a definition is a draft until it is published in one
transaction, and sealed afterwards; the expected revision is compared before any graph
question; and `MutationUnitOfWork`'s generated forwarders can no longer be redirected to
another `Session` operation.

**A second review then found five more, four of them introduced or left standing by that
first pass, and all five are corrected too.** Their table is in `docs/STATE.md` ("The second
M2.4 review correction pass"); the design consequences are ADR 0007 decisions 4a-bis, 4d, 8e
and 8f. In one sentence each: a replay is now backed by a protected provenance row linking the
claim to the exact transition it stands for, because a machine tag says which machine a row
belongs to and not what it records; the operation name and the request fingerprint are derived
inside PostgreSQL, because a fingerprint a caller supplies can bind a claim to a request that
was never made; lifecycle **audit** events got the same tag and the same narrowed read policy
the other two framework tables already had; every publication rule moved from the function
onto the table's own triggers and every child mutation now serialises with publication on one
machine-row lock; and a chosen framework identifier is refused at permission-check time while
the `lifecycle.` operation namespace is closed to generic writers, which is what removes the
two remaining write-side existence oracles.

**A third review found the last two, and both are corrected at the root.** Their table is in
`docs/STATE.md` ("The third M2.4 review correction pass"); the design consequences are ADR
0007 decisions 8g and 8h. In one sentence each: a generic outbox writer now proves, in a
`BEFORE INSERT` trigger that runs as the inserting role under its own row-security view and
before the foreign key, the one-event-per-claim index or the `ON CONFLICT` arbiter is
consulted, that the claim it links to is a generic claim it may read in its own tenant --
so a hidden lifecycle claim and an absent UUID are refused with one message, where before one
produced a uniqueness violation and the other a foreign-key violation; and every
lifecycle-derived row -- the three machine tags, the provenance relation, the lifecycle
outbox link -- is now written only by a **dedicated `NOLOGIN` lifecycle writer role** that
owns the two `SECURITY DEFINER` entry points and that nobody, the schema owner included, can
`SET ROLE` to, because the previous `current_user = schema owner` check was passed by the
owner's own DML and by any definer function the owner happened to own. The writer is
recognised from the catalogue (`firmbatch.lifecycle_writer_role()`: the owner of both entry
points, provided it is not the schema owner and cannot log in), installed by the wiring layer
under a temporary `SET`-only membership the administrator grants and revokes, left owning
and holding nothing by a downgrade, and restored exactly by a re-upgrade.

The points below are written as they now stand.

**The one sentence that matters.** A lifecycle is a versioned graph stored in protected,
global tables and sealed the moment it is published, an instance is a tenant-owned row
carrying a state and a monotonic revision, and a move is **one conditional `UPDATE`** whose
predicate carries the tenant, the instance, the machine version, the expected state and the
expected revision — with a `BEFORE UPDATE` trigger underneath it that requires `(old, new)` to
be a declared edge for every writer including the schema owner, and one database call that
writes every artifact the move owes or none of them.

Twelve things worth a reviewer's attention, in descending order of consequence:

1. **Every artifact is written by the call that changes the state, or none is.** The database
   function writes the state change, the history row, the audit event, the idempotency claim
   when one was asked for, and the outbox intent — and it checks `mutation:execute` as well as
   the machine's transition scope, inside the database. Neither Python entry point appends
   anything, so an application role executing arbitrary SQL cannot produce a subset. Creating
   an instance writes an outbox intent too (`<machine>.created`), so the rule has no
   exception. Every lower-level state-changing function is executable by nobody. ADR 0007
   decisions 8c and 8d.
2. **A replay is backed by a transition, not by a machine tag -- and the transition boundary
   is an identity, not the schema owner.** The tag says which machine a framework row belongs
   to; it says nothing about which move a claim records, so a claim carrying a plausible
   `result` would have replayed as a transition that never happened.
   `firmbatch.lifecycle_claim_provenance` is the link: one row per claim, every column a
   composite foreign key into a row the transition wrote, no runtime role holding any
   privilege on it, written only by the transition entry point **executing as the dedicated
   lifecycle writer role that owns it**, refused to every other identity including the
   schema owner's own DML and the schema owner's own definer functions, and refused every
   `UPDATE` and `DELETE`. The same identity check guards the three machine tags and the
   lifecycle outbox link. A replay resolves the whole chain and refuses anything that does
   not agree with itself. ADR 0007 decisions 8f and 8h.
3. **The operation name and the request fingerprint are the database's.** Both were
   parameters; a fingerprint a caller supplies can bind a claim to a request that was never
   made, and one operation name for every machine put a tenant's machines in one key space,
   which made the claim index answer "is this key taken" for rows the read policies hide.
   The operation is now `lifecycle.transition.<machine>.v<version>` from the machine the
   instance pins, and the fingerprint is a SHA-256 over a `jsonb` descriptor of the request
   the call actually executed. **PostgreSQL is the only implementation**, so there is no
   parity to prove. The replay lookup and the lost-race recovery went with them. ADR 0007
   decision 8e.
4. **A definition is a draft until it is published, and sealed once it is — and every rule
   is on the table rather than in the function.** Registration inserts the machine
   unpublished, then its states, then its edges, and publishes as its **last** statement in
   the same transaction. The `BEFORE UPDATE` trigger carries the whole validation, so a
   hand-written `UPDATE` runs exactly what the supported function runs; a `BEFORE INSERT`
   trigger refuses a row that arrives published; the instant is the server's. Publication
   requires every row to carry that transaction's `xmin` — which refuses an `AUTOCOMMIT`
   registration and a definition assembled across transactions — and then checks the
   whole-graph properties no constraint can state. Every consumer requires `published_at`.
   Afterwards nothing may insert, update, delete, unpublish or re-describe it, including the
   owner under ordinary DML. ADR 0007 decisions 4a–4c and 4a-bis.
5. **Publication and the graph serialise on one lock.** Reading the publication column
   without a lock is not deciding on it: an edge could commit between a publication's read
   and its decision, leaving a published machine carrying an edge nothing validated. One
   lockable object — the machine row — taken `FOR UPDATE` by publication before it inspects
   any child and by every state and edge insert before it reads the column, which it then
   re-reads from the row the lock returns. An edge locks the machine, not the states it
   names. State and edge `UPDATE`/`DELETE` are refused outright, so neither can race at
   all. ADR 0007 decision 4d.
6. **No machine is registered, and that is the decision rather than an omission.** Migration
   `0004` seeds nothing. The job lifecycle (target architecture §5.1) and the window-offer
   machine (§12.1) are Milestone 5 and 6 definitions, registered alongside the domain tables
   they describe. Both diagrams establish intent and neither is edge-complete; a registered
   version is immutable; and a graph carrying contractual events is a product decision rather
   than a data structure. `test_a_fresh_database_carries_no_lifecycle_definition` asserts it
   on a fresh disposable database. ADR 0007 decision 2.
7. **The graph is enforced by a trigger, not by the function.** A row-level-security policy's
   `USING` clause sees the old row and its `WITH CHECK` sees the new one, and no policy sees
   both — so "this pair is a declared edge" is not expressible as a policy at all. The
   `BEFORE UPDATE` trigger does see both, and it binds the owner. The function's own edge
   check is a courtesy that gives the caller a good error. ADR 0007 decision 8.
8. **The required capability is data, read from the protected definition.** A machine version
   declares which scope its instances take, and every policy reads it through
   `firmbatch.lifecycle_required_scope()`. The caller never states one. This does **not**
   reopen the closed catalogue: a definition may name only a scope that already exists, and
   M2.4 adds none — there is deliberately no `lifecycle:*` wildcard. ADR 0007 decision 7.
9. **A conflict is one refusal and says nothing else**, and making that true took two fixes
   found by measurement. Two raise sites in plpgsql are two different errors, because psycopg
   renders the `CONTEXT` line number and a line number is a branch identifier; and the Python
   translation drops the database's text for this one error and uses its own constant. ADR
   0007 decision 8b.
10. **The expectation is compared before the graph**, and the reason is a defect the
   unchoreographed race test found: with the graph first, a caller that lost a race and
   re-read after the winner committed was told its transition was *invalid* rather than
   *stale* — and whether it was depended on the interleaving.
11. **Idempotency reuses M2.2's table and rules, and is composed rather than wrapped.** Two
   supported shapes, one database call: the internal form commits one unlinked event, and the
   API form passes **one idempotency key** into the same call, which derives the rest and
   writes the claim, one linked event and the provenance that ties them. It cannot go through `execute_idempotent_mutation`, and the
   reason is forced: the event must be written by the function, an outbox row is append-only
   so the link cannot be added afterwards, and a claim's `result` is not known until the move
   has happened — so claim and event must be written by the same call, claim first, whereas
   the generic primitive claims *after* the mutation it wraps. Everything that carries
   meaning is M2.2's: the same table, the same unique index as the serialisation point, the
   same key validator, the same conflict. The fingerprint is **not**, deliberately -- see point 3.
   **No claim identifier and no operation name is ever caller-supplied**, so there is nothing
   to attach and nothing to validate. The generic primitive is untouched for
   every non-lifecycle mutation; the one change in `db/idempotency.py` is the forwarder
   narrowing above. ADR 0007 decisions 8d and 10.
12. **The two runtime roles are no longer symmetric, and there is a fourth role.**
   Provisioning receives no lifecycle authority of any kind, and `RevisionPlan` grew an
   `application_functions` field to say so. The lifecycle writer -- `NOLOGIN`, no credential,
   no membership, unreachable by `SET ROLE`, owning exactly the two entry points and holding
   the minimum their bodies need -- is created and dropped with the other three, installed by
   `roles.install_lifecycle_writer()` under a temporary `SET`-only membership the bootstrap
   administrator grants and revokes (`bootstrap.wire_roles()` is the one function every
   re-wiring goes through), and its ownership and grant matrix is compared to the plan field
   by field. The ACL sanitiser's two function loops now touch only functions the schema owner
   owns, because the owner cannot revoke on the writer's: `db/roles.py` runs that body as its
   `DO` block, `0004` installs the same body as `firmbatch.sanitize_schema_privileges()` and
   drops it on downgrade, and migration `0003` is untouched history with no diff against
   `main`. ADR 0007 decision 8h.
13. **A generic outbox link is an authorization check made before any constraint.**
   `firmbatch.outbox_events_link_is_authorized()` runs as the inserting role, under its own
   row-security view, and refuses a link to any claim that is absent, hidden, another
   tenant's, not readable by the current authenticated context, or a lifecycle claim's --
   with one message, SQLSTATE `FB006`, translated to `OutboxLinkRefused`. The lifecycle
   writer passes; an authorized generic claim links as before; one already linked still
   meets the one-event-per-claim index by name. ADR 0007 decision 8g.

**Limits carried forward, and one new one:**

- authenticated work remains **writable-primary-only** (M2.3's boundary, unchanged; Milestone
  8 owns read-replica routing);
- the outbox still records intent and a future dispatcher still delivers **at least once**;
- sealing a published definition, the lifecycle tags, the provenance relation and the
  outbox link are enforced by row triggers, so they bind ordinary DML including the owner's
  -- the owner's own `INSERT` and its own definer functions are refused every
  lifecycle-derived write -- but **not** a superuser, and not an owner who first disables or
  redefines a trigger, sets `session_replication_role = replica`, or drops a writer-owned
  function inside its schema (which makes the writer unrecognised and closes every guard).
  Those are deliberate DDL-shaped acts by a role already trusted with the definitions
  themselves, and the trusted-administrator limitation is retained on purpose;
- **moving an instance requires the machine's read capability** as well as its transition
  capability, because the function resolves the instance through the same policy a reader
  uses. That is the capability model read correctly rather than a regression, and it is
  asserted by name;
- a caller that catches the database's refusal in Python keeps **nothing**: the `RAISE` aborts
  back to the last savepoint, so the artifact count is all-or-nothing and the revision is
  unchanged;
- `audit:read` alone no longer reads a lifecycle audit row, its resource identifiers or its
  details. Generic audit reading is unchanged, and the `lifecycle.` action namespace is
  closed to the generic append;
- the request fingerprint is canonical **within a database** and is not a cross-implementation
  identifier. Nothing compares one across databases or persists one as an external contract;
  if PostgreSQL's `jsonb` text form ever changed, stored claims would stop matching and those
  retries would be refused as conflicting reuses rather than replayed;
- the "no chosen identifier" caveat is **closed**: a generic link to a claim this context may
  not read -- hidden, absent, another tenant's, or a lifecycle claim's -- is refused before
  the foreign key and the unique index, with one message, in the plain and the
  `ON CONFLICT` forms;
- installing the lifecycle writer is a two-party act -- the administrator grants the owner a
  `SET`-only membership for one call and revokes it after -- so an operator runbook has to
  do the same: grant, install, revoke. A wiring that skips the writer leaves a database in
  which every lifecycle-derived write is refused, which is the fail-closed direction;
- the verify script's header comment and the `verify` skill now describe the four-role test
  lifecycle, and the two new test modules are registered in `REQUIRED_FILES` -- both edits
  made with the human's explicit approval, narrowly, and neither adds, removes, reorders or
  weakens a gate;
- the bounded-metadata policy is **shared rather than copied**, so a raw-SQL caller whose
  transition details are refused sees a message that says "audit details". The rule is the
  same rule; only the noun is imprecise, in a backstop;
- the concurrency test depends on `pg_stat_activity` showing a blocked backend, so on a
  server where that view is restricted it fails rather than silently degrading.

**Where it stands.** `./scripts/verify-repository.sh` on 2026-09-06, after the third
correction pass and at implementation commit `d91e4f2`: **14 gates passed, 0 failed**, the
layout gate over **97** required files, and the PostgreSQL foundation suite at
**1,746 collected — 1,745 passed, 1 skipped** (the pre-existing local `REPLICATION`
skip), up from 1,315 at M2.3, from 1,512 before the first correction pass, from 1,640
before the second and from 1,721 before the third. `ruff check .` clean, `git diff --check`
clean, one Alembic head, `0004` upgrading, downgrading and re-upgrading from `0001` with
exact role wiring -- the lifecycle writer's included -- at each revision, and **migration
`0003` unchanged**, with no diff against `main`. **All actionable M2.4 review findings are
corrected.** M2.4 is **implemented and tested** and, since `4511f7d`, **merged** — not
deployed, not VERIFIED LIVE, and no evidence artifact has been captured.

Order for the human at the time (all of it is now done; PR #7 merged at `4511f7d`, with the
supplied post-merge transcript reporting **14 gates, 0 failed** and 97 required files):

1. Commit this documentation change — `docs/STATE.md` and `docs/tasks/current.md`, on top of
   implementation commit `d91e4f2`.
2. Push `feat/milestone-2-4-lifecycle-state-machines`.
3. Open the pull request.
4. Wait for CI. Expect the same **14 gates, 0 failed**; the foundation suite's skip count
   differs by cluster shape, because CI's bootstrap administrator is a superuser — see the
   M2.1 CI correction above.
5. Merge after all required checks pass.
6. Optionally, later: capture live evidence with `/record-evidence` under `docs/evidence/m2/`
   to promote Milestone 2 to **VERIFIED LIVE**. Until then the **implemented and tested**
   classification stands, for all four slices. (Still open — see "Open questions carried
   into Milestone 3" above.)

**What is next.** **Milestone 3 under the revision D.1 roadmap**: M3.0 documentation adoption
(merged since at `116b5ee`, PR #8), then M3.1 identity, workspaces, memberships, permissions and credential
issuance with `AUTH-MEMBERSHIP-BOUND-IDENTITY` above as its launch-blocking gate, then the
customer application (M3.2) and a protected AWS staging preview (M3.3, planned and not yet
authorized). The portal it builds is the **customer** application and nothing else; the
**operator capacity agent remains separate operator-side software**, a Phase P binary in the
operator's own cluster, kept apart by §17 invariant 11 and ADR 0008.

**Do not** implement execution, customer billing, jobs, window offers or the portal
opportunistically on top of this. The kernel is the mechanism those milestones express part
of their invariants *with*; it establishes none of them.

---

## Environment note — running the foundation suite

The developer's WSL environment has no Docker, so the suite runs against **native**
PostgreSQL 16 (16.15 observed). CI uses a `postgres:16` service container. Both reach the same
`scripts/verify-repository.sh`.

Environment facts worth writing down, because none is obvious and each cost a debugging
round:

- The admin role needs `CREATEDB` and `CREATEROLE`. Locally a **non-superuser** admin is
  preferable: it cannot accidentally read through the policies while investigating. CI's
  admin is the `postgres` **superuser** of an ephemeral service container, and that is
  accepted — the bootstrap administrator is trusted inside an attested disposable
  cluster. Nothing may require the admin to be a non-superuser; see ADR 0004 section 8f.
- Roles created by the bootstrap **cannot** authenticate over the unix socket under the default
  Debian/Ubuntu `local all all peer` line in `pg_hba.conf`. The bootstrap therefore builds the
  application and provisioning URLs against the server's TCP endpoint (`SHOW port` on loopback)
  even when the admin URL is a socket. Do not "simplify" that to reuse the admin URL host.
- **`FIRMBATCH_TEST_DATABASE_URL` now needs an explicit port**, and an explicit user, host
  and database. A URL that used to work without `&port=5432` is refused: the port it was
  silently using came from `PGPORT` or a compiled-in default. Multi-host failover URLs are
  refused for the same reason.
- The server needs the disposable-cluster marker before anything can be created or dropped
  (`attestation.py --mark`, once per cluster). The local WSL cluster was marked on 2026-09-03
  after confirming it held only `postgres`, `template0`, `template1` and zero user tables.
- `inet_server_port()` returns **NULL** over a unix socket, so it cannot be used to check that
  two URLs point at the same server. The bootstrap records the endpoint at creation and compares
  against that instead. This was a real defect that dropped a live test database.
- **Teardown does not use `DROP DATABASE ... WITH (FORCE)`, and must not be changed to.**
  This note previously said the opposite, and it was wrong in a way worth spelling out.
  `FORCE` needs the privileges of the roles whose backends it terminates, so adopting it
  means *broadening* the role that performs teardown rather than narrowing it — the exact
  move ADR 0004 §8e argues against, and the exact move that would undo the per-run owner
  being a restricted identity. The implementation carries no `FORCE` anywhere, and a test
  asserts that on the source.
- What happens instead, in this order: the per-run owner revalidates the target on its own
  connection (attestation, cluster, endpoint, database name, OID, provenance, live owner),
  then revokes `CONNECT`, then terminates the remaining backends, then drops. Every one of
  those statements runs as the owner, so PostgreSQL's ownership check — evaluated against
  whatever object exists at that instant — is what actually guards them. The owner can
  terminate the runtime roles' backends because it is granted membership in them at
  bootstrap, which is a narrower grant than `FORCE` would require.
- If the connections cannot be disposed of, the database is **left in place and reported**
  as a cleanup failure. That is the designed outcome, not a bug to route around: an
  operator must not widen teardown authority to make cleanup pass. Dispose application
  engines before teardown and the situation does not arise.
- PostgreSQL 16 splits the `SET` option out of `ADMIN` on role membership. A `CREATEROLE`
  creator gets `ADMIN` but not `SET`, so `CREATE DATABASE ... OWNER <role>` and
  `ALTER TABLE ... OWNER TO <role>` both need an explicit
  `GRANT <role> TO CURRENT_USER WITH SET TRUE` first. The bootstrap takes that grant for
  exactly one statement and gives it back in a `finally`.
- Give that grant `INHERIT FALSE, ADMIN FALSE` as well. Granted without them,
  `REVOKE SET OPTION FOR ...` leaves an **inheriting** membership row behind, so the admin
  holds the owner's privileges without being able to name the role. Verified both ways
  round against a real server.
- `pg_has_role(..., 'MEMBER')` is the wrong probe for "can this role become that one". In
  PostgreSQL 16 it stays true for the implicit `ADMIN` grant a `CREATEROLE` creator
  receives, even when `SET ROLE` is refused. `'SET'` (may become it) and `'USAGE'`
  (inherits it) are the two that describe real reach.
- **But `pg_has_role` is the wrong question to ask of the bootstrap administrator at all.**
  It folds in superuser authority, which no revoke changes, so requiring it to be false
  made bootstrap unsatisfiable on CI. Assert the **catalogue** instead —
  `pg_auth_members.set_option` / `.inherit_option`, direct rows and a recursive walk —
  which asks what grant was left behind rather than who could get in. That property is
  true of a superuser and a non-superuser admin alike.
- `ALTER DATABASE ... OWNER TO` requires the *current* owner to hold `CREATEDB`, and
  `ALTER <object> OWNER TO` requires the *incoming* owner to hold `CREATE` on the schema.
  Both are why the ownership tests are shaped the way they are.
- After bootstrap a **non-superuser** admin genuinely cannot drop the disposable database:
  it gets "must be owner of database". A superuser admin can, and that is accepted. Tests
  that deliberately break the normal teardown path use `conftest.drop_disposable_objects`,
  which re-acquires `SET` through the `ADMIN` option a non-superuser still holds. That
  says something true about the threat model rather than working around it
  — the per-run owner is protected from a concurrent process, not from the
  administrator that created it.
- Releasing a savepoint does **not** undo a `SET LOCAL` made inside it; only rolling the
  savepoint back does. That is why tenant switches inside a savepoint are refused outright
  rather than unwound.
- A non-superuser with `CREATEROLE` cannot set a custom GUC as a role or database default
  (`ALTER ROLE ... SET app.tenant_id` is refused), so that particular poisoning route is not
  reachable locally. It is reachable in CI, where the admin is a superuser, and is covered by
  the connect-time clear plus the per-transaction baseline.

---

## Resolved during repository initialization and the R0 audit

### 1 · Ruff findings in existing v0 code — frozen as per-file exceptions

`ruff check .` reported **21 findings, all in pre-existing v0 code**, none introduced by the
repository-initialization pass:

| Rule | Count | Where | Nature |
| --- | --- | --- | --- |
| `E702` multiple statements on one line (semicolon) | 16 | `fb.py:211–251` | The argparse block's deliberate compact style |
| `E401` multiple imports on one line | 3 | `demo/make_requests.py:4`, `fb.py:179`, `tests/test_recovery.py:6` | Deliberate terse imports |
| `E741` ambiguous variable name `l` | 1 | `fb.py:52` | `[json.loads(l) for l in open(a.file)]` |
| `F841` local variable `e` assigned but never used | 1 | `fb.py:172` | `except Exception as e:` where `e` is unused |

Resolved with narrowly scoped `[tool.ruff.lint.per-file-ignores]` in `pyproject.toml`. No
source file was modified, no rule was weakened globally, and nothing was auto-fixed. The
breakdown was re-verified during the R0 audit and is exact.

**These are frozen v0 exceptions, not conventions for new code.** Any file not named in that
table gets the full rule set. Do not extend the list to new modules; when one of these three
files is genuinely rewritten under the roadmap, delete its entry rather than growing it.

### 2 · Claude resolves the `.claude/skills/` symlinks — confirmed

`verify` and `record-evidence` appear in the session skill listing, resolved through the
symlinks. `milestone` is absent from the model-facing listing only because it sets
`disable-model-invocation: true`, which is intended — it is user-triggered. The Claude
`PreToolUse` hook is also confirmed loaded and blocking: an attempted `.env` read was denied
with the `credential-read` rule name intact.

`scripts/verify-repository.sh` now gates the symlinks structurally, so a future replacement
of a link by a copy fails verification rather than drifting silently.

### 3 · Guard hardening — the R0 accident paths

The R0 audit found the guard's enforcement claim false for several forms an aligned agent
plausibly types. Each is now covered by a synthetic test asserting the *invariant*, written
before the fix. `.agents/policy/test_guard.py` is at **247 checks**.

Closed: `git -C` / `git -c` and other valued global options hiding the subcommand; `gh`
equivalents of commit, push, and merge; `env`/`nohup`/`timeout`/`nice`/`stdbuf`/`command`
prefixes; `cd X && ...` changing what a relative path means; unparseable input failing open;
wrapper-depth exhaustion falling through; argparse-abbreviated provider selection
(`--prov verda`) and unprovable provider values; recursive deletion of an ancestor of
`docs/evidence`; source as well as destination operands for `cp`/`mv`/`install`/`ln`/`rsync`;
in-place archivers (`gzip`, `xz`); `sed --in-place`; credential reads through `Read`, `Grep`,
`Glob`, and ordinary shell readers beyond the twelve-name list.

A **second** review round then found eleven more, all of which were ALLOWED by the first
round of hardening and all of which are ordinary shapes. Closed: a multi-line bash block
being classified only by its first command word (`shlex` treats a newline as whitespace,
so `SEPARATORS` containing `\n` was dead code — this was the largest hole); `rm -rf *`
and `rm -rf docs/*`, where a glob operand skipped the evidence-ancestor rule; `mv docs
/tmp/old` and `rsync --delete`; `gh -R o/r pr merge` and `aws --region x ec2
terminate-instances`, which repeated the `git -C` positional bug; `bash --norc -c`, where
a letter-membership test matched the wrong flag and recursed on the wrong token;
`timeout 5m` and `env -u NAME`, where a non-numeric option value stopped prefix
stripping; a leading `(` making a visible `rm` unclassifiable; `git restore <file>`;
`.env.local` and the rest of the `.env.*` family; and an unrecognised tool name carrying
a command or patch, which failed open.

One of those was a **regression this remediation introduced**: adding `pushd` to the
directory tracker without `popd` turned a previously correct deny into an allow, because
the parser then believed the shell was somewhere it had already left. `cd -` and `||`
were wrong for related reasons. All three now have tests.

**Deliberately left open**, and documented as outside the guarantee in `AGENTS.md` and
`.codex/README.md`: interpreters (`python3 -c`, `perl -e`, `awk`), `sudo`, `xargs`,
`busybox`, subshells, command substitution, `eval`, here-documents. Closing these would buy
an argument against an adversary that cannot be won at this layer.

**Deliberately not locked:** the guard does not protect its own configuration. Human approval
before changing `AGENTS.md`, `CLAUDE.md`, `.agents/policy/`, `.claude/settings.json`, or
`.codex/hooks.json` is an `AGENTS.md` rule, not a hook rule.

### 4 · `docs/current-state.md` — resolved in favour of `docs/STATE.md`

The roadmap previously named `docs/current-state.md` as a required artifact while the
repository had `docs/STATE.md`. Resolved by amending the roadmap (six references) to name
`docs/STATE.md`, which is cited by `AGENTS.md`, all three skills, both reviewer sets, the ADR,
and the policy tests. **There is one state document. Do not create a second.**

### 5 · Verification — one entry point

`scripts/verify-repository.sh` replaces three commands run across two working directories.
Twelve gates at R0; **fourteen** since Milestone 2.1 added the runtime import closure check and the PostgreSQL foundation suite. That suite creates and drops one disposable database and three per-run roles, and leaves exactly one role behind on purpose: the persistent `firmbatch_disposable_test_cluster` attestation marker.
`AGENTS.md`, the `verify` skill, and `.github/workflows/ci.yml` all invoke it.

**Milestone 2.2 added no gate**, and that is the correct outcome rather than an omission:
the foundation-suite gate runs the whole `control_plane/tests` directory, so new test
modules are already inside the authoritative path. What M2.2 added is six entries to
`REQUIRED_FILES` (73 now, from 67), so that deleting one of the new canonical files fails
the layout gate instead of quietly shrinking the suite.

### 6 · `.codex/hooks.json` resolves the guard from the repository root

Codex previously invoked the relative `.agents/policy/guard.py`. From any cwd other than
the repository root, `python3` would exit 2 on the missing file — which the Codex adapter
contract reads as *block*, so it failed closed rather than open, but it then blocked
**everything**, silently, with no signal that the guard was not actually running.

It now uses the supported form, which is symmetrical with the Claude side's
`$CLAUDE_PROJECT_DIR`:

```
/usr/bin/python3 "$(git rev-parse --show-toplevel)/.agents/policy/guard.py" --adapter codex
```

Exercised by hand from `docs/evidence/v0/` — a `git push --force` payload blocks with the
rule name at exit 2, and `git status` allows at exit 0 — but **no artifact records this**,
so it is asserted, not VERIFIED. The matcher, `timeout: 10`, `synchronous`, and `blocking`
are unchanged. The absolute
interpreter is the system `/usr/bin/python3` (3.12.3 here) rather than the conda
environment's, which is deliberate: `guard.py` is stdlib-only, and a hook must not depend
on which environment happens to be activated.

**The fix is partial, and the residue is recorded rather than hidden.** `git rev-parse`
is a function of the working directory, so this is narrower than the Claude side's
harness-supplied `$CLAUDE_PROJECT_DIR`. Measured behaviour of the new form:

| Hook cwd | Result |
| --- | --- |
| repository root | blocks correctly, exit 2 |
| any subdirectory (`docs/evidence/v0/`) | blocks correctly, exit 2 — this is what the fix bought |
| outside any work tree, incl. `/home/chams/src` | empty substitution → blocks **everything**, empty stdout, exit 2 |
| `git` not on `PATH` | blocks everything |
| exec'd without a shell | `$(...)` stays literal → blocks everything |
| repository path with spaces or quotes | blocks correctly (the substitution is double-quoted) |

Every degraded case fails **closed**, which is the right direction, but the symptom is a
Codex session where nothing works and nothing says why — and the most likely operator
response to that is to disable the guard. Two things would close it properly: a
Codex-supplied project-directory variable if one exists, or a content gate in
`scripts/verify-repository.sh` asserting the Codex hook command invokes `guard.py` with
`--adapter codex`, matching the gate the Claude side already has. Neither was in the
approved scope of this correction.

Two further limits worth knowing. The degraded cases signal only through the exit code,
with empty stdout; if Codex keys its block on the JSON body rather than the status, they
fail **open** instead — which makes open item 8 below load-bearing for more than
discovery. And `/usr/bin/python3` missing gives exit 127, the canonical
hook-could-not-run signal, which is the state the Claude adapter documents as fail-open.

### 7 · CI — observed externally, evidence artifact pending

`.github/workflows/ci.yml` now calls the verification script instead of duplicating its
commands, adds `permissions: contents: read`, and no longer installs
`requirements-v0-lock.txt` — none of the gates need it (all three are stdlib-only plus ruff),
so it was a failure surface with no coverage benefit, and the lock is incomplete anyway
(`anyio` needs `sniffio`, unpinned).

The fragile part is unchanged and deliberate: `tests/test_recovery.py` does
`from firmbatch.control import db`, so the workflow checks out with `path: firmbatch` and the
script runs the property tests from the **parent** directory. Do not "simplify" it.

Push and pull-request checks passed for PR #2 on 2 September 2026. Because the repository's
VERIFIED LIVE taxonomy requires an immutable artifact under `docs/evidence/`, this remains an
external observation until the run identity and output are captured with the evidence procedure.

---

## Open — verification the tooling still needs

### 8 · Confirm Codex discovers `.codex/hooks.json` and `.codex/agents/*.toml`

Both adapter protocols pass synthetic tests over the full stdin/stdout/exit-code contract,
but nothing has yet observed Codex *loading* these files in a live session. Until it has, the
Codex-side guard is declared, not proven.

To confirm: open a Codex session in this repository and attempt a blocked action, e.g.
`git push --force` or editing `docs/evidence/v0/local-demo-001-report.txt`. Expect a block
carrying the rule name. Capture the result with `/record-evidence` as
`docs/evidence/r0/codex-hook-discovery.txt`. If the hook does not fire, the schema in
`.codex/hooks.json` is wrong and the fix is there — not in `guard.py`, whose protocol is
tested.

Manual protocol check, which does pass today:

```bash
echo '{"tool_name":"shell","input":{"command":"git push --force"}}' \
  | python3 .agents/policy/guard.py --adapter codex; echo "exit=$?"   # expect block, exit=2
```

### 9 · Reviewer tool declarations were not honoured in this session

Two of the three reviewers dispatched during the R0 remediation reported a toolset that
did not match their definition: one had `Bash` available and `Glob` missing, the inverse
of its `tools: Read, Grep, Glob` line. Both used the shell read-only and disclosed it.
Until this is explained, **treat reviewer read-only as an instruction the reviewer
follows, not a constraint the harness imposes**, and do not rely on it to bound a
reviewer's effects. `scripts/verify-repository.sh` gates the declaration, which is all a
static check can do. To settle: dispatch a reviewer and have it report its own toolset.

Related: one reviewer's loaded instructions matched the **pre-remediation** file on disk,
so a definition change does not reach an already-running session. Expect a lag of one
session after editing `.claude/agents/` or `.codex/agents/`.

### 10 · Claude-side fail-open under hook crash or timeout

The adapters now deny on an unexpected exception, and that is covered by tests. What remains
unobserved is the harness end: whether Claude Code proceeds with a tool call when the hook
process exits non-zero with empty stdout, or when the 10s timeout expires. The guard can no
longer produce that state on its own, but a missing `python3` or an unset
`$CLAUDE_PROJECT_DIR` still can. Needs a live hook invocation to settle.

---

## Milestone 1 result and diagnostic backlog

The canonical audit gate was satisfied by `docs/architecture/v0-to-v1-migration-audit.md` and
merged at `6b4f341`. The following experiments remain useful diagnostics against frozen v0.
They are not permission to launch billable capacity, they were not prerequisites for the
Milestone 1 gate, and they are not prerequisites for Milestone 2.

### 11 · Reproduce the real preemption path locally

The v0 baseline claimed three SIGKILLed workers; no artifact shows one. The corrected
`--chaos` procedure in the `verify` skill now isolates the port, waits for readiness, traps
cleanup, and says explicitly that **stdout must be captured**, because the kill is visible
nowhere else. Run it with `--chaos-after` past the scale-down window so the preemption path,
not scale-down, reclaims the shards, and assert `no_heartbeat` appears.

### 12 · Preserve the D1 failing case for the target regression suite

Claim a shard with `lease_secs=1`, `reap()`, re-claim as a second worker, then POST
`/w/results` with `done: true` as the first worker. Assert the shard is not `done` and the
second worker's remaining requests are still issuable. It fails conceptually under v0 and must
become a passing target-attempt test in Milestone 6.

### 13 · Make reconciliation reports reproducible

No script currently generates `local-demo-001-reconciliation.json`. Any new diagnostic run must
commit or capture the exact read-only reconciliation query set without rewriting historical evidence.

### 14 · Align protected agent instructions after explicit approval — **RESOLVED**

`AGENTS.md` and `.agents/skills/milestone/SKILL.md` named the superseded pilot roadmap. With
explicit human approval, both were narrowly corrected during Milestone 2.1:

- `AGENTS.md` now states the authority order — `docs/firmbatch-v1-roadmap.md` canonical,
  `docs/architecture/v1-target-architecture.md` the implementation specification with its §17
  invariants, `docs/STATE.md` for what the code does now, and the pilot roadmap explicitly
  superseded. The working contract's items 1 and 4 now cite the canonical roadmap and §17
  rather than the pilot roadmap's §7 and §5.
- `.agents/skills/milestone/SKILL.md` inspects the canonical milestone and §17 first, and names
  the migration audit as a required input. Its inspect → gap → bounded plan → implementation →
  verification → durable-state workflow and its approval requirement are unchanged.

No guard, hook, reviewer, or other agent-configuration change was made.
