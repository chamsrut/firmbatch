# ADR 0009: identity is protected state; a session is a third actor; a credential is issued from a membership, never exchanged for one

- **Status:** Accepted
- **Date:** 2026-09-07
- **Decision owners:** Firmbatch product owner and maintainers
- **Milestone:** 3.1 — membership-bound identity, sessions and credential issuance, on
  `feat/milestone-3-1-identity-membership` from `main` at `116b5ee`
- **Related:** `docs/firmbatch-v1-roadmap.md` Milestone 3.1 and
  `AUTH-MEMBERSHIP-BOUND-IDENTITY`; `docs/architecture/v1-target-architecture.md` §17
  invariants 1–11; ADR 0004 (tenant isolation), ADR 0005 (idempotency and outbox), ADR
  0006 (authenticated context, authorization, audit and secrets), ADR 0007 (lifecycle
  kernel and the dedicated writer), ADR 0008 (staged delivery: M3.2 owns the UI, M3.3
  owns staging)

## Context

At Milestone 2.4 a credential *is* the membership. `firmbatch.auth_bindings` names one
tenant per binding, `firmbatch.bind_authenticated_context` will establish a context for
that tenant and no other, and the only way a binding comes to exist is the provisioning
path or an existing credential holding `credential:manage`. There are no accounts, no
passwords, no sessions, no memberships and no invitations. That is sufficient while
credentials are provisioned out of band and no person signs in; it stops being sufficient
the moment a person can sign in and choose a workspace, because something has to decide
which workspaces that person may choose from, and nothing does.

The roadmap's `AUTH-MEMBERSHIP-BOUND-IDENTITY` gate says what must become true: an
authenticated customer identity is **proven to be an active member of the selected
workspace and tenant** before a browser session is bound to it or an API credential is
issued for it; the runtime does not hold the authority to mint a credential for an
arbitrary account, tenant, workspace, membership or scope; browser sessions and API
credentials are distinct credential types that are never accepted at one another's
boundary and never converted into one another; and every Milestone 2 guarantee —
authenticated context, ownership, ACL sanitation, `FORCE` row security, idempotency,
audit, outbox and lifecycle provenance — holds unchanged.

Three constraints shaped the design more than any other. First, migrations `0001`–`0004`
are history and are not edited; everything here is a forward migration `0005`. Second, the
ordinary application role must be unable to reach the boundary by any route, raw SQL
included: a check that lives only in Python is a check a compromised runtime does not make.
Third, the customer application is Milestone 3.2's and the hosted environment is Milestone
3.3's, so this milestone ends at a native HTTP boundary with no HTML, no provider and no
deployment.

## Decision

### 1. The identity plane is protected state, reached only through definer functions

Nine tables — `accounts`, `account_passwords`, `account_tokens`, `memberships`,
`workspace_directory`, `browser_sessions`, `workspace_invitations`,
`account_idempotency_records`, and the unlogged `identity_transaction_context` — are
created with **no grant to any runtime role**, no row-security policy, and no column
privilege, exactly as `auth_bindings` and the lifecycle definition tables are (ADR 0006
decision 3, ADR 0007 decision 3). They are read and written by `SECURITY DEFINER` functions
owned by the schema owner, `search_path` pinned to `pg_catalog`, every reference
schema-qualified, no dynamic SQL, `EXECUTE` revoked from `PUBLIC`, and granted to the
**application role alone**: the provisioning role and the lifecycle writer receive
nothing. `db/roles.py` wires them as a fourth revision plan; the ACL sanitiser installed
by `0004` strips any stray grant on them, and the principal check at connect time refuses
a runtime connection that holds one. The existing protected-state tests walk the new tables
through the same parametrised assertions as the old ones.

**No fifth role.** Milestone 2.4 introduced a dedicated `NOLOGIN` lifecycle writer because
the property it needed — "this row was written by the transition entry point and by
nothing else, the schema owner's own DML included" — is a statement about *authorship*
that only a distinct executing identity can make (ADR 0007 decision 8h). The identity plane
needs no such statement. Its property is the simpler one the registry already has: no
runtime role can touch the rows at all, and the functions that can are the owner's. A fifth
role would add a `SET ROLE` surface and a wiring step without adding a property. If a later
milestone needs identity rows whose authorship must be provable against the owner, that is
the moment to add one, by the 0004 pattern.

### 2. A browser session is a third actor kind, and the context it acquires is derived every time

`firmbatch.auth_transaction_context` gains no column. A bound session establishes a
Milestone 2.3 context through the same owner-only `auth_context_begin` the credential path
uses, with `actor_kind = 'session'`, `principal_id` = the account, `binding_id` NULL, and
the scope array equal to the membership's role permissions. The two actor constraints on
`audit_events` and `lifecycle_transitions` are widened by exactly one disjunct — a session
actor has a principal and no binding — and restored by the downgrade. Every policy, every
accessor and every lifecycle function is unchanged: a session context is a context.

The binding on the session row (`browser_sessions.workspace_id`, `tenant_id`,
`membership_id`) is a **cache of an earlier authorization decision, and the decision is
remade at every bind** against the membership as it is now. `bind_session_context` in
workspace mode re-reads the membership by id, tenant, workspace and account with
`revoked_at IS NULL`; a membership that is gone leaves the session unbound and establishes
no tenant context. Revocation is also **structural**: a `BEFORE UPDATE OR DELETE` trigger
on `memberships`, `SECURITY DEFINER` so it holds whoever fires it, revokes every API
credential the membership issued and unbinds every session bound through it in the
revoking statement's own sequence, refuses un-revocation and re-roling of a revoked row,
and refuses any change to the columns that say what the membership *is*. The next bind of
either credential type observes the revocation on the terms ADR 0006 decision 4 already
states for the credential path.

A session's own transaction context is a second unlogged relation,
`identity_transaction_context`, keyed like the first (backend pid and transaction id) and
written only by `identity_context_write`, executable by nobody. It carries the session, the
account, the workspace, the membership, the role and whether the CSRF secret was verified.
`identity_require_session(mode, csrf)` is the one precondition every identity function
calls, and it refuses the wrong mode, an unverified CSRF token where a mutation needs one,
and a transaction that bound nothing, with the specific `FB013` — a caller-side programming
error, not a refusal about a target.

### 3. A workspace is a tenant, and its creation provisions one

At this milestone a workspace and a tenant are one-to-one: `create_workspace` generates a
tenant row with a generated slug (`ws-<20 hex>`, never the customer's), the workspace, and
the creator's owner membership, in one function. It runs in **account mode** — the session
has selected no workspace yet — and establishes the new tenant's context itself, with the
owner's permissions plus `tenant:provision` for the three inserts that need it, before
writing the claim, the outbox event and the audit row in that tenant. Then it **narrows**
the context to the owner's own permissions before control returns (decision 7).

The roadmap's later shape — several workspaces sharing a tenant, or a tenant that is a
billing entity above its workspaces — is not foreclosed: the schema carries `tenant_id`
and `workspace_id` separately on every row that has either, and nothing derives one from
the other except this creation path.

### 4. Roles are closed, permissions are scope-like, and three of them are session-only

Four roles — `viewer`, `member`, `admin`, `owner` — with a permission table written once in
`security/permissions.py`, once in migration `0005`, and once as `firmbatch.membership_role_scopes()`,
pinned to each other by test. A viewer reads (`membership:read`, `tenant:read`,
`workspace:read`); a member also writes and issues (`credential:issue`,
`mutation:execute`, `workspace:write`); an admin and an owner also read the trail and
manage the membership (`audit:read`, `membership:manage`). Owner and admin differ by
**rule**, not by scope: only an owner may remove, demote or promote an owner, and the last
active owner cannot be removed or demoted. Those rules are enforced by the functions that
read the target membership under the workspace row lock.

`credential:issue`, `membership:read` and `membership:manage` are **not Milestone 2.3
scopes**: they are not in the closed catalogue, no `auth_bindings` row can carry them, and
an API credential can never hold them. **No role grants `credential:manage`.** The Milestone
2.3 minter `register_auth_binding` and revoker `revoke_auth_binding` therefore refuse every
session, and the only way a session produces a credential is decision 5.

### 5. A credential is issued from a membership by a distinct, audited operation — it is not a token exchange

`issue_api_credential` runs in workspace mode, CSRF-verified, and requires
`credential:issue`. It **re-reads the membership** by id, tenant, workspace and account and
refuses a revoked one; bounds the requested scopes by the closed catalogue, by the issuable
subset (the delegable Milestone 2.3 scopes minus `credential:manage`) and by the member's
**own** effective permissions as the membership is now — not as the session cached them;
and mints a fresh 244-bit secret with the `fbk_` prefix through the same construction
`register_auth_binding` uses. The binding it writes carries `membership_id` and
`workspace_id`, which is what the revocation cascade acts on, and `principal_id` = the
account, which is what the audit trail records. The Python wrapper checks the same scope
rule first so a caller gets it by name; the database checks it again so raw SQL gets it too.

Rotation is an **atomic cutover**: the old binding is locked `FOR UPDATE`, a new one is
minted with the same scopes, label and membership and `rotated_from_id` set, and the old
one is revoked in the same statement sequence; the old secret stops working in the
transaction the new one starts. Only the member whose membership issued a credential may
rotate it, because the rotated credential authenticates as that member; a manager may
revoke any credential in the workspace and rotate none but its own. It rotates a **live**
credential only — revoked and expired are one state, and an expired one is refused with the
neutral refusal (see "Revoked and expired are one credential state" below). `record_api_credential_use`
stamps `last_used_at` from a credential-authenticated context and nothing else.
`bind_authenticated_context` is **not modified**: a credential issued here authenticates
exactly as an out-of-band one does.

**The two credential types are distinct by construction.** A session secret is `fbs_…`, a
CSRF secret `fbc_…`, an API credential `fbk_…`, and each boundary refuses the other's shape
before it is sent anywhere; even were the shapes forged, `bind_session_context` looks a
digest up in `browser_sessions` and `bind_authenticated_context` in `auth_bindings`, so
each fails the other's lookup. There is no function that takes a session and returns a
credential, or the reverse; there is only issuance, which mints.

### 6. Secrets: five kinds, one construction, stored only as digests; passwords by Argon2id

Session, CSRF, email-verification, account-recovery and invitation secrets share the
bearer credential's construction — two `gen_random_uuid()` values, 244 bits, 43 URL-safe
characters — behind a type letter that makes each recognisable and none acceptable where
another belongs. Each is minted inside PostgreSQL, returned once in the result row of the
call that minted it, and stored **only** as its SHA-256 fingerprint. The secret-shape
recogniser gains one seventh pattern (`fb[cirsv]_…`) so that the metadata policy, the
label checks and the Python `looks_like_secret` all refuse them in any field; migration
`0005` replaces `firmbatch.secret_shape` with the same template over seven shapes and
restores `0003`'s text — asserted byte-for-byte — on downgrade. Nothing returns a
fingerprint, no listing has a column that could hold one, and tests render every row of
every table and every audit, outbox and exception chain to assert absence.

Passwords are hashed with **Argon2id** through `argon2-cffi` (`t=3, m=64 MiB, p=4`,
version 19), nowhere else: the policy — 12 to 256 UTF-8 bytes, a `Secret` and not a string —
lives in `security/passwords.py`, and the stored form is bounded by a check constraint so
that a writer reaching the table another way cannot store a plaintext or a weaker hash. A
login that finds no account verifies against a dummy hash so the two outcomes cost the
same. **Verification runs in the application process**, which is a trust statement made
plainly: `login_lookup` hands the application role one account's hash for one address, so
a compromised runtime could harvest Argon2id hashes for addresses it names. That is the
limitation of hashing outside the database — PostgreSQL 16's `pgcrypto` has no memory-hard
algorithm, and moving verification into the database would trade a harvestable hash for a
weaker one. The hash is the only thing that crosses; the password never does, and the
mitigation is the algorithm's cost.

### 7. Idempotency composes with Milestone 2.2, and the context is narrowed, never widened

Every workspace-mode mutation with a key writes one Milestone 2.2 claim and one linked
outbox event through `identity_claim`, in the mutation's own statement sequence, after
`identity_replay` under the workspace row lock; a replay returns the winner's result and,
for issuance, rotation and invitation, **no secret** — the secret was displayed once, when
it was minted. Account-mode operations that create a tenant context (workspace creation,
invitation acceptance) are keyed on `account_idempotency_records`, because before they run
there is no tenant to claim under; the lost race is a unique violation inside a
subtransaction whose handler returns the winner's stored result.

Two operations write framework rows under an authority the resulting membership does not
hold: creating a workspace provisions a tenant, and accepting an invitation records a claim
and an event for a membership whose role may be read-only. Those writes are the function's
own — they are what the operation is — and the row-security policies still evaluate
against the transaction's context, so the context is established with the extra capability
for exactly those statements and then **narrowed** by `identity_context_narrow`, executable
by nobody, whose predicate requires the new scope set to be contained by the old one and
the transaction id to be this transaction's. The tenant, the principal and the actor kind
are untouched — a transaction still binds one tenant once — and what the caller's
transaction holds after the function returns is the member's own permissions and nothing
more. Without it, a viewer that accepted an invitation could append arbitrary outbox events
with raw SQL for the rest of the transaction.

### 8. One neutral refusal, from one raise site per function

Absent, hidden, in another tenant, revoked, expired, not addressed to this account, and
not-yet-bound are **one** answer — `FB010`, one message, raised from a single site per
function so that PostgreSQL's line-numbered `CONTEXT` cannot tell them apart. The Python
translator drops the database text and carries its own explanation. `FB011` is a conflict
inside the caller's own visible scope that is safe to name (the last owner, an existing
member, a pending invitation), `FB012` an idempotency key reused for a different request,
`FB013` a context precondition. Login answers a wrong password and an unknown address with
one outcome; verification and recovery requests answer a known and an unknown address with
one acceptance; invitation acceptance answers the wrong recipient, an expired, revoked or
reused invitation and a forged secret alike.

### 9. The HTTP boundary: Starlette, two boundaries, and the browser rules the design names

The native v1 API is a thin ASGI application on **Starlette** (`control_plane/api/`),
served by uvicorn in the reviewable local form only. Starlette rather than a larger
framework because the boundary needs routing, a test client, and CORS middleware, and
nothing else: no schema generation, no dependency injection, no serialization layer that
would render a field this design keeps out of responses. Every handler bounds and parses
its input, authenticates at exactly one of two boundaries, runs one transaction through the
`db/` wrappers, and renders identifiers and never a secret it did not just mint.

**Cookies.** The session cookie `fb_session` is host-only (no `Domain`), `Path=/`,
`HttpOnly`, `Secure` (refusable only with `FIRMBATCH_ENV=test`), `SameSite=Strict`:
`app.firmbatch.com` and `api.firmbatch.com` are one site, so the application's credentialed
requests carry it and no other site's do. **CSRF.** Every cookie-authenticated mutation must
carry the session's own CSRF secret in `X-CSRF-Token` — verified inside the database
against the session's fingerprint — and an `Origin` on the explicit allow-list; login
requires the origin too. **CORS** is that same allow-list with credentials; a wildcard is
refused by configuration, and an unlisted origin receives no allow-origin header. **Two
boundaries.** A browser route that receives an `Authorization` header is refused before
either credential is read; a bearer route that receives the session cookie is refused the
same way; the bearer boundary accepts only a well-formed `fbk_` value. Authentication
precedes parsing: an unauthenticated request learns nothing about a route's body or header
requirements. The database's neutral bind refusal becomes `401` when the session itself is
refused and `412 workspace_required` when a valid session has selected no workspace and the
route needs one — told apart by binding the same session again in account mode, which
succeeds only in the second case and discloses nothing the caller did not already hold.
Bodies are bounded (16 KiB) before they are parsed; error bodies are `{"error": <code>}`
and nothing else; the log carries method, route template, status and duration.

**Email.** `api/email.py` is the delivery interface: an `OutboundEmail` that carries at most
one `Secret` and never renders it, a production adapter that **raises** because no provider
is configured at this milestone, and a capture adapter that refuses to exist outside the
`test` environment. No provider is named, configured or contacted; no verification,
recovery or invitation secret is returned by any HTTP response.

### 10. What is deliberately not here

- **The customer application** (M3.2): no HTML, no template, no portal; the API is what it
  will call. No password change while signed in — recovery covers it, and a change flow
  needs the re-authentication design M3.2 owns.
- **Deployment, TLS, real secrets delivery and the separated issuer credential** (M3.3):
  the issuing authority here is the owner-owned definer function, which the runtime cannot
  impersonate because it cannot read, write or grant the tables behind it; splitting the
  process that *calls* it from the process that serves requests is a deployment shape and
  M3.3's to build and qualify on managed PostgreSQL.
- **A real email provider**, rate limiting, request metrics and observability (M8 controls,
  a subset pulled forward by M3.3).
- **Account deletion and archival.** A membership is revoked, never deleted; an account is
  never deleted. Retention is a decision no milestone has taken.
- **Account-level events in a tenant audit trail.** Signup, verification, recovery and
  session revocation have no tenant; they leave rows in `account_tokens` and
  `browser_sessions` and no `audit_events` row. Workspace binding, membership, invitation
  and credential operations are audited in the workspace's tenant as `session` actors.
- **More than one workspace per tenant**, and any tenant that is not a workspace.

## Consequences

- The runtime application role holds no authority to mint a credential for an arbitrary
  account, tenant, workspace, membership or scope. It can call `issue_api_credential`,
  which mints only for the membership behind a CSRF-verified, workspace-bound session, only
  within that membership's re-read permissions, and only inside the issuable subset. Raw
  SQL as the runtime role cannot insert, update or delete a binding, membership or session,
  cannot call an internal function, cannot widen or re-point a context, and cannot forge a
  fingerprint it cannot read. The four gate cases are each a named test.
- Migrations `0001`–`0004` are unchanged. `0005` upgrades, downgrades to a catalogue equal to
  an independent downgrade, and re-upgrades; the role wiring reconciles at every supported
  revision. The one live object of an earlier migration it changes — `secret_shape` — is
  replaced by the same template and restored to `0003`'s exact text on downgrade.
- Three dependencies join the runtime set: `argon2-cffi`, `starlette`, `uvicorn`; `httpx`
  joins the development set for the test client. Both lock files were regenerated with the
  documented `pip-compile --generate-hashes` process. Starlette 1.6 prefers the `httpx2`
  client for its test client and emits a deprecation warning under `httpx` 0.28; the
  warning is informational and the pinned pair works, and moving the development pin is a
  later lock regeneration, not a runtime change.
- A viewer holds no `mutation:execute` and therefore cannot claim a key or append an event
  through the Milestone 2.2 primitive in its own transaction; the only framework rows
  written on a viewer's behalf are the ones identity functions write under the narrowed
  context described in decision 7.
- The hash-harvest limitation in decision 6 is recorded rather than solved. It is a
  property of any design that verifies passwords outside the database, and the mitigation
  is Argon2id's cost and the runtime's protection, which M3.3 and M8 own.

## Rejected alternatives

- **Sessions as signed tokens (JWT or similar), verified without a database read.**
  Rejected: revocation and membership re-derivation are the whole property, and a token
  that is valid until it expires cannot observe either on the terms ADR 0006 states.
- **Sessions held in the application process or a cache.** Rejected: the session would then
  be state the runtime role could read and forge, and the bind could not be enforced at the
  PostgreSQL boundary.
- **Membership permissions as Milestone 2.3 scopes on a synthetic binding per session.**
  Rejected: a session would then be a binding, the registry would hold a row per login,
  `credential:manage` semantics would leak into sessions, and the two credential types
  would be one table apart rather than distinct by construction.
- **A fifth `NOLOGIN` role owning the identity functions**, by the 0004 pattern. Rejected
  for this milestone (decision 1): no authorship property needs it, and it would add a
  `SET ROLE` surface and a wiring step for nothing.
- **Verifying passwords inside PostgreSQL.** Rejected: `pgcrypto` on PostgreSQL 16 offers
  no memory-hard algorithm, so the trade would be a harvestable Argon2id hash for a weaker
  one.
- **A `SameSite=None` cookie with a `Domain` attribute** to serve a future third-party
  embedding. Rejected: the two hosts are one site and the design's whole CSRF posture rests
  on `Strict`; embedding is not a requirement.
- **FastAPI.** Rejected: its schema and validation layers would add an attack surface and a
  rendering path for exactly the fields this boundary keeps out of responses, without
  adding a property the four hand-written parsers do not already have.

## Security corrections (Codex M3.1 diff scan)

A Codex security diff scan of the uncommitted M3.1 work raised ten findings and two review
gaps. All are corrected in the same branch. The corrections that change the design recorded
above, rather than merely hardening an implementation detail, are set out here; the rest are
implementation fixes described in `docs/STATE.md`.

### A distinct authenticator principal: the trusted-issuer boundary, advanced from M3.3

Decision 10 above deferred "the separated issuer credential" to M3.3, on the reasoning that
the issuing authority is an owner-owned definer function the runtime cannot impersonate.
The scan showed that reasoning is not sufficient for the **pre-authentication** functions.
`login_lookup` writes a login challenge before the password is verified (verification is in
the process, decision 6), and `open_browser_session` mints a session from that challenge; a
process holding the ordinary application role could therefore call the two in one
transaction and open a session for any active account without proving the password. The
same shape let the application role call `request_account_recovery`, receive the raw
recovery secret in the result row, and immediately call `complete_account_recovery` to
replace a victim's password — no mailbox access required.

The database cannot close this by itself: it has no Argon2, so it cannot confirm the
password match, and the login challenge is legitimate state some principal must be trusted
to write only after a successful verification. The correction is to make that principal
**distinct from the ordinary application role**. A fifth login role, the **authenticator**,
holds `EXECUTE` on exactly the pre-authentication functions — `signup_account`,
`request_email_verification`, `verify_account_email`, `login_lookup`,
`open_browser_session`, `request_account_recovery`, `account_recovery_token_valid`,
`complete_account_recovery` — and the application role holds none of them. Raw SQL as the
application role can no longer harvest a stored hash, mint a victim session, obtain and
consume a recovery secret, or issue and consume a mailbox-verification token. (The three
mailbox-verification functions were moved here by the second correction pass below; the
first pass moved the other five.)

**Its grant is the least that reaches those eight, and is derived from the call graph.**
Besides the eight it holds `EXECUTE` on exactly two read-side accessors:
`auth_tenant_id`, which `db/engine.transaction()` calls to assert a transaction inherited no
context, and `auth_context`, which that invoker-rights accessor calls as the caller. Ten
functions, plus `USAGE` on the schema, and no table or column privilege anywhere. It is
deliberately **not** given the common runtime set the application and provisioning roles
hold: that tuple also carries `bind_authenticated_context`, `register_auth_binding`,
`revoke_auth_binding` and `append_audit_event`, none of which any authenticator call path
reaches, and granting them would let the trusted-issuer principal establish a bearer context
and reach the untied credential minter — the opposite of what this role exists to be. It is
a member of no role, so nothing is reachable through `SET ROLE` either.
`tests/test_identity_protection.py` asserts the whole of that from the catalogue, function
by function — with the ten named in the assertion rather than only counted — and separately
drives the pre-authentication flows to prove the ten are also *enough*.

Password verification still runs in the process, so a compromised
**authenticator** could still skip it; but the authenticator is a narrow principal used only
by the pre-authentication routes, not the broad runtime that serves every workspace,
membership and credential request. This is the "distinct narrowly held authenticator
principal" the finding's remediation named, and it advances the M3.3 issuer-separation
boundary into the database layer now; separating the *process* that holds the authenticator
credential from the request-serving process remains M3.3's deployment task.

This reverses the "no fifth role" choice in decision 1 **for the pre-authentication surface
only**. The reasoning there — that no authorship property needed a distinct executing
identity — held for the identity tables (still true; they remain protected by absent
grants). It did not anticipate that the *grant* on the pre-authentication functions is
itself the boundary: confining those functions to a principal the runtime is not is a
privilege fact, not an authorship one. The authenticator is a login role, not a `NOLOGIN`
one, because the process must connect as it to run the in-process password verification.

### Account recovery evicts credentials through a durable security epoch

Decision 5 did not say what account recovery does to API credentials the account had
issued. The scan showed recovery revoked browser sessions but left those credentials
active, so an attacker who issued one before the victim recovered kept tenant access. A
best-effort sweep of currently-visible rows would still miss a credential racing the
recovery. The correction adds an integer `security_epoch` to `accounts`, stamps each
membership-bound credential with the account's epoch at issue and rotation
(`auth_bindings.principal_epoch`), and advances the epoch in `complete_account_recovery`.
`bind_authenticated_context` — the one M2.3 function this revision now replaces, restored
byte-for-byte on downgrade — refuses a membership-bound credential whose stamped epoch no
longer equals the account's current one, and also rechecks that the credential's membership
is still active. A credential issued before the recovery, including one committed in a
transaction that raced it, therefore carries a stale epoch and does not authenticate.

### Shared workspace serialization for issuance and rotation

Decision 5 serialized membership mutations on the workspace row. Issuance read the
membership *before* taking that lock, and rotation never took it, so either could commit a
credential after a concurrent removal or demotion. Both now take the workspace lock before
reading membership and re-read the membership (and the caller's own role) under it, so
issuance, rotation, removal and demotion share one lock and one order. The owner-only rules
in `change_membership_role`, `remove_membership` and `create_invitation` likewise re-read
the caller's current role under the lock, so a concurrently demoted owner cannot act on the
authority its session cached.

### Bounded memory-hard work, streamed request bodies, and reclaimable pending state

Unauthenticated Argon2 work (login, signup, recovery completion) runs behind a bounded
admission gate that returns a deterministic 503 under saturation without disclosing account
existence; the recovery path rejects malformed and non-existent tokens before hashing; the
HTTP boundary enforces its body limit while consuming the ASGI stream rather than trusting
Content-Length; and `purge_expired_unverified_accounts` gives an explicit, owner-run expiry
control against unbounded unverified-account growth. These are edge/observability controls
M3.3 and M8 own in full; the application-layer floor is present now and is additive to,
never a substitute for, an eventual ingress limit.

### What remains M3.3's

The authenticator credential still reaches the same process that serves requests in the
local reviewable form; splitting the process that calls the trusted-issuer functions from
the one that serves the public routes is M3.3's, as is a real edge rate limit and TLS. The
in-process password verification, and therefore the residual trust in the authenticator
principal, is the limitation decision 6 records, now confined to a narrow principal.

## Second review correction pass (GPT-5.6 Sol review of M3.1)

A second adversarial review of the same uncommitted branch raised six findings. All are
corrected in the branch, and the four that change what this ADR decided — rather than
hardening an implementation detail — are recorded here. The theme running through them is
one the first pass had already begun and had not finished: **a decision made once is not a
decision that still holds.** A challenge written before a password is verified, a scope set
cached at bind time, and a lifecycle state derived from one of its two inputs are all
answers that were true when they were computed and may not be true when they are used.

### 1. A login challenge is bound to the password version it was answered against

Decision 6 puts the password comparison in the process and bounds the trust with the login
challenge: `login_lookup` records **which** account was challenged, and `open_browser_session`
opens a session for that account and no other. The review showed the bound is on *identity*
and not on *time*. Password verification is memory-hard and takes hundreds of milliseconds;
a recovery can commit inside that window. The old password then verifies against a hash the
account no longer has, and the session opens **after** `complete_account_recovery` revoked
every session it could see — so the recovery leaves behind exactly the access it exists to
remove, and there is nothing left to revoke it.

The challenge now carries the account's **security version** as well as its identity.
`accounts.security_epoch` is that version: after signup, the only statement sequence that
ever replaces `account_passwords.password_hash` is `complete_account_recovery`, and it
advances the epoch in the same sequence. `login_lookup` reads the hash and the epoch in one
statement, so the pair is coherent. `open_browser_session` then takes `SELECT … FOR UPDATE`
on the account row — a lock that conflicts with the row-exclusive lock the recovery's own
`UPDATE accounts` takes — re-reads the epoch under it, refuses on a mismatch with the
neutral refusal, and **holds the lock to commit**, so no recovery can slip between the check
and the `INSERT`.

That closes both orderings, and by different halves of the same mechanism. If the recovery
commits first, the comparison fails and no session is opened. If the session opening takes
the lock first, the recovery *waits* for it, and its later `UPDATE browser_sessions` takes a
fresh `READ COMMITTED` snapshot containing the session just committed — which it revokes.
`tests/test_identity_concurrency.py` drives both.

### 2. Mailbox verification is a mailbox proof, and its authority is the authenticator's

The first pass moved recovery behind the authenticator on the reasoning that a role which
can request *and* consume a mailbox-proof secret needs no mailbox. The review pointed out
that mailbox **verification** is the same shape and had been left with the application role:
`signup_account` and `request_email_verification` mint a verification secret and return it in
the result row, and `verify_account_email` consumes one and flips the account to `active`. A
role holding all three registers an address it does not control, reads the secret out of its
own result, consumes it, and holds a verified account — which then satisfies the
verified-account precondition on workspace creation and invitation acceptance.

All three move to the authenticator, and the application role holds none of them. The
authenticator's inventory is therefore eight pre-authentication functions plus the two
read-side accessors its transaction preamble needs; the exhaustive privilege test names all
ten rather than counting them. The HTTP boundary runs signup, verification request and
verification completion on the trusted engine. A raw verification secret is handed to the
configured email adapter and to nothing else: not a response body, not a log line, not an
audit or outbox attribute, not an exception chain, and not any result the application role
can obtain — which it now cannot, because the functions that produce one are not its to call.

### 3. One membership revalidation, in the database, for every workspace operation

Decision 2 says membership is derived at the boundary every time, and decision 5 says
issuance re-reads it. The first correction pass added a re-read under the workspace lock to
five functions. The review found the remaining ones still deciding from
`auth_has_scope(...)`, which reads the **transaction context the bind cached** — so
`rename_workspace`, `revoke_invitation`, the manager-only invitation listing,
`revoke_api_credential`, the credential listing (including its manager *reach*) and the
credential-history route all acted on authority the account might no longer hold. Re-reading
the membership in each function separately is how three of them came to skip it.

There is now one mechanism, `firmbatch.workspace_membership_authority(p_scope, p_lock)`, and
every workspace-mode function goes through it — as does the HTTP boundary, for the one
disclosure it performs itself. In order: the transaction must carry a workspace-mode session
whose tenant is the authenticated tenant; the serialisation point is taken; the tenant, the
workspace, the account, the membership's identity, its active status and the account's
active status are re-read under it as one row; and the **current** role's permission set must
contain the requested permission. It returns the caller's session row with the freshly read
role, and callers run it **before** the replay lookup, so a demoted caller cannot replay its
way to a result it may no longer ask for.

The serialisation point differs by intent, and the difference is not cosmetic. A **mutator**
takes the workspace row `FOR UPDATE` — the lock every other mutation takes, in one order. A
**reader** takes its own membership row `FOR SHARE` instead, for two reasons: `workspaces` is
under forced row security whose `UPDATE` policy requires `workspace:write`, and PostgreSQL
evaluates the `UPDATE` policies for any `SELECT … FOR SHARE`/`FOR UPDATE`, so a viewer would
find no row to lock and be refused a listing it is entitled to; and a reader's decision
depends on its own authority alone, so its own membership is the precise thing to hold still
against the demotion or removal that would invalidate the disclosure. A caller that will
mutate must take the `FOR UPDATE` form first: taking the share form and upgrading later is
the one way two transactions deadlock here, and no call path in this revision does it.

### 4. Revoked and expired are one credential state, and rotation does not revive one

Decision 5 describes rotation as an atomic cutover and says nothing about an **expired**
predecessor. `bind_authenticated_context` has always treated unknown, revoked and expired as
one refusal, but two surfaces disagreed with it: the credential listing derived "active" from
`revoked_at` alone, so an elapsed credential the bearer boundary already refuses was shown as
usable; and rotation, on finding the inherited expiry elapsed, replaced it with `NULL` — which
is not an expiry that has passed but an expiry that never comes, so a dying credential was
promoted into a permanent one.

The lifecycle state is now computed by PostgreSQL, in `workspace_api_credentials()`, against
the same `clock_timestamp()` the bearer boundary uses: active is *neither revoked nor
expired*, and nothing derives it from an application clock. And **an expired credential is
refused rotation**, with the same neutral refusal a revoked one gets. That is the narrowest
fail-closed reading of decision 5 and the reason is structural rather than stylistic:
rotation carries the predecessor's scope set forward **without rebounding it by the member's
current role**, so admitting a dead credential would revive a scope set the member may no
longer hold — and it would do so on a path that a manager cannot audit as an issuance. The
alternative considered, admitting an expired credential when the caller supplies a valid
future expiry, was rejected for that reason: the expiry is not the part that makes the
operation safe. Re-issuance is the supported way back, and it is the operation that rebounds
the scopes against the membership as it is now. The elapsed-expiry guard is kept in the
rotation body as a **refusal** rather than deleted, so a future edit that admits an elapsed
predecessor cannot silently reintroduce the promotion to `NULL`.

### 5. Two HTTP corrections, both about ordering (decision 9)

**Authenticate the route, then interpret the body.** Decision 9's neutral-error rule was
undone by where parsing happened: the boundary read *and parsed* every body before the
handler ran, so an unauthenticated request with broken JSON or an unsupported media type got
`400` or `415` — which says the boundary got as far as parsing what the sender sent, and lets
absent, invalid and mixed credentials be told apart by the shape of the refusal. The bounded
**stream read** still comes first, because refusing after buffering would mean the buffer had
already happened; everything that interprets the bytes moved behind the credential. Absent,
malformed, unknown and mixed credentials are one `401` whatever the body is.

**A wrong CSRF token is not a missing workspace.** The database answers a wrong CSRF secret
with the same neutral refusal it gives an unknown session, so the boundary re-binds in
account mode to tell "refused" from "no workspace selected". That retry dropped the CSRF
secret, making it a strictly easier question than the one that had just failed — so a forged
mutation came back as `412 workspace_required`, telling its sender the cookie was good and
only a workspace was missing. The retry now carries the proof the request carried: an
incorrect token is `401`, and a genuinely unbound session presenting its own token still gets
the `412` it needs.

**`keep_current` is a JSON Boolean, strictly.** `bool(body.get("keep_current", False))`
accepted every JSON type and meant something by each — `"false"` is truthy, `0` and `null`
are falsy — on the field that decides whether the caller's own session survives. Only `true`
and `false` are accepted; anything else is `422 invalid_request` before any session is
touched.
