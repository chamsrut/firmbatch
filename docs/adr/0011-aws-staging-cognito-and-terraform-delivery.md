# ADR 0011: protected AWS staging is one origin behind an identity broker; Cognito authenticates and Firmbatch authorizes; Terraform delivers it in four bounded slices, and only the fourth may create a resource

- **Status:** Accepted — architecture and documentation only. Nothing in this ADR is
  implemented, deployed or authorized to deploy. **Corrected 2026-09-13** after an
  independent architecture review: four P2 and eleven P3 findings, all accepted and applied
  (see "Review corrections"). **Corrected again the same day** in a final pass that turned
  six further architecture questions into decisions (see "Final correction pass").
- **Date:** 2026-09-13
- **Decision owners:** Firmbatch product owner and maintainers
- **Milestone:** 3.3a — AWS staging, Cognito and Terraform architecture adoption, on
  `docs/milestone-3-3-aws-terraform-architecture` from `main` at `ae61747` (Milestone 3.2,
  PR #10)
- **Amends, without rewriting:** ADR 0008 decision 5 (the protected AWS staging preview —
  this ADR splits it into four slices and fixes its topology and identity design); ADR 0002
  decision 5 (the customer portal reaches the API **same-origin**; Milestone 3.3 establishes
  only the staging browser origin, and production public hostnames remain Milestone 8's
  decision — decision 3 below); the roadmap's original M3.3 text, which proposed
  `staging.app.firmbatch.com` **and** `staging.api.firmbatch.com` as two hosts (superseded by
  decision 3).
- **Plans changes for M3.3c, not made here:** ADR 0009 decision 9's session-cookie name
  becomes `__Host-fb_session` wherever cookies are `Secure` (decision 4.1); in AWS mode the
  portal's sign-out moves from ADR 0010 decision 9's `/v1/account/logout` to the broker's
  `/auth/logout` (decision 4.4); a dedicated identity-binding database boundary joins ADR
  0009's roles (decision 5). The first two remain as they are in local development and test.
- **Builds on, unchanged:** ADR 0009 (the identity plane and the trusted-issuer boundary);
  ADR 0010 decision 1 and its closing consequence (same origin for portal and API is a
  requirement on M3.3 infrastructure — met by decision 3); ADR 0007 (the `NOLOGIN` owner
  pattern decision 5 may reuse); `docs/architecture/v1-target-architecture.md` §14 (the AWS
  shape) and §17 (every invariant); `docs/architecture/rev-d-decision-register.md` §3 (the
  AWS staging row).
- **Companion document:** `docs/architecture/m3-3-aws-staging-topology.md` — the topology,
  flows, routing table, task and credential table, Terraform layout, delivery pipeline,
  logging and evidence rules, and the deployment parameters, in one place.

## Context

**What the repository is at `ae61747`.** Milestones 3.1 and 3.2 are merged: a protected
PostgreSQL identity plane reached only through owner-owned `SECURITY DEFINER` functions,
with a distinct **authenticator** login role holding the pre-authentication functions
(signup, mailbox verification, login lookup, session opening, recovery, signed-in password
change) that the ordinary application role does not hold; a Starlette API on `/v1/*`; and a
TypeScript portal served **same-origin** with that API through a proxy. The browser holds
exactly two cookies on the Firmbatch origin: the `HttpOnly`, `Secure`, `SameSite=Strict`,
host-only session credential, named **`fb_session` with no prefix** in every environment,
and the readable CSRF secret, named `__Host-fb_csrf` wherever it is `Secure`, verified inside
PostgreSQL. The portal signs out through `POST /v1/account/logout`. Passwords are Argon2id
hashes verified in the application process, a stated limitation (ADR 0009 decision 6). No
email is delivered; the production adapter raises. Nothing is deployed, nothing is VERIFIED
LIVE, and no evidence artifact exists for any of it.

**What the authorities say about staging.** ADR 0008 decision 5 pulled a protected AWS
staging preview forward to M3.3 as a recommendation, planned and not authorized, carrying a
necessary subset of Milestone 8's controls and the qualification of the `NOLOGIN` lifecycle
writer and the migration and role installation on managed RDS. The target's §14 names the
shape — ALB, ECS Fargate, RDS PostgreSQL, S3, Secrets Manager and KMS, CloudWatch,
Terraform with isolated environments and an explicit migration step — and its cost line is a
planning estimate. `docs/STATE.md` and `docs/tasks/current.md` carried a **Cognito adoption
decision** open for M3.3: Cognito to own customer authentication while Firmbatch retains its
server-side browser session, CSRF, workspace authorization, row-level security, audit,
consent and API credentials.

**Why a recorded decision rather than an implementation.** Four things had to be settled
before any Terraform or application code is written, and each is a decision a later reader
would otherwise reverse-engineer from a plan file:

1. The original M3.3 text named two staging hosts. M3.2's cookie design cannot serve two: a
   `__Host-` cookie carries no `Domain`, so a portal on one host cannot read a cookie an API
   set on another. One origin is a requirement, not a preference (ADR 0010).
2. Cognito owning authentication changes what the M3.1 authentication path is *for*, where
   the authenticator credential lives, and what the browser may ever hold. Those are
   boundary decisions, and §17 invariants 2 and 11 turn on them.
3. Terraform state, saved plans, secrets and the migration path each have a wrong default —
   state and plans that hold secrets, a plan uploaded as a build artifact, a provider that
   runs SQL, a service that holds the schema owner — and the rules have to exist before the
   first `resource` block.
4. Deployment is a human authorization with a reviewed plan and a current cost estimate
   (ADR 0008 decision 5). A single slice that ends in `apply` would put that authorization
   in the middle of an implementation task. It must be its own gate.

## Decision

### 1. Milestone 3.3 is four bounded slices, and Milestone 3 closes only after the fourth

| Slice | Scope | What it may not do |
| --- | --- | --- |
| **M3.3a** — this branch | Adopt the AWS staging, Cognito and Terraform architecture: this ADR, the topology document, and the status and roadmap reconciliation | No AWS resource, no Terraform, no application code, no migration, no CI change, no evidence |
| **M3.3b** | **Scaffolding only:** the Terraform modules and environment roots, including the separate state and plan buckets (decision 8); ECS task-definition and service scaffolding, parameterized by image digest, command and secret reference; the container-build foundation; ECR, the `staging-plan` and `staging-apply` environments, the distinct plan and apply roles and the manually dispatched workflows, with the **required acceptance tests** of decision 9; the reviewer allow-list validation and its independently tested policy check (decision 6); static Terraform verification | No cloud `plan` against a real backend and no `apply`; **no deployable identity-broker, database-bootstrap or identity-binding implementation**; its task definitions are not operational |
| **M3.3c** | **Every program the scaffolding runs, and its dependencies:** the production database bootstrap command; the identity-binding command and its **dedicated database boundary** (decision 5); the Cognito identity-broker entry point; the Cognito authorization, callback, refresh, revocation and logout clients; JWT and JWKS verification; the KMS encryption and decryption integration; the staging environment configuration mode; the `__Host-fb_session` change (decision 4.1); the AWS-mode route changes including the logout move (decision 4.4); metadata-safe access and unhandled-error logging (decision 10); the database identity mapping (decision 5, migration `0007`); the portal's adaptation to `/auth/*`; the **browser-evidence tooling** M3.3d runs (decision 10); the production runtime dependencies with the runtime and development requirement files and both lock files (`requirements-v1.txt`, `requirements-v1-dev.txt`, `requirements-v1-lock.txt`, `requirements-v1-dev-lock.txt`); the runtime-import gate's module inventory; the container entry points and tests for **every** one-off and long-running command; RDS-compatibility and security tests that can run against local PostgreSQL 16 | No deployment; local authentication retained for development and test |
| **M3.3d** | A reviewed Terraform plan, a current cost estimate, **explicit human deployment authorization**, then apply, bootstrap, migrations, identity binding, browser tests against the real URL, the restore drill, inventories, post-deployment cost and alarm checks, and evidence capture | Nothing before the authorization is recorded |

**M3.3b cannot be applied, and its task definitions are not operational, until the M3.3c
programs, dependencies and image have passed review.** Scaffolding that names a command no
reviewed image contains is a template, not a deployable environment.

**M3.3c selects, pins and reviews the HTTP client, the JOSE/JWT library and the AWS SDK.**
This ADR names none of them: a library chosen in an architecture document would be chosen
without the review, the lock regeneration and the runtime-import check that make a
dependency acceptable here.

**M3.3a, M3.3b and M3.3c are not deployment authorization**, singly or together. A merged
M3.3c is a repository that *could* be deployed; it is deployed only when M3.3d's
authorization exists. Milestone 3's completion gate ("the protected staging preview exists
under the controls above") is met at the end of M3.3d and at no earlier point.

### 2. The environment boundary: a dedicated staging account, synthetic data only

- Staging runs in a **dedicated AWS account**, distinct from any future production account.
  Terraform enforces the expected account through the provider's allowed account list and a
  caller-identity precondition; a plan against any other account fails before it reads a
  resource.
- The recommended staging region is **`eu-central-1` (Frankfurt)**, chosen for proximity to
  the EU region policy the target names and for RDS PostgreSQL 16 and Cognito availability
  there. It is **subject to confirmation immediately before planning and deployment**, and
  is a parameter, not a constant.
- The environment holds **synthetic test accounts and synthetic tenant data only**. No
  production data, no supplier credential, no operator-agent credential and no GPU-provider
  credential enters it. The operator capacity agent is separate operator-side software
  (target §2, §4.2; §17 invariant 11) and is no part of this deployment.
- The **final account ID, domains, CIDRs including the reviewer allow-list, SES identity,
  alert recipient and budget threshold are deployment parameters requiring human
  confirmation** at M3.3d, with the others in the table at the end. This ADR chooses none of
  their values.
- **AWS Budgets provides alerts, not a hard spending cap.** A budget with an alert threshold
  is configured; no document may describe it as a limit that stops spend.

### 3. Public topology: one customer origin, and the same-origin rule

The staging customer application has **one origin**: `https://staging.app.firmbatch.com`.
`staging.api.firmbatch.com` is **not** retained as the active browser design; the roadmap
text that proposed it is superseded here.

**Milestone 3.3 establishes only the staging browser origin.** Production public hostnames
remain a **Milestone 8 decision**. If a separate production API hostname is introduced then,
it is for non-browser clients — the SDK, CLI and automation — or for reviewed edge routing;
**the customer portal remains same-origin** with the API it calls, whatever hostnames
Milestone 8 chooses. No document presents a production pair of browser and API hostnames as
an accepted browser architecture.

The edge and the compute plane:

- **Route 53** for the zone and alias records; a **regional ACM certificate** for the ALB.
- An **internet-facing ALB** reachable only from the **structurally validated,
  human-reviewed reviewer CIDR allow-list** (decision 6). Its HTTPS listener serves the
  application; a listener rule matches the exact host and returns a fixed refusal to any
  other `Host`. **Port 80** exists, admits exactly the **same** reviewed allow-list as port
  443, and does nothing but return the redirect to HTTPS.
- **Private ECS Fargate tasks** with no public IP, in private subnets.
- **Private RDS PostgreSQL 16**, not publicly accessible.
- **One NAT gateway** for staging, with a **fixed egress IP** (the Elastic IP the tasks'
  outbound calls to Cognito leave from), and an **S3 gateway endpoint** where it removes NAT
  traffic (image layers, any S3 use).

**ALB path routing:**

| Path | Target |
| --- | --- |
| `/` and every frontend route | web/API service (serves the compiled portal) |
| `/v1/*` | web/API service (the native API) |
| `/auth/*` | identity-broker service |

**The compiled portal is served from the web/API image in M3.3.** CloudFront and separate
static-site S3 hosting are **explicitly deferred**. This is a staging simplicity and
security decision — one origin, one certificate, one allow-list, no second public surface —
and not the final production performance design, which Milestone 8 decides.

**Two ECS services, separate task roles and separate secret access, the same immutable
image digest:**

| Service | Entry point (M3.3c) | Database credential it holds | Other secrets and permissions |
| --- | --- | --- | --- |
| web/API | the Starlette API plus the compiled portal | the **application** role only | none |
| identity broker | the `/auth/*` broker | the **authenticator** role only | the Cognito app-client secret; KMS encrypt and decrypt on the refresh-token key under an encryption-context condition |

**Three one-off ECS task definitions, same image digest, none of them a service:**

| One-off task | Entry point (M3.3c) | Database credential it holds, for its own run only | Other permissions |
| --- | --- | --- | --- |
| migration | `python3 -m firmbatch.control_plane.migrate upgrade` | the **migration** (schema-owner) role | none |
| bootstrap | the production database bootstrap command | the **RDS-managed master** secret | write the runtime values into exactly the pre-created Secrets Manager containers |
| identity binding | the identity-binding command (decision 5) | the dedicated **identity-binding** login role only — never the authenticator | the minimum Cognito read permission that validates the selected subject; no other secret or AWS permission |

**The binding workflow cannot reach the broker.** The operator's permission to start a task
is limited to the `identity-binding` task definition, and its `iam:PassRole` to that task's
own execution and task roles, so the workflow can neither start the identity broker or any
other task nor run the binding task under another task's roles. The long-running identity
broker keeps the separate authenticator and session boundary.

**No long-running service receives schema-owner, migration or master credentials.** This is
the process separation ADR 0009 deferred to M3.3 — "splitting the process that calls the
trusted-issuer functions from the one that serves the public routes" — made into a
deployment requirement for M3.3c and M3.3d: the broker is to be the authenticator process,
and the web/API service is to hold no pre-authentication authority at all.

### 4. The Cognito boundary: one pool per environment, a confidential client, no token in the browser

**One Cognito User Pool per environment**, in the staging account and region.

**Not used**, by decision:

- Cognito **Identity Pools** — no AWS credential is ever minted for a customer.
- **ALB `authenticate-cognito`** — it would put an ALB-owned session cookie and a token
  header on the path, and it makes the load balancer the authorization boundary; Firmbatch's
  authorization is inside PostgreSQL and stays there.
- **Cognito groups** for Firmbatch workspaces or roles — memberships and roles are
  Firmbatch rows re-derived at every bind (ADR 0009 decision 2); a group claim would be a
  second, unrevalidated source of authority.
- **Cognito JWT authorization in the core API** — the API accepts the Firmbatch session
  cookie and the Firmbatch bearer credential, and nothing else; a JWT is never presented to
  `/v1/*`.
- **Social identity providers** in protected staging.

**Managed Login v2** at a **custom domain**, proposed as `https://auth.staging.app.firmbatch.com`,
**under the same registrable Firmbatch domain as the customer origin**; the exact hostname
remains a deployment parameter. Two facts about the custom domain are recorded so that
M3.3b does not rediscover them: the certificate for a Cognito custom domain **must be
provisioned in `us-east-1`** even when the pool is in `eu-central-1`, which is why the
Terraform providers carry a `us-east-1` alias (decision 8); and the custom domain's parent
name must already resolve, which the ALB alias for `staging.app.firmbatch.com` provides.
Managed Login requires at least the Essentials feature plan; its per-user price is a line of
the current cost estimate at M3.3d.

**The app client** is a **confidential, traditional-web client** with a client secret, using
the **authorization-code grant only**, with **PKCE (S256)** in addition to the secret,
**exact** callback and logout URLs (no wildcard, no path prefix), scopes **`openid` and
`email` only**, **`PreventUserExistenceErrors` enabled**, **refresh-token rotation
enabled**, **five-minute access and ID tokens**, and an **eight-hour refresh-token
validity** that is also the maximum Firmbatch session window (the existing
`FIRMBATCH_API_SESSION_TTL_SECONDS` set to eight hours in staging; the code already accepts
it). Eight hours stands unless a later reviewed decision changes it.

**The pool:** invite-only (administrator-created users only); **email-only, case-insensitive
usernames**; verified email required; **password plus required TOTP**; the pool's own
managed-login cookie stays on the authentication domain and is never read by Firmbatch.

**Not requested in M3.3:** `aws.cognito.signin.user.admin`. Self-service email and profile
changes are deferred. **In AWS mode, password authentication, password recovery and
verification email become Cognito responsibilities**; the local M3.1 implementation of them
remains available **only in development and test** until the Cognito cutover is accepted at
M3.3d, and for a bounded rollback window after it (decision 5).

**The browser receives no Cognito token.** It receives only the opaque Firmbatch session
credential and the readable CSRF secret on the Firmbatch origin, and during a login a
short-lived transaction handle (decision 4.1). The only Cognito artefact that transits the
browser is the single-use authorization code in the callback query, which is useless without
the PKCE verifier and client secret the broker alone holds.

#### 4.1 Cookies: the session gains the `__Host-` prefix, and the OIDC handle is deliberately `Lax`

**The session cookie.** M3.3c renames the Firmbatch session cookie to **`__Host-fb_session`
whenever secure cookies are enabled**, with **`Secure`, `HttpOnly`, `Path=/`, no `Domain`
and `SameSite=Strict`**. The unprefixed `fb_session` remains only as a **development-only**
name, used when HTTPS and secure cookies are deliberately unavailable locally — the
derivation `csrf_cookie_name()` already applies to the CSRF cookie, and for the same reason:
a browser rejects a `__Host-` cookie that is not `Secure`. A secure deployment reads **only**
`__Host-fb_session` and never falls back to the unprefixed name. M3.3c updates the
application's configuration and every test that names the cookie. **No deployed-cookie
migration** is needed, because M3.2 has never been deployed.

Why the prefix and not host-only alone: a cookie set without `Domain` is host-only, but that
does not stop a **sibling or parent-domain host from setting its own cookie of the same
name** with `Domain=firmbatch.com`, which the browser then sends alongside or ahead of the
real one. The **`__Host-` prefix is the browser-enforced protection** against that — the
browser refuses to store a `__Host-` cookie that carries a `Domain`, lacks `Secure` or has a
`Path` other than `/` — and the M3.2 CSRF cookie already relies on it. The session credential
should not be the one cookie without it.

**The OIDC transaction handle.** The broker's login transaction is tied to the browser that
started it by a cookie named **`__Host-fb_oidc`** (or an equivalent name M3.3c's review
settles), with **`Secure`, `HttpOnly`, `Path=/`, no `Domain`** and **`SameSite=Lax`,
deliberately**: the callback arrives as a top-level navigation initiated from the
authentication host, and it must keep working even if that host later stops being same-site
with the customer origin. The handle is **opaque, single-use and short-lived**, and it
**contains no Cognito token, no authorization code, no `nonce` and no PKCE verifier** — it is
a random reference whose fingerprint keys the server-side transaction record. **It is not an
authenticated Firmbatch session** and authorizes nothing on `/v1/*`.

The proposed authentication hostname sits under the same registrable domain as the customer
origin; the `Lax` handle is chosen so that nothing depends on that remaining true forever.
`__Host-fb_session` stays `Strict`. It is **set** on the callback's response and is next
**sent** on the portal's own same-origin requests; the design relies on nothing receiving the
session cookie on the callback request itself.

#### 4.2 The identity broker

The broker must:

- generate and retain a **single-use `state`, `nonce` and PKCE verifier server-side**, with
  a short expiry, bound to the browser by the `__Host-fb_oidc` handle whose fingerprint is
  stored beside them; a callback whose state, handle or expiry does not match is refused,
  once;
- **exchange the authorization code server-side**, over the fixed NAT egress IP, with the
  client secret and the verifier;
- **validate signature, expiry, exact issuer, `token_use`, audience or client ID, `nonce`
  and scopes** before anything else happens;
- **cache the JWKS by `kid`** and refresh it safely on an unknown key, with a bound on refresh
  frequency so an attacker cannot make the broker fetch on every request;
- **create or rotate a Firmbatch session only after it finds the identity's existing explicit
  binding** (decision 5), through a new trusted-issuer entry point granted to the
  authenticator role alone; the broker never creates a binding;
- **never log** codes, tokens, claims, `state`, `nonce`, the verifier or the client secret;
  the metadata allow-list of decision 10 is what it may log.

#### 4.3 Every callback ends in a clean redirect

**Every Cognito callback, successful or failed, returns a `303` redirect to a fixed, clean
Firmbatch URL after clearing the one-time transaction handle.** That includes a callback
carrying a provider `error`, a callback with a missing, replayed or mismatched `state` or
handle, a failed exchange and a failed binding. **No response body is ever rendered at a URL
that retains `code`, `state`, `error_description` or any other provider parameter**, so no page
is ever displayed at a URL that carries them. The clean destination may display **only a neutral
error identifier**. Callback responses carry **`Cache-Control: no-store`** and
**`Referrer-Policy: no-referrer`**. A successful callback sets the session and CSRF cookies on
the same `303`.

#### 4.4 Logout goes through the broker in AWS mode

**In AWS mode, `/v1/account/logout` is disabled as a portal and browser logout route**, and
the portal signs out through **`/auth/logout`**, which:

- **invalidates the Firmbatch session** (the broker's trusted-issuer entry point revokes it
  after verifying the session cookie and the CSRF secret against the session row);
- **best-effort revokes the Cognito refresh-token family** using the stored, decrypted refresh
  token (decision 5); a revocation failure is logged as metadata and does not keep the
  Firmbatch session alive;
- **redirects through Cognito's logout endpoint**, so that Cognito's separate managed-login
  cookie is cleared as well;
- **completes at a fixed, clean Firmbatch URL** (the registered logout URL).

The local `/v1/account/logout` behaviour remains for **local development and test mode
only**. **M3.3c owns this route-mode change and its tests**, including the portal's
sign-out adaptation, which keeps ADR 0010 decision 9's rule that a sign-out that did not end
the session is never presented as signed out.

### 5. Identity mapping: issuer plus subject, bound explicitly, never by email

M3.3c adds a protected identity-plane relation equivalent to:

```text
auth_identity(
  provider,          -- 'cognito'
  issuer,            -- the exact issuer URL of the pool
  subject,           -- the Cognito sub
  account_id,        -- the Firmbatch account the identity is bound to
  created_at,
  last_seen_at
)
UNIQUE (issuer, subject)
```

reached, like every M3.1 table, only through `SECURITY DEFINER` functions with no grant to
any runtime role. The **external identity is Cognito's issuer plus `sub`**, never the email
address. **A Cognito subject is never attached to an existing account merely because the
email matches**: a login whose `(issuer, subject)` has no binding is refused with the neutral
refusal, whatever email the token carries.

**Binding is an explicit act, performed only by the `identity-binding` one-off task through a
dedicated database boundary.**

**The identity-binding database boundary (M3.3c).**

- A dedicated identity-binding **login role**, with **no table privileges** and **no
  membership** in the authenticator, application, provisioning, migration or owner roles.
- **`EXECUTE` on only one** narrowly scoped identity-binding function.
- That function is `SECURITY DEFINER`. Where M3.3c's review finds an owner boundary is
  needed, it is owned by a **separate `NOLOGIN` owner** holding only what binding requires,
  by the pattern of M2.4's lifecycle writer (ADR 0007), rather than by the schema owner.
- The login role **cannot** create browser sessions, issue API credentials, change
  memberships, assume another role or execute general authenticator functions, and **direct
  table writes remain unavailable** to it.
- The function binds **one explicit `(issuer, subject)`** to **one explicit unused invitation
  or account**, and **never binds by email equality**.
- It is **idempotent** for an identical request and **refuses a conflicting binding** — a
  subject already bound to another target, or a target already bound to another subject.
- It **records a Firmbatch audit event atomically**: a binding and its audit event commit
  together, and a refusal commits its refusal audit event and no binding, answering with the
  neutral refusal rather than raising so that the record survives.

**A constraint M3.3c has to honour.** The repository's ordinary transaction preamble calls
`auth_tenant_id`, which reads `auth_context`; that is why the authenticator's grant includes
both (ADR 0009, "Security corrections"). A role whose whole grant is one function cannot use
that preamble unchanged, so the binding command's database path must not rely on it, and
M3.3c's tests prove from the catalogue that the role's entire grant is the one function.

**The task:**

- is a **fifth task definition**, separate from the web/API service, the identity broker, the
  bootstrap task and the migration task; it has **no public endpoint and no persistent
  service**, and it is **distinct from the operator capacity agent**;
- is **invoked manually** through a reviewed, authenticated operator workflow or an AWS SSO
  session — never automatically, never from a pull request;
- receives **only the identity-binding credential**, for the duration of its run, and **no
  authenticator, schema-owner, migration or master credential**;
- holds only the **minimum Cognito read permission required to validate the selected
  subject** in the one staging pool;
- accepts **only non-secret identifiers** as invocation metadata — the Cognito subject, the
  target account's identifier or the unused invitation's row identifier (never its acceptance
  token), and a change reference that carries no email address — and no email address, token
  or password, because task overrides are themselves recorded by AWS;
- answers every refusal with the neutral refusal and **logs no email address or token**.

**Its command is assumed to be overridable.** `RunTask` lets its caller override a
container's command, so the design assumes arbitrary code can run inside the task. That code
holds a database credential that can execute one binding function and nothing else, a
Cognito permission that only reads, and no other secret. It still cannot issue a session,
obtain an API credential or reach broader database authority.

Two questions remain M3.3c's to specify and test: where the account-plane binding audit
record lives, since an account has no tenant audit trail today (ADR 0009 decision 10); and
the exact semantics of binding to an unused invitation.

**No legacy-password migration is designed**, because Firmbatch has deployed no real M3.1 or
M3.2 users: there is nobody to migrate. Controlled synthetic staging identities are created in
Cognito and bound through the task at M3.3d. **Local authentication is preserved only for
development, tests and a bounded rollback window**; in AWS mode the web/API service holds no
authenticator credential and serves no local signup, login, verification, recovery,
password-change or logout route to the browser.

**Cognito refresh tokens are encrypted server-side with KMS**, with an encryption context
that binds the ciphertext to the Firmbatch session and account it belongs to, and are stored
**only in protected server-side state** reachable through authenticator-only functions. They
**never enter browser storage, logs or the core API**; the web/API service holds no KMS
grant and no function that returns one. The broker uses a stored refresh token for two
things only: revocation at logout, and — if M3.3c chooses it, with the interval recorded
there — a bounded server-side re-validation of the identity so that a disabled Cognito user
loses the Firmbatch session before the eight-hour window ends.

A consequence worth stating: ADR 0009 decision 6's hash-harvest limitation does not apply to
AWS-mode accounts, because they carry no Firmbatch password hash. The limitation stands for
local development and test, confined to the narrow authenticator principal as before.

### 6. Network protection

- The ALB accepts connections **only from the reviewer CIDR allow-list**, on port 443 and,
  with **exactly the same reviewed list**, on port 80, whose only action is the redirect to
  HTTPS.
- **The allow-list is validated structurally and fails closed**, by Terraform variable
  validation **and** by an independently tested policy check — never by a string comparison
  alone. The list is **invalid when empty**. Every entry must be a **valid, canonical IPv4 or
  IPv6 CIDR**, with an **IPv4 prefix of `/24` or narrower** or an **IPv6 prefix of `/64` or
  narrower**. The list holds at most a **small fixed maximum of entries, proposed as 16**.
  **No unspecified, multicast, loopback, link-local or otherwise non-routable range** is
  accepted, **nor any duplicate or overlapping entry**, **nor any combination of entries
  exceeding the configured maximum address-space allowance**. Tests prove each rejection.
- **The planned CIDRs require explicit human review**, and **no reviewer's personal CIDR is
  committed** to the repository: the list is supplied at plan time from protected
  configuration outside it, valued `tfvars` stay excluded from Git, and tests use synthetic
  entries.
- **ECS tasks have no public IP**; the services' security groups accept traffic from the
  ALB's security group only, and the one-off tasks accept no inbound traffic.
- **RDS is not publicly accessible** and accepts PostgreSQL only from the **web/API service,
  the identity broker, the bootstrap task, the migration task and the identity-binding
  task**, each through **its own reviewed security group and its own credential boundary**;
  the identity-binding group reaches RDS, and its credential limits it to one function.
- **Cognito is invite-only and protected by a Cognito-associated WAF web ACL** whose IP
  allow-list is the same reviewed list **plus, added separately, the identity broker's NAT
  Elastic IP as a `/32`**; that `/32` is never added to the ALB allow-list. **No CAPTCHA on
  the TOTP-enrollment paths**: a challenge inserted into first-login MFA setup breaks the
  enrollment flow for the people the allow-list already admits. The ALB has **no WAF added**
  in M3.3: its security-group allow-list protects it.
- **HTTP redirects to HTTPS** from the allow-listed port 80; TLS terminates at the ALB.
- **Exact host and origin validation remains application-enforced**: the API and the broker
  refuse a `Host` that is not the configured origin and keep the `Origin` allow-list on
  every cookie-authenticated mutation, whatever the ALB rule already refused.

### 7. PostgreSQL and secrets: managed RDS, verified TLS, and no password in Terraform state

**RDS PostgreSQL 16**, with the exact supported minor version checked immediately before
deployment (the target names 16; the suite refuses any other major):

- private DB subnets across **two availability zones**, **Single-AZ** for staging;
- **encrypted storage**; an **explicit PostgreSQL 16 parameter group** with
  **`rds.force_ssl = 1`**; clients verify the server certificate, preferably
  **`sslmode=verify-full`** with the RDS certificate bundle — the URL parser already accepts
  `sslmode` and `sslrootcert`, so this is configuration, and M3.3c confirms the bundle's
  path inside the image;
- **seven-day automated backup and point-in-time-recovery retention**; **deletion
  protection**; a **required final snapshot** on destroy; **no read replica** in M3.3
  (writable-primary routing is preserved; replicas are Milestone 8's qualification).

**`rds_superuser` is not a PostgreSQL superuser.** It lacks the `SUPERUSER` attribute,
cannot read `pg_authid`, and holds ownership and membership semantics that differ from the
superuser the CI container has and the non-superuser administrator the local cluster has.
The repository's principal check and role reconciliation read `pg_roles`, not `pg_authid`,
which is the right catalogue for RDS; everything else is a qualification, not an assumption.
**M3.3d must qualify, against managed RDS**: migrations `0001`–`0006` upgrading cleanly, and
`0007` once M3.3c adds it; `FORCE` row-level security on every tenant relation; the ownership
of every `SECURITY DEFINER` function by the schema owner, or by the dedicated `NOLOGIN` owner
decision 5 allows for the binding function, and never by the master user; the `NOLOGIN`
lifecycle writer's installation and `SET ROLE` semantics; **the identity-binding login role's
catalogue** — `EXECUTE` on its one function, no table or column privilege, no role
membership — and a refused attempt, as that role, to open a session, issue a credential,
change a membership, assume a role or write a table; the grant and ACL-sanitiser
inventories; downgrade and re-upgrade with role reconciliation at each revision; and clean
teardown. Local PostgreSQL success is not evidence for any of these — the roadmap already
says so.

**The master credential is RDS-managed in Secrets Manager** and is available **only to the
one-off bootstrap task**. Neither ECS service, the migration task, the identity-binding task,
CI, nor Terraform's state holds it.

**Distinct boundaries are preserved**: application, provisioning, authenticator, migration
and owner, plus the `NOLOGIN` lifecycle writer, exactly as `db/roles.py` wires them today; M3.3c
adds the identity-binding login role and, where review needs it, the separate `NOLOGIN` owner
of its function. **The one-off bootstrap task** creates and rotates the login credentials and
**writes the runtime secret values directly into pre-created Secrets Manager containers** —
Terraform creates the secret resources with no version; the task puts the values — so the
database passwords **never enter Terraform state**. Each service's and each one-off task's
execution role may read exactly the secrets its own container definition names, and no other.

**Terraform runs no database SQL** — no PostgreSQL provider, no `local-exec`, no
`remote-exec`. **Bootstrap, migrations and identity binding are explicit one-off ECS tasks**
using the same image digest.

**One acknowledged exception, and its consequence for plans.** If Terraform creates the
confidential Cognito app client, the **client secret is in Terraform state**, sensitive-marked
or not, and a saved binary plan carries the prior state with it. **Terraform state and saved
plan files are therefore equally sensitive.** State lives only in the KMS-encrypted, versioned
state bucket and saved plans only in the separate KMS-encrypted, Object-Locked plan bucket
(decisions 8 and 9), each readable only by the identities decision 9 names and by a separately
authenticated operator session. Marking outputs `sensitive` hides them from plan output and
**does not remove them from state or from a saved plan**, and no document may say otherwise.

### 8. Terraform architecture

The intended layout, documented now and created in M3.3b as scaffolding:

```text
infra/terraform/
  bootstrap/                 the state bucket and the separate plan bucket (Object Lock
                             enabled), their KMS keys, then the bootstrap's own state
                             migrated into the state bucket
  policy/                    the reviewer allow-list policy check and its own tests,
                             independent of Terraform variable validation
  modules/
    network/                 VPC, subnets, NAT, S3 gateway endpoint, security groups
    edge/                    Route 53 records, ACM, ALB, the 443 and 80 listeners, rules,
                             the validated allow-list variable
    compute/                 ECS cluster; the two services and the three one-off task
                             definitions (migration, bootstrap, identity binding),
                             parameterized by image digest, command and secret reference
    database/                RDS, parameter group, subnet group, managed master secret
    identity/                Cognito user pool, domain, managed-login branding, app client,
                             the us-east-1 certificate, the Cognito-associated WAF
    secrets/                 Secrets Manager containers (no versions), KMS keys and grants
    observability/           CloudWatch log groups with retention, alarms, the budget
    delivery/                ECR, the GitHub OIDC provider, the distinct plan and apply
                             roles (the apply role under a permissions boundary), the
                             operator permission to run identity binding, deploy permissions
  environments/
    staging/                 the staging root: one state key, pinned versions, tfvars example
    production/README.md     a placeholder stating production is a separate root, account
                             and state, not created by Milestone 3
```

Rules:

- **No Terraform workspaces for environment isolation.** Separate roots, separate state
  keys, separate accounts.
- **Bootstrap** creates two buckets and never mixes them. The **state bucket** is
  access-controlled, **versioned, KMS-encrypted and public-access-blocked**, holds each
  root's state under its own key, and keeps its own retention policy; state is never expired
  with plan artifacts. The **plan bucket** is separate, KMS-encrypted, public-access-blocked
  and versioned, with **Object Lock** and the retention and lifecycle rules of decision 9.
  Bootstrap then migrates its own state into the state bucket under its own key.
- **The native S3 lockfile** (`use_lockfile = true`) provides locking. The deprecated
  DynamoDB locking table is not introduced.
- **Terraform and provider versions are pinned**; **`.terraform.lock.hcl` is committed**.
- **Provider aliases** for `eu-central-1` (default) and `us-east-1` (the Cognito custom-domain
  certificate, and nothing else while CloudFront is deferred).
- **Excluded from Git** when M3.3b adds the code: state files, plan files, any `tfvars`
  carrying values (a values-free `.example` is tracked), crash logs and override files;
  `.terraform/` directories. No reviewer CIDR is ever committed.
- **Outputs are marked `sensitive` where appropriate**, with the state and plan caveat of
  decision 7 stated beside them.
- **No static AWS access keys** — not in `.env`, not in CI, not in Terraform, not in a
  GitHub environment secret. Humans use short-lived credentials; CI uses OIDC (decision 9).
- The repository's policy guard already denies `terraform apply`, `destroy`, `import`,
  `taint`, `untaint` and `state rm|mv|push`, and a **prefix list** of mutating `aws` verbs
  (`AWS_MUTATING_PREFIXES` in `.agents/policy/guard.py`, plus the `s3` deletion forms) —
  not every mutating verb: `cognito-idp admin-create-user`, `set-user-pool-mfa-config` and
  the like are not on it, and `AGENTS.md`'s rule, not the hook, is the boundary. `fmt`,
  `init`, `validate`, `test` and `plan` are allowed — and **`terraform test` is not
  harmless**: its `run` blocks apply real resources unless they use `command = plan` or
  mocked providers, so M3.3b's tests run with mocks or plan-only and with no credentials.
  An agent validates and a human applies because the instruction says so, not because the
  hook enforces it. Extending the guard is a `.agents/policy/` change needing the human's
  approval, and is not this slice's.

### 9. Delivery model

**GitHub Actions eventually uses AWS OIDC. No untrusted pull request receives AWS
credentials.** Four stages, kept apart:

1. **Pull-request static checks** — `terraform fmt -check`, `terraform init -backend=false`,
   `terraform validate`, lint and policy checks including the allow-list policy check,
   `terraform test` with mocks. No GitHub environment, no AWS credential, no cloud access.
2. **Trusted cloud plan**, from a manually dispatched workflow, in the **`staging-plan`**
   environment.
3. **Human-approved apply of the reviewed plan**, from a manually dispatched workflow started
   with that plan's object key, version ID and expected SHA-256, in the separate
   **`staging-apply`** environment.
4. **Application deployment** — a separate, later stage; its identity and approval are
   specified when M3.3b's delivery structure is reviewed, and neither the plan approval nor
   the apply approval authorizes it.

#### 9.1 Environments, workflows and roles — required M3.3b acceptance tests

Each property below is a **required M3.3b acceptance test** that fails when the property is
absent. None is informal operational guidance.

- **Both environments**, `staging-plan` and `staging-apply`: deployment branch rules
  permitting **only `main`**; **required reviewers**; **prevention of self-review** where
  GitHub supports it; and **no environment secret containing a permanent AWS credential**.
- **The deployment workflows**: **manually dispatched from the default branch**; they
  **refuse unless `github.ref` is exactly `refs/heads/main`**; they **verify that the selected
  source commit is reachable from and currently approved on protected `main`**; their files
  are **protected by `CODEOWNERS` and branch protection**; and **deployments from forks and
  pull-request contexts are disabled**.
- **AWS OIDC trust**: each role's trust policy names the **exact repository and the exact
  environment** — `repo:chamsrut/firmbatch:environment:staging-plan` for the plan role and
  `repo:chamsrut/firmbatch:environment:staging-apply` for the apply role.
- **Distinct plan and apply IAM roles.** The **apply role has a permissions boundary** and
  **cannot be assumed through the `staging-plan` environment**.

| Environment | AWS permissions of its role |
| --- | --- |
| `staging-plan` | read the environment's state and refresh it (read-only resource access), write the lockfile object the S3 backend takes while planning, and **create new objects in the plan bucket**; it **cannot overwrite an approved object version, remove or bypass retention, retrieve historical plan versions, or apply infrastructure** |
| `staging-apply` | within its **permissions boundary**: read the one approved plan object version and its environment's state, write that state and its lockfile, and the infrastructure permissions the apply needs; it **cannot bypass plan retention or retrieve arbitrary historical plan versions** |

**Both environments require human approval, because the plan identity can read sensitive
state. Approval of planning does not authorize applying.** Adding the workflows,
`CODEOWNERS` and a Terraform static gate in `scripts/verify-repository.sh` are changes to
protected files and need the human's explicit, file-specific approval when M3.3b proposes
them (`AGENTS.md`).

#### 9.2 Plan approval does not rest on plan-produced metadata

The apply job **never trusts a manifest because the plan job wrote it.**

- Saved plans live in a **dedicated plan bucket, separate from the Terraform state bucket**:
  KMS-encrypted, public-access-blocked, **versioned**, with **Object Lock governance
  retention**.
- Plan objects have **content-addressed keys containing the source commit and the plan's
  SHA-256**.
- The plan role **can create new plan objects** but **cannot overwrite an approved object
  version, remove retention or apply infrastructure**.
- The full plan is inspected in a **separately authenticated operator session**, never in
  the GitHub run.
- The human **starts the apply workflow with the reviewed object's key, its S3 version ID
  and its expected SHA-256**, and **those values are visible in the protected `staging-apply`
  approval request**.
- The apply job **downloads that exact object version**; **independently recomputes the
  SHA-256** and compares it with the expected value; **independently checks out the approved
  source commit** named by the key and verifies it; **independently recomputes the
  provider-lock digest** from that checkout; **checks the Terraform version itself**; and
  relies on **Terraform's own saved-plan and state checks** to reject a stale lineage or
  serial.
- **Any mismatch, a missing version, an expired plan, or an approved source commit that is no
  longer reachable from or approved on protected `main` fails closed.** Apply never
  generates a new plan.
- Metadata the plan job records may **aid review**; **it is not an authority for apply**.
- **No binary plan or full plan rendering** is placed in a GitHub artifact or a public log.
  GitHub displays only a deliberately sanitized summary: action counts, policy results, the
  cost summary and the plan checksum.

#### 9.3 Plan retention in a versioned bucket

- Plan objects carry a proposed **one-day Object Lock governance retention**, tied to the
  **saved-plan lifetime, a human-confirmed deployment parameter with 24 hours recommended**.
- **Lifecycle rules expire current and noncurrent plan versions** after the approved short
  retention, and **delete markers are expired too**.
- **Neither the plan role nor the apply role can bypass retention or retrieve arbitrary
  historical versions.**
- **Apply refuses any plan older than the allowed age**, measured from when S3 created that
  object version, even if an old version still physically exists.
- Deleting a current object in a versioned bucket only adds a delete marker; **no document
  may say a delete removes every copy of a plan**. Refused plans are left to lifecycle expiry.
- **Terraform state uses a different retention policy**, in its own bucket, and is **never
  expired with plan artifacts**.

**One immutable container image** is built per deployment, stored in **ECR with immutable
tags and scan-on-push**, and **deployed by digest**. **The migration ECS task runs before
service rollout; the rollout is aborted on migration failure.** Application failures roll back
through the **ECS deployment circuit breaker**. **A database downgrade is not an automatic
rollback strategy**: downgrades exist and are tested, and a human decides whether to run
one.

M3.3c's new modules extend `scripts/verify-repository.sh`'s `REQUIRED_FILES`,
`scripts/check-runtime-imports.py`'s module inventory and the test bootstrap's role set as
the verification script and skill describe it, all of which need the same approval, as at
M3.1 and M3.2.

### 10. Logging and evidence

**Firmbatch application logs** go to **CloudWatch log groups with explicit retention**, with
**allow-listed metadata fields only**: method, route template or a fixed classification,
status, duration, request ID, task ID, image digest, session and account **identifiers**
(never secrets), and the broker's outcome codes. **Excluded**: request and response bodies;
query strings; headers and cookies; OAuth codes and tokens and every callback parameter;
email addresses; SQL values; raw S3 or object identifiers; customer payload. **Both of the
API's log lines record the raw request path today**: the unhandled-error line names
`request.url.path` directly, and the access line, which is meant to record the route
template, reads a matched route from the request scope that the locked Starlette 1.6.0 does
not record, and falls back to the raw path. Today's path parameters are identifiers, not
secrets. M3.3c replaces both with route-template or fixed-classification metadata, never logs
a query string or a callback parameter, and tests both lines.

**AWS-managed control-plane and delivery logs are not Firmbatch application logs, and the
allow-list does not govern them.** CloudTrail, Cognito user-pool logging and export, SES
delivery and event records, the Cognito-associated WAF's logs, and any CloudWatch log
destination receiving those records **can contain customer identity attributes such as email
addresses**. **M3.3d inventories and reviews each of them** and applies least privilege,
explicit retention, encryption and access auditing. Their records are **never copied into
ordinary Firmbatch application logs**, and no document may claim that the application
logging allow-list removes identity data from AWS control-plane services.

**ALB access logs stay disabled for M3.3.** The callback carries `code` and `state` in its
query string, and an access log retains the full request line. They are enabled only after a
separate review proves the query parameters and every other sensitive value cannot be
retained.

**Browser evidence is credential-safe.** M3.3d retains **no ordinary Playwright trace, HAR
file, video, storage-state file, console dump, network log or failure screenshot** from an
authenticated or OAuth journey. M3.3c builds the tooling that enforces this, and M3.3d runs it:

- **synthetic staging identities and synthetic content only**;
- Playwright **trace, video, screenshot and storage-state persistence disabled** for
  authentication tests;
- **no callback URL, query string, authorization code, `state`, `nonce`, cookie, CSRF value,
  token, email address or refresh material** in any report;
- authentication failures produce **only fixed classifications and opaque correlation IDs**;
- the **evidence collector writes an allow-listed summary** containing only the test name,
  the clean host and path, the result, the status class, the deployment digest and sanitized
  timing;
- **callback and logout verification is represented by sanitized assertions**, not by
  captured traffic;
- **UI screenshots, only if separately approved**, are taken on a **clean
  post-authentication route showing obviously synthetic data**, and never include an account
  email, a credential, an API key or browser developer tools;
- **generated evidence is scanned** for secrets, URLs containing queries, cookies, bearer
  material and email addresses **before it can be committed**, and **a failed scan prevents
  publication**; if that scan belongs in the `record-evidence` skill, the skill change needs
  the human's approval;
- **raw CI and browser artifacts have zero retention by default and are never uploaded.**

**M3.3d must produce**, under `docs/evidence/m3/` with the standard provenance header: the
**sanitized plan summary** — action counts, policy results, cost summary and plan checksum —
with the record that the full plan was reviewed in an operator session, and **never the
binary plan or a full plan rendering**; the current AWS cost estimate; the explicit human
deployment approval, naming the approved plan object's version and checksum; the RDS
compatibility qualification (decision 7); the controlled staging identities bound through the
identity-binding task, with their success and refusal audit records; synthetic identity and
tenant-isolation tests against the deployed database; **the browser journey's allow-listed,
secret-scanned summary** and **any explicitly approved UI images** — **never raw browser
artifacts**; the backup restore drill; the resource and secret inventory, by name and
identifier and never by value; the inventory and review of the AWS-managed logs that can hold
identity data; post-deployment cost and alarm checks; and the evidence capture itself.
Nothing is VERIFIED LIVE before that capture.

### 11. Explicit deferrals

Milestone 3.3 does **not** deliver, and no document may claim: production deployment;
production public hostnames; CloudFront; static-site S3 hosting; Multi-AZ RDS; read replicas
or RDS Proxy; autoscaling; multiple NAT gateways; production identities or data; real
GPU-provider execution; operator capacity agent deployment; payload presigning and transfer;
the SQS outbox dispatcher and workers; settlement; production disaster recovery.

**The operator capacity agent remains separate operator-side software** (Phase P, target
§2 and §4.2, §17 invariant 11). Cognito and AWS staging change nothing about the multi-provider
GPU boundary: AWS hosts the control plane and the payload plane; GPU execution stays
multi-cloud, and no driver is enabled by this milestone.

### 12. Status reconciliation

Current documentation now says: M3.2 was merged through **PR #10 at `ae61747`**
(implementation `ce097cb`, status commit `59d82a7`); M3.2 is **implemented, tested and
reviewed, but not deployed and not VERIFIED LIVE**; **Milestone 3 remains active**; **M3.3a is
the current slice**; **the customer can see the real hosted portal only after M3.3d**; and
**no AWS deployment or evidence exists yet**.

## Consequences

- The M3.2 same-origin requirement is met by topology rather than by a second cookie design:
  one origin, one certificate, one allow-list, and `/auth/*` routed to a second service on
  the same host.
- The trusted-issuer process split ADR 0009 deferred becomes a deployment shape: the broker
  holds the authenticator credential, and nothing else does. The web/API service holds none,
  and the identity-binding task holds only its own one-function credential. Local
  authentication keeps the existing one-process form for development and test.
- Every §17 invariant is preserved. In particular: PostgreSQL stays the only authority
  (invariant 1 — no Cognito claim is a source of authorization); every tenant-owned row and
  credential stays tenant-scoped (2 — `auth_identity` and the stored refresh token are
  account-plane rows, reached through protected functions as M3.1's `accounts` are);
  customer, operator and supplier interfaces stay separate (11 — the operator agent is not in
  this deployment, the identity-binding task is not it, and the reviewer allow-list is not a
  customer surface).
- M3.3b produces scaffolding that cannot run until M3.3c's image exists, and its acceptance
  tests make the delivery controls checkable rather than conventional. M3.3c carries most of
  the implementation and its dependency review. M3.3d is the only slice that spends money,
  and it starts with a human saying so.
- Protected-file approvals are expected at M3.3b (workflows, `CODEOWNERS`, a verification
  gate) and M3.3c (`REQUIRED_FILES`, the runtime-import inventory, the test bootstrap's role
  set as the verification script and skill describe it, and the `record-evidence` skill if the
  evidence scan is placed there).
- Documents now distinguish four M3.3 slices where they said "M3.3", at the cost of one more
  label a reader has to hold.

## What this decision does not claim

- It authorizes no deployment, purchase, DNS change, certificate request, account creation
  or supplier contact. Creating any AWS resource is M3.3d's, after its authorization.
- It claims no capability is implemented: no broker, no bootstrap or binding command, no
  binding role or function, no identity mapping, no cookie rename, no Terraform, no plan
  bucket, no workflow, no evidence tooling, no image and no pipeline exists in this repository
  at `ae61747` plus this branch.
- It fixes no deployment parameter; the table below lists them.
- It chooses no JOSE/JWT library, HTTP client or AWS SDK; M3.3c does, under review.
- It verifies nothing about AWS pricing or behaviour. The target's cost line is a planning
  estimate; the current estimate is M3.3d's deliverable.
- It reclassifies no evidence. M3.1 and M3.2 stay implemented, tested and reviewed, not
  VERIFIED LIVE; no evidence artifact exists for either.

## Rejected alternatives

- **Two staging hosts, `staging.app` and `staging.api`.** Rejected: the `__Host-` cookie
  contract cannot span two hosts (ADR 0010), and a second public host is a second
  certificate, allow-list and attack surface for no property.
- **Deciding production hostnames now.** Rejected: M3.3 needs one staging origin; production
  naming is Milestone 8's, bound only by the same-origin rule for the portal.
- **CloudFront with an S3 static site now.** Rejected for M3.3: it adds a second edge, a
  second origin policy and an `us-east-1` certificate for a static bundle whose only
  requirement in staging is to be served under the one origin; deferred to Milestone 8's
  production design.
- **ALB `authenticate-cognito`.** Rejected: it puts an ALB-managed session and a token
  header on the request path, cannot express Firmbatch's membership-derived authorization,
  and would give the browser a cookie Firmbatch does not control.
- **Cognito groups for workspaces or roles.** Rejected: authority would then live in two
  places, and a group claim minted at login cannot observe a revocation the way every bind
  re-derives membership today.
- **Verifying Cognito JWTs in the core API.** Rejected: the API's two credential types are
  distinct by construction (ADR 0009 decision 5); a third boundary that accepts a bearer
  JWT would reopen it, and it would put tokens in the browser.
- **Identity Pools, social providers, `aws.cognito.signin.user.admin`.** Rejected or deferred:
  none is needed by a protected, invite-only staging preview.
- **A host-only session cookie without the `__Host-` prefix.** Rejected: host-only does not
  stop another host in the domain from setting a same-named parent-domain cookie; the prefix
  does.
- **A `Strict` OIDC transaction handle.** Rejected: it ties the callback to the
  authentication host staying same-site with the customer origin, which the design should not
  depend on.
- **Rendering a callback error at the callback URL.** Rejected: the provider parameters would
  stay in browser history and in any `Referer`.
- **Binding a Cognito identity to an account by email match.** Rejected: an email is
  reassignable and a claim; `(issuer, sub)` is the identity. Explicit binding is the only
  path.
- **Binding through the broker, a web route or the bootstrap task.** Rejected: binding is a
  rare, operator-run act; putting it on a public service or on the task that holds the master
  credential widens both for no property.
- **Giving the identity-binding task the authenticator credential, or leaving a narrower one
  optional.** Rejected: a caller who can override the task's command would hold every
  authenticator function, session issuance included. Only a credential that cannot do more
  than bind is safe to place where arbitrary code may run.
- **A legacy-password migration.** Rejected: no real users exist to migrate.
- **Refresh tokens in the browser, or in the API's reach.** Rejected: the browser holds one
  opaque Firmbatch credential; a refresh token is a long-lived bearer that must live behind
  KMS and the authenticator boundary only.
- **A PostgreSQL Terraform provider or `local-exec` for roles and migrations.** Rejected:
  it puts passwords and SQL in state and plan output and makes a Terraform run a database
  writer. One-off tasks with the repository's own `migrate.py` and role wiring are the path.
- **Terraform workspaces for staging and production.** Rejected: one state bucket key and
  one set of credentials for two environments is how a staging `apply` touches production.
- **DynamoDB state locking.** Rejected: superseded by the native S3 lockfile.
- **The saved plan as a GitHub Actions artifact, or the full plan in the job log.**
  Rejected: a saved plan carries prior state and the Cognito client secret, and an artifact or
  log is readable far more widely than the plan bucket.
- **Saved plans in the state bucket.** Rejected: plan retention and expiry rules would sit
  beside state, which must never expire with them.
- **Trusting the plan job's recorded metadata at apply.** Rejected: an identity that can write
  a plan can write the manifest beside it. The approval names an object version and a
  checksum, and the apply job recomputes every check itself.
- **One GitHub environment and one role for plan and apply.** Rejected: an approval to look
  would then be an approval to change.
- **Deploying from release tags or any branch but `main`.** Rejected: one protected,
  reviewed source is what the reachability and approval check can prove.
- **Rejecting only the literal `0.0.0.0/0` and `::/0`.** Rejected: equivalent broad ranges
  written differently pass a string comparison.
- **Ordinary Playwright traces, HAR files, videos and screenshots as evidence.** Rejected:
  they capture cookies, callback codes, CSRF values and email addresses.
- **ALB access logs on from day one.** Rejected until a review proves the callback query
  cannot be retained.
- **A single M3.3 slice ending in `apply`.** Rejected: the deployment authorization would be
  a step inside a task rather than a gate between tasks.

## Deployment parameters requiring human confirmation

Recorded once here and repeated in the topology document; **no value is chosen by this ADR**.

| Parameter | Confirmed when |
| --- | --- |
| Staging AWS account ID | before the first `plan` (M3.3d) |
| Region (recommended `eu-central-1`) | immediately before planning and deployment |
| Domains: the Route 53 hosted zone, the customer origin `staging.app.firmbatch.com`, and the Cognito custom domain (proposed `auth.staging.app.firmbatch.com`) with its callback and logout URLs | M3.3d |
| CIDRs: the VPC and subnet ranges, and the reviewer allow-list for ports 443 and 80 with its maximum address-space allowance, explicitly reviewed and never committed | M3.3d, and on every change |
| SES identity | M3.3d |
| Alert recipient for alarms and the budget | M3.3d |
| Budget threshold (alerts, not a cap) | M3.3d |
| RDS sizing — instance class and storage — and the exact PostgreSQL 16 minor | M3.3d |
| Saved-plan lifetime (24 hours recommended) and the required reviewers of `staging-plan` and `staging-apply` | before the first trusted plan |
| The staging identities to bind: which Cognito subjects to which accounts or invitations | M3.3d, per binding |
| Retention of the AWS-managed logs that can hold identity data | M3.3d |
| The current cost estimate, including the Cognito feature plan Managed Login requires | M3.3d, before authorization |
| **Explicit deployment authorization** | M3.3d, recorded before `apply` |

## Review corrections

An independent review of this ADR and its companion documents raised four P2 and eleven P3
findings on 2026-09-13. All were accepted and applied the same day, in these documents only;
no code, migration, CI, script, snapshot or §17 text changed. A security review and an
evidence audit run after the corrections raised further questions. Six of them are decided in
the final correction pass below; the rest remain open, with their owning slice, under "Open
questions carried into Milestone 3" in `docs/tasks/current.md`.

| Finding | Correction, and where it now lives |
| --- | --- |
| P2-1 saved plan exposure | The plan never becomes a GitHub artifact or public log; GitHub shows a sanitized summary only; operator-session review; state and plans equally sensitive. Strengthened in the final pass: a separate Object-Locked plan bucket and an apply that verifies independently. Decisions 7, 8, 9, 10 |
| P2-2 session cookie prefix | `__Host-fb_session` wherever `Secure`; development-only unprefixed name; no deployed-cookie migration; the host-only wording corrected; the `__Host-fb_oidc` `Lax` handle specified. Decision 4.1 |
| P2-3 identity binding | A fifth one-off task definition with its permission, invocation, audit and logging rules. Its credential replaced in the final pass by a dedicated binding boundary. Decisions 3, 5, 6, 7, 8, 10 |
| P2-4 slice ownership | M3.3b is scaffolding only; every program, client, dependency, lock file, entry point and test is M3.3c's; M3.3b is not operational until M3.3c passes review; no library chosen here. Decision 1 |
| P3-1 RDS ingress | Five security groups, each with its own credential boundary. Decision 6 |
| P3-2 ALB WAF | Removed from the edge module; the Cognito WAF is the identity module's; no WAF added to the ALB, whose security-group allow-list protects it. Decisions 6, 8 |
| P3-3 hostname and cookie semantics | Same registrable domain; `Strict` session; `Lax` handle that is not a session. Decisions 4, 4.1 |
| P3-4 AWS-mode logout | `/v1/account/logout` disabled for the browser in AWS mode; `/auth/logout` with a fixed clean completion URL; M3.3c owns it. Decision 4.4 |
| P3-5 GitHub environments | `staging-plan` and `staging-apply`, both human-approved, exact `sub` conditions; planning approval does not authorize applying. Constrained further in the final pass. Decision 9 |
| P3-6 broker ownership | Every executable broker component moved from M3.3b to M3.3c. Decision 1 |
| P3-7 AWS-managed identity data | CloudTrail, Cognito logging and export, SES records, Cognito WAF logs and their destinations inventoried and reviewed at M3.3d. Decision 10 |
| P3-8 port 80 | The same allow-list as 443, redirect only. Decisions 3, 6 |
| P3-9 callback cleanup | Every callback ends in a `303` to a fixed clean URL after clearing the handle; `no-store` and `no-referrer`. Decision 4.3 |
| P3-10 unhandled-error logging | Recorded as an M3.3c finding and requirement; a check after the corrections found the access line also falls back to the raw path, and M3.3c covers both lines. Decision 10; `docs/tasks/current.md` |
| P3-11 historical and production-hostname wording | Production hostnames are Milestone 8's and the portal stays same-origin; the stale M3.0 "this branch" wording in the task file's M2.4 section corrected. Decision 3; the roadmap; `docs/tasks/current.md` |

## Final correction pass

Six questions raised after the review corrections were decided on 2026-09-13, again in these
documents only; no code, migration, dependency, Terraform, workflow, verification script,
snapshot or §17 text changed.

| Question | Decision, and where it lives |
| --- | --- |
| The identity-binding task held the authenticator credential, which an overridden command could use to issue sessions | A dedicated identity-binding login role with no table privilege and no role membership, holding `EXECUTE` on one `SECURITY DEFINER` binding function, with a separate `NOLOGIN` owner where review needs one. The function is idempotent, refuses conflicts, never binds by email and audits atomically. The task receives only that credential and the minimum Cognito read, its command is assumed overridable, and it cannot reach the broker. Decisions 1, 3, 5, 6, 7 |
| `staging-plan` and `staging-apply` were not tied to `main`, reviewers or protected workflows | Both environments allow only `main`, require reviewers, prevent self-review where supported and hold no permanent AWS credential. Workflows are manually dispatched from the default branch, check `refs/heads/main` and the commit's reachability and approval, are protected by `CODEOWNERS` and branch protection, and are disabled for forks and pull requests. OIDC trust names the exact repository and environment. Plan and apply roles are distinct, and the apply role has a permissions boundary. All are required M3.3b acceptance tests. Decisions 1, 9.1 |
| Apply trusted metadata the plan role wrote | A dedicated plan bucket separate from state, content-addressed keys, versioning and Object Lock governance retention. The plan role can create but not overwrite, unlock or apply. The human starts apply with the object key, version ID and expected SHA-256, visible in the approval request. Apply recomputes the checksum, verifies the commit, recomputes the provider-lock digest, checks the Terraform version, relies on Terraform's saved-plan state checks, and fails closed on any mismatch, missing version, expired plan or unapproved commit. Decisions 7, 8, 9.2 |
| Deleting a plan in a versioned bucket does not remove its versions | One-day governance retention tied to the 24-hour recommended lifetime. Lifecycle expiry of current and noncurrent versions and delete markers. Neither role can bypass retention or read arbitrary history. Apply refuses a plan older than the allowed age. State keeps its own retention and never expires with plans. Decisions 8, 9.3 |
| The allow-list check compared strings | Terraform validation plus an independently tested policy check requiring canonical CIDRs, IPv4 `/24` or narrower, IPv6 `/64` or narrower, at most 16 entries proposed, no non-routable, duplicate or overlapping entries, a maximum address-space allowance and a non-empty list. Human review, no committed reviewer CIDRs, the same list on ports 80 and 443, and the broker's NAT EIP added separately as a `/32` to the Cognito WAF only. Decisions 3, 6, 8 |
| Browser evidence could capture credentials | No raw traces, HAR files, videos, storage state, console or network dumps or failure screenshots from authentication journeys. An allow-listed summary, fixed failure classifications and opaque correlation IDs, sanitized callback and logout assertions, separately approved screenshots of clean synthetic routes only, a blocking pre-commit secret scan, and zero-retention raw artifacts that are never uploaded. Tooling in M3.3c. Decisions 1, 10 |
