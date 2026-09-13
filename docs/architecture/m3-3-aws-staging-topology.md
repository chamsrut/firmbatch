# Milestone 3.3 — protected AWS staging topology

**Status:** Architecture, adopted by ADR 0011 (Milestone 3.3a, 2026-09-13), corrected the same
day after an independent architecture review and again in a final correction pass (ADR 0011
"Review corrections" and "Final correction pass"). **Nothing here exists**: no AWS resource,
no Terraform, no image, no pipeline, no broker, no bootstrap or binding command, no binding
role, no evidence tooling. This document says what M3.3b, M3.3c and M3.3d build, and in what
order, and it authorizes none of it. **Deploying is M3.3d's, after a reviewed plan, a current
cost estimate and explicit human authorization.**
**Decision record:** `docs/adr/0011-aws-staging-cognito-and-terraform-delivery.md`
**Sequence:** `docs/firmbatch-v1-roadmap.md` Milestone 3.3 (a–d)
**Target:** `docs/architecture/v1-target-architecture.md` §14 (the AWS shape), §14.1 (this
staging subset), §17 (every invariant, preserved)
**What the code does now:** `docs/STATE.md`

Every hostname, CIDR, account, region, lifetime and threshold below is a **deployment
parameter** until a human confirms it at M3.3d; the table at the end lists them.
`eu-central-1` is a recommendation, not a decision. **Milestone 3.3 establishes only the
staging browser origin**; production public hostnames are Milestone 8's decision.

## 1. The shape in one picture

```text
   reviewer networks (validated, reviewed CIDRs)          the broker's NAT EIP, as a /32
            │                                                            │
            ▼                                                            ▼
 ┌─────────────────────────────────────────────────┐   ┌──────────────────────────────────┐
 │ https://staging.app.firmbatch.com               │   │ https://auth.staging.app.…       │
 │ Route 53 alias → internet-facing ALB            │   │ Cognito User Pool, Managed       │
 │ regional ACM cert · no WAF · no access logs     │   │ Login v2, custom domain          │
 │ 443 and 80 admit the SAME reviewed allow-list   │   │ cert in us-east-1                │
 │ 80: redirect to 443 and nothing else            │   │ Cognito WAF: reviewed CIDRs,     │
 │ exact-host rule                                 │   │ plus the NAT EIP /32 separately  │
 └────────────┬───────────────────────┬────────────┘   └───────────────┬──────────────────┘
              │ / , /v1/*             │ /auth/*                        │ code exchange, JWKS,
              ▼                       ▼                                │ revoke, logout; a user
 ┌────────────────────────┐ ┌───────────────────────────┐              │ read for binding
 │ ECS service: web/API   │ │ ECS service: identity     │◄─────────────┤ (all via NAT)
 │ serves compiled portal │ │ broker                    │              │
 │ + /v1 API              │ │ authenticator DB role     │              │
 │ application DB role    │ │ Cognito client secret     │              │
 │ no public IP           │ │ KMS grant (refresh tok.)  │              │
 └───────────┬────────────┘ └────────────┬──────────────┘              │
             │ TLS, verify-full          │ TLS, verify-full            │
             ▼                           ▼                             │
 ┌──────────────────────────────────────────────────────────────┐      │
 │ RDS PostgreSQL 16 · private subnets in two AZs · Single-AZ    │      │
 │ encrypted · rds.force_ssl=1 · 7-day PITR · deletion protect.  │      │
 │ ingress: five security groups, one per service or task        │      │
 └──────────────────────────────────────────────────────────────┘      │
        ▲                        ▲                        ▲            │
 one-off task: bootstrap   one-off task: migrate   one-off task: identity-binding
 RDS-managed master        migration credential;   dedicated binding login role:
 secret; creates/rotates   `migrate upgrade`       EXECUTE on one binding function
 login roles; writes       before any service      and nothing else; manual operator
 values into Secrets       rollout                 invocation; command assumed
 Manager containers                                overridable; audited atomically

 Every box above runs the same immutable image digest. Only the two services are long-running.
```

The **operator capacity agent** appears nowhere in this picture. It is separate
operator-side software (target §2, §4.2; §17 invariant 11) and is not part of the customer
portal deployment; the identity-binding task is not it. No GPU provider, worker, payload
bucket, queue or settlement component is deployed by Milestone 3.3.

## 2. Origin, DNS and edge

| Item | Decision |
| --- | --- |
| Customer origin | **One**: `https://staging.app.firmbatch.com`. No `staging.api.` host. The browser reaches the API same-origin under `/v1/*`; a second host cannot share the `__Host-` cookies (ADR 0010). |
| Production hostnames | **Not decided here.** Milestone 8 chooses them. Any separate production API hostname serves non-browser clients or reviewed edge routing; the customer portal stays same-origin. |
| DNS | Route 53 hosted zone (parameter); an alias record to the ALB. The Cognito custom domain needs its parent name (`staging.app.firmbatch.com`) to resolve first, which this alias provides. |
| Certificate | Regional ACM certificate in the staging region for the ALB, DNS-validated in the zone. |
| ALB | Internet-facing, in public subnets. Its security group admits **443 and 80 from the same reviewed allow-list** and nothing else; **80's only action is the redirect to 443**. Listener rule: exact `Host` match; any other host receives a fixed refusal. Invalid header fields dropped; strictest desync mitigation. **M3.3 adds no WAF to the ALB**: its security-group allow-list protects it. **Access logs disabled** for M3.3 (the callback query carries `code` and `state`). |
| Allow-list | Shared by 443 and 80, **explicitly reviewed by a human**, supplied at plan time from protected configuration outside the repository and **never committed**. Validated **structurally and fail-closed** by Terraform variable validation **and** an independently tested policy check: **non-empty**; every entry a **valid, canonical IPv4 or IPv6 CIDR**; **IPv4 `/24` or narrower**, **IPv6 `/64` or narrower**; **at most 16 entries** (proposed); **no unspecified, multicast, loopback, link-local or otherwise non-routable range**; **no duplicate or overlapping entries**; **no combination exceeding the configured maximum address-space allowance**. |

**ALB path routing** (priority order):

| Rule | Condition | Target group |
| --- | --- | --- |
| 1 | host ≠ `staging.app.firmbatch.com` | fixed response, refused |
| 2 | path `/auth/*` | identity-broker service |
| 3 | path `/v1/*` | web/API service |
| 4 | default (`/` and every frontend route) | web/API service |

Application-side, both services still validate the exact `Host` and keep the `Origin`
allow-list on every cookie-authenticated mutation. The ALB rule is defence in depth, not
the boundary.

## 3. Compute: two services, three one-off tasks, one image

**One immutable image**, built once per deployment, in ECR with immutable tags and
scan-on-push, deployed **by digest** to every task definition below.

| Task definition | Kind | Entry point (M3.3c) | Database credential | Other secret and AWS access | Egress beyond the common set |
| --- | --- | --- | --- | --- | --- |
| `web-api` | ECS service (≥1 task; no autoscaling in M3.3) | the Starlette API on `/v1/*`, serving the compiled portal for `/` and frontend routes | `FIRMBATCH_DATABASE_URL` — the **application** role | none | RDS |
| `identity-broker` | ECS service (≥1 task) | the `/auth/*` broker | `FIRMBATCH_AUTHENTICATOR_DATABASE_URL` — the **authenticator** role | Cognito client secret; KMS **Encrypt/Decrypt** on the refresh-token key with the encryption-context condition | RDS; Cognito token, JWKS, revoke and logout endpoints, and KMS, through the NAT EIP |
| `migrate` | one-off task, run before every service rollout | `python3 -m firmbatch.control_plane.migrate upgrade` | `FIRMBATCH_MIGRATION_DATABASE_URL` — the **migration** (schema-owner) role | none | RDS |
| `bootstrap` | one-off task, run once and on rotation | the production database bootstrap command: creates and rotates the login roles and writes their values into the pre-created Secrets Manager containers | the **RDS-managed master secret** | `secretsmanager:PutSecretValue` on exactly the runtime containers | RDS |
| `identity-binding` | one-off task, **invoked manually** by an operator | the identity-binding command (§6.6) | the dedicated **identity-binding** login role only (§6.6), **for its run** — never the authenticator | the minimum Cognito read that validates the selected subject in the one staging pool; **no other secret or AWS permission** | RDS; the Cognito user-pool API through the NAT EIP |

Rules:

- **Every task, service or one-off, also needs the common set**: ECR for the image pull,
  Secrets Manager for secret injection and CloudWatch Logs for its log stream, reached
  through its own network interface and the NAT, since only S3 has a gateway endpoint. The
  table's last column lists only what each adds.
- **No long-running service holds the schema-owner, migration or master credential**, and no
  one-off task holds a credential it does not name in the table.
- Each task's **execution role** may read exactly the secrets its own container definition
  names, and no other; each **task role** carries only the AWS permissions in the table.
- **The binding task's command is assumed overridable.** `RunTask` lets its caller override a
  container's command, so arbitrary code may run inside `identity-binding`. It then holds a
  database credential that executes one binding function and nothing else, a Cognito
  permission that only reads, and no other secret, so it still cannot issue a session or
  reach broader database authority.
- **The binding workflow cannot reach the broker.** The operator's run permission is limited
  to the `identity-binding` task definition, and its `iam:PassRole` to that task's own
  execution and task roles, so it can start no other task and cannot run the binding task
  under another task's roles. The long-running broker keeps the separate authenticator and
  session boundary.
- The **provisioning** role and the **`NOLOGIN` lifecycle writer** are wired by
  `db/roles.py` as today; no service or task holds a provisioning credential, and the writer
  has none by construction.
- Tasks have **no public IP**. The services' security groups accept traffic from the ALB
  security group only; the one-off tasks accept no inbound traffic. **RDS accepts PostgreSQL
  from five security groups** — `web-api`, `identity-broker`, `migrate`, `bootstrap`,
  `identity-binding` — each its own group with its own credential boundary.
- **M3.3b defines these five task definitions as scaffolding** — parameterized by image
  digest, command and secret reference. **None is operational until M3.3c's programs,
  dependencies and image have passed review**, and M3.3b cannot be applied before then.
- **Serving the portal from the web/API image**: M3.3b's container-build foundation copies
  the built `portal/dist` into the image; the web/API entry point that serves it — single-page
  fallback, immutable cache headers on hashed assets, `no-store` on the HTML shell — and its
  tests are **M3.3c's**. CloudFront and S3 static hosting are deferred (ADR 0011 decision 3).
- **The staging environment configuration mode is M3.3c's**: `Secure` cookies with the
  `__Host-` names, `https://` origins only, no capture email adapter, and the local
  signup, login, verification, recovery, password-change and `/v1/account/logout` routes
  disabled for the browser — defined without weakening any production control. Today
  `Environment` has only `test` and `production`.

## 4. Network

| Layer | Decision |
| --- | --- |
| VPC | One VPC (CIDR: parameter), two AZs. |
| Public subnets | ALB and the NAT gateway only. |
| Private subnets | ECS tasks; no public IP; default route to the NAT gateway. |
| DB subnets | RDS only, across two AZs (Single-AZ instance); no route to the internet. |
| NAT | **One** NAT gateway with an Elastic IP — the fixed egress address the Cognito WAF admits as a separate `/32`. Multiple NAT gateways are deferred. |
| Endpoints | An **S3 gateway endpoint** (free) so image layers and any S3 use do not cross the NAT; interface endpoints are added only if a cost line justifies them. |
| Security groups | One per service and one per one-off task; RDS ingress from exactly those five, the identity-binding group's reach limited by its credential to one function; ALB ingress from the reviewed allow-list on 443 and 80. |
| ALB protection | The structurally validated security-group allow-list. **No WAF on the ALB** in M3.3. |
| WAF on Cognito | A regional web ACL associated with the user pool (the **identity** module's): allow the same reviewed allow-list and, **added separately, the identity broker's NAT EIP as a `/32`**, which never enters the ALB allow-list; block everything else; **no CAPTCHA or challenge action** on the managed-login paths, because TOTP enrollment happens there. |
| Egress | Every task reaches ECR, Secrets Manager and CloudWatch Logs through the NAT; the broker also reaches Cognito and KMS, and the binding task Cognito; RDS is reached privately. With only an S3 gateway endpoint, that outbound HTTPS path is routed to the internet through the NAT, and security groups written for it do not narrow it to those services. Whether and how to narrow it is an open question (`docs/tasks/current.md`), not a decision made here. |

## 5. PostgreSQL on RDS

| Item | Decision |
| --- | --- |
| Engine | RDS PostgreSQL **16**; the exact supported minor is checked immediately before deployment. |
| Placement | Private DB subnet group across two AZs; **Single-AZ** instance for staging (Multi-AZ deferred). |
| Storage | Encrypted (KMS). |
| Parameters | An explicit PostgreSQL 16 parameter group with **`rds.force_ssl = 1`**. |
| Client TLS | **`sslmode=verify-full`** with `sslrootcert` pointing at the RDS certificate bundle baked into the image; both keys are already accepted by the URL parser, so this is configuration, confirmed by M3.3c. |
| Backups | **Seven-day** automated backup and point-in-time-recovery retention. |
| Protection | **Deletion protection on**; **final snapshot required**; no `skip_final_snapshot`. |
| Replicas | **None** in M3.3; writable-primary routing preserved. |
| Master credential | **RDS-managed** in Secrets Manager; readable by the bootstrap task alone. |
| Access | Not publicly accessible; PostgreSQL from the five approved security groups only, each through its own credential boundary. |

**Why RDS is a qualification and not an assumption.** `rds_superuser` is not a PostgreSQL
superuser: no `SUPERUSER` attribute, no `pg_authid`, and ownership and membership semantics
that differ from both clusters the suite runs on today (a superuser in CI, a non-superuser
administrator locally). The repository already reads `pg_roles` rather than `pg_authid`,
which is right for RDS. **M3.3d qualifies, against the deployed instance and records under
`docs/evidence/m3/`:**

1. migrations `0001`–`0006` upgrade cleanly under the migration credential, and `0007` once
   M3.3c adds it;
2. `FORCE` row-level security is in force on every tenant relation;
3. every `SECURITY DEFINER` function is owned by the schema owner, or by the dedicated
   `NOLOGIN` owner ADR 0011 decision 5 allows for the binding function, and never by the
   master user;
4. the `NOLOGIN` lifecycle writer installs, owns its two entry points, and the `SET ROLE`
   and inheritance semantics behave as the local tests assert;
5. the identity-binding login role's catalogue is `EXECUTE` on its one function and nothing
   else — no table or column privilege, no role membership — and, as that role, an attempt to
   open a session, issue a credential, change a membership, assume a role or write a table
   is refused;
6. the grant and column-grant inventories and the ACL sanitiser reconcile at head;
7. downgrade to each earlier revision and re-upgrade, with role reconciliation at each;
8. clean teardown at the end of the environment's life: final snapshot, then the instance,
   with deletion protection lifted by a human.

## 6. Identity: Cognito authenticates, Firmbatch authorizes

### 6.1 The pool and the client

| Item | Decision |
| --- | --- |
| Pool | One per environment, in the staging account and region. |
| Sign-in | Email-only, **case-insensitive** usernames; verified email required. |
| Creation | **Invite-only**: administrator-created users; no self-signup in protected staging. |
| MFA | Password **plus required TOTP**. |
| Existence errors | `PreventUserExistenceErrors` enabled. |
| Login UI | **Managed Login v2** at the custom domain (proposed `auth.staging.app.firmbatch.com`, **under the same registrable Firmbatch domain as the customer origin**; parameter). Certificate **in `us-east-1`**. Requires at least the Essentials feature plan, priced in the cost estimate. |
| Identity providers | The pool itself only. No social providers; no Identity Pools. |
| App client | **Confidential** traditional-web client with a secret; **authorization-code grant only**; **PKCE S256**; **exact** callback URL `https://staging.app.firmbatch.com/auth/callback` and logout URL `https://staging.app.firmbatch.com/` (fixed, clean; parameters); scopes **`openid email`** only; **refresh-token rotation** on; **5-minute** access and ID tokens; **8-hour** refresh-token validity. |
| Not requested | `aws.cognito.signin.user.admin`; self-service email or profile change (deferred). |
| Sender | Cognito's invitation and recovery mail through an SES identity (parameter). |
| WAF | The Cognito-associated IP allow-list of §4. |

### 6.2 Cookies

| Cookie | Name | Attributes | What it is |
| --- | --- | --- | --- |
| Session | **`__Host-fb_session`** wherever cookies are `Secure`; `fb_session` only as a development-only name when HTTPS is deliberately unavailable locally | `Secure`, `HttpOnly`, `Path=/`, no `Domain`, **`SameSite=Strict`** | The Firmbatch session credential. **Renamed in M3.3c** — today it is `fb_session` everywhere. A secure deployment reads only `__Host-fb_session`, never falling back to the unprefixed name. No deployed-cookie migration: M3.2 was never deployed. |
| CSRF | `__Host-fb_csrf` wherever `Secure`; `fb_csrf` development-only | `Secure`, readable by script, `Path=/`, no `Domain`, `SameSite=Strict` | Unchanged from M3.2 (ADR 0010 decision 3). Not a credential. |
| OIDC transaction handle | **`__Host-fb_oidc`** (or a name M3.3c's review settles) | `Secure`, `HttpOnly`, `Path=/`, no `Domain`, **`SameSite=Lax`, deliberately** | Opaque, single-use, short-lived, expiring with the server-side transaction it references. Contains **no Cognito token, authorization code, `nonce` or PKCE verifier**. **Not an authenticated Firmbatch session**; authorizes nothing on `/v1/*`. Cleared by every callback. |
| Cognito managed login | Cognito's | Cognito's | On the authentication domain only. Never read by Firmbatch. Cleared through Cognito's logout endpoint. |

**Host-only is not enough; the prefix is what protects the name.** A cookie set without
`Domain` is host-only, but that does not prevent a sibling or parent-domain host from setting
**its own cookie with the same name** and `Domain=firmbatch.com`, which the browser then sends
beside the real one. The **`__Host-` prefix supplies the browser-enforced protection**: a
browser refuses to store a `__Host-` cookie that carries a `Domain`, lacks `Secure` or has a
`Path` other than `/`. That is why the session cookie gains the prefix in M3.3c, as the CSRF
cookie already has it.

**Why the handle is `Lax` and the session `Strict`.** The callback is a top-level navigation
initiated from the authentication host. The proposed authentication host shares the customer
origin's registrable domain today, but the handle is `Lax` so that the callback keeps working
if that ever stops being true; it can afford to be, because it is an opaque single-use
reference and not a credential. **`__Host-fb_session` stays `Strict`**: it is set on the
callback's `303` response and next sent on the portal's own same-origin requests, and nothing
relies on it being sent on the callback request itself. M3.3d's browser journey asserts that
sequence against the real URL, as a sanitized assertion rather than captured traffic (§10).

### 6.3 Login

```text
browser                     identity broker (/auth/*)                 Cognito
  │  GET /auth/login             │                                       │
  │─────────────────────────────►│ mint state, nonce, PKCE verifier and  │
  │                              │ an opaque handle; store the first     │
  │                              │ three server-side, keyed by the       │
  │                              │ handle's fingerprint; single-use;     │
  │                              │ short expiry                          │
  │  302 → authorize URL         │                                       │
  │  Set-Cookie: __Host-fb_oidc  │                                       │
  │  (Secure, HttpOnly, Path=/,  │                                       │
  │   no Domain, SameSite=Lax)   │                                       │
  │◄─────────────────────────────│                                       │
  │  managed login: password + TOTP (Cognito's cookie on its own host)   │
  │─────────────────────────────────────────────────────────────────────►│
  │  302 → /auth/callback?code=…&state=…   (or ?error=…)                 │
  │◄─────────────────────────────────────────────────────────────────────│
  │  GET /auth/callback          │                                       │
  │─────────────────────────────►│ handle ↔ stored state: match,         │
  │                              │ unexpired, unconsumed → consume once  │
  │                              │ POST /oauth2/token (client secret +   │
  │                              │ code_verifier), from the NAT EIP      │
  │                              │──────────────────────────────────────►│
  │                              │◄──────────────────────────────────────│
  │                              │ validate: signature (JWKS by kid),    │
  │                              │ exp, exact iss, token_use, aud /      │
  │                              │ client_id, nonce, scope               │
  │                              │ (issuer, sub) bound? → account;       │
  │                              │ else the neutral refusal; never email │
  │                              │ open a Firmbatch session via the      │
  │                              │ authenticator-only entry point;       │
  │                              │ encrypt + store the refresh token     │
  │                              │ (KMS, context = session + account)    │
  │  303 → fixed clean URL       │                                       │
  │  clear __Host-fb_oidc        │                                       │
  │  on success: set             │                                       │
  │  __Host-fb_session and       │                                       │
  │  __Host-fb_csrf              │                                       │
  │  Cache-Control: no-store     │                                       │
  │  Referrer-Policy: no-referrer│                                       │
  │◄─────────────────────────────│                                       │
```

The browser receives **no Cognito token** at any step. The single-use authorization code is
the only Cognito artefact that transits it, and it is inert without the verifier and the
client secret the broker holds.

### 6.4 Every callback ends in a clean redirect

- **Every callback, successful or failed, answers `303` to a fixed, clean Firmbatch URL**
  after clearing the one-time transaction handle: a provider `error`, a missing, replayed or
  mismatched `state` or handle, an expired transaction, a failed exchange, a failed
  validation and an unbound identity all take the same path.
- **No response body is ever rendered at a URL that retains `code`, `state`,
  `error_description` or any other provider parameter**, so no page is ever displayed at a URL
  that carries them.
- The clean destination displays **only a neutral error identifier** on failure.
- Callback responses carry **`Cache-Control: no-store`** and **`Referrer-Policy:
  no-referrer`**.
- A failed callback sets no session cookie.

### 6.5 Logout

```text
portal → POST /auth/logout  (top-level form navigation; __Host-fb_session cookie; the CSRF
                             secret in the form body, because a form navigation cannot set
                             X-CSRF-Token; Origin checked)
  broker: authenticator-only entry point verifies the session and the CSRF secret
          against the session row, revokes the Firmbatch session, returns the
          refresh-token ciphertext
  broker: KMS decrypt (context checked) → POST /oauth2/revoke (best effort; a
          failure is metadata, never a reason to keep the session)
  broker: clear __Host-fb_session and __Host-fb_csrf → 303 → Cognito /logout?client_id&logout_uri
  Cognito: clears its managed-login cookie → 302 → the fixed, clean Firmbatch logout URL
```

- **In AWS mode, `/v1/account/logout` is disabled as a portal and browser logout route**;
  the portal uses `/auth/logout`. The local `/v1/account/logout` behaviour stays for
  **development and test mode only**.
- **M3.3c owns the route-mode change and its tests**, including the portal's sign-out
  adaptation, which keeps ADR 0010 decision 9's rule that a sign-out that did not end the
  session is never presented as signed out.
- A `Strict` session cookie is not sent on a cross-site request, so a third-party page
  cannot trigger the logout; the CSRF check inside the entry point is the second layer.

### 6.6 The identity mapping, the binding boundary and the binding task (M3.3c, migration `0007`)

```text
auth_identity(provider, issuer, subject, account_id, created_at, last_seen_at)
UNIQUE (issuer, subject)
```

- Protected identity plane: no grant to any runtime role; `SECURITY DEFINER` functions;
  authenticator-only entry points for **opening a federated session** from a bound identity.
- **Never bound by email match.** An unbound `(issuer, subject)` is the neutral refusal.
- **No legacy-password migration**: no real M3.1/M3.2 user exists. Local password
  authentication stays for development, tests and a bounded rollback window, and the web/API
  service in AWS mode serves none of the local signup, login, verification, recovery,
  password-change or logout routes to the browser and holds no authenticator credential.
- **Refresh tokens**: KMS-encrypted with an encryption context binding them to the session
  and account, stored in protected server-side state reachable through authenticator-only
  functions; never in the browser, a log line or the core API. Used for revocation at logout
  and, if M3.3c chooses it, a bounded server-side re-validation of the identity.
- The Firmbatch session TTL is set to **eight hours** (`FIRMBATCH_API_SESSION_TTL_SECONDS`)
  to match the refresh-token validity; the code accepts it today.

**The identity-binding database boundary.**

| Element | Rule |
| --- | --- |
| Login role | A dedicated **identity-binding login role**. **No table privileges.** **No membership** in the authenticator, application, provisioning, migration or owner roles. |
| Grant | **`EXECUTE` on only one** narrowly scoped identity-binding function. |
| Function owner | `SECURITY DEFINER`; owned by a **separate `NOLOGIN` owner** holding only what binding requires, where M3.3c's review finds an owner boundary is needed (the M2.4 lifecycle-writer pattern, ADR 0007). |
| What the role cannot do | Create browser sessions, issue API credentials, change memberships, assume another role, execute general authenticator functions, or write any table directly. |
| What the function does | Binds **one explicit `(issuer, subject)`** to **one explicit unused invitation or account**; **never binds by email equality**; **idempotent** for an identical request; **refuses a conflicting binding**; **records a Firmbatch audit event atomically** — a binding with its audit event, or a refusal with its refusal audit event and no binding, answering with the neutral refusal rather than raising so the record commits. |

**A constraint on the binding command.** The repository's ordinary transaction preamble calls
`auth_tenant_id`, which reads `auth_context`, which is why the authenticator's grant holds both
(ADR 0009, "Security corrections"). A role whose entire grant is one function cannot use that
preamble unchanged, so the binding command's database path must not depend on it, and M3.3c's
tests prove from the catalogue that the role's grant is the one function.

**Binding happens in the `identity-binding` one-off task, and nowhere else.**

```text
operator (reviewed, authenticated operator workflow or AWS SSO session; never automatic,
          never from a pull request; run permission for this task definition only,
          PassRole for its own roles only)
  → RunTask identity-binding  with non-secret identifiers only:
        the Cognito subject · the target account ID, or the unused invitation's row ID,
        never its acceptance token ·
        a change reference                     (no email address, token or password —
                                                 task overrides are recorded by AWS)
  task: validate the subject in the one staging pool (minimum Cognito read), confirm the
        exact issuer
  task: call the one binding function as the dedicated binding login role
        → binding + audit event, atomically; or refusal + refusal audit event, atomically;
          identical repeat → the existing outcome; conflict → refused
  task: exit; no endpoint, no service, nothing retained
```

- Separate from the web/API service, the identity broker, the bootstrap task and the
  migration task, and **distinct from the operator capacity agent**.
- Receives **only the identity-binding credential**, for its run, and **no authenticator,
  schema-owner, migration or master credential**.
- **Its command is assumed overridable**; the credential is designed so that arbitrary code
  inside the task still cannot issue sessions or obtain broader database authority.
- **Never binds on email equality**; **logs no email address or token**; answers every
  refusal with the neutral refusal.
- **For M3.3c to specify and test:** where the account-plane binding audit record lives,
  since an account has no tenant audit trail today (ADR 0009 decision 10); and the exact
  semantics of binding to an unused invitation.

### 6.7 What Cognito does and does not decide

Cognito decides **who** signed in. Firmbatch decides **what they may do**: the membership,
role and workspace are re-derived at every bind exactly as ADR 0009 states; the session is
an ordinary Firmbatch session; the API accepts no JWT; no Cognito group, attribute or claim
is a source of authorization. Invariant 1 (PostgreSQL is authoritative) and invariant 11
(customer, operator and supplier interfaces separate) are unchanged.

## 7. Secrets, state and plans

| Secret or sensitive material | Created by | Value written by | Read by |
| --- | --- | --- | --- |
| RDS master credential | RDS (managed) | RDS | `bootstrap` task only |
| application DB URL | Terraform (container only) | `bootstrap` task | `web-api` execution role |
| authenticator DB URL | Terraform (container only) | `bootstrap` task | `identity-broker` execution role only |
| identity-binding DB URL | Terraform (container only) | `bootstrap` task | `identity-binding` execution role only |
| migration DB URL | Terraform (container only) | `bootstrap` task | `migrate` task execution role |
| Cognito client secret | Terraform (**in state** — the acknowledged exception) | Terraform | `identity-broker` execution role |
| refresh-token KMS key | Terraform | — | `identity-broker` task role (Encrypt/Decrypt with context condition) |
| Terraform state | Terraform, under its environment's key in the **state bucket** | Terraform | the `staging-plan` and `staging-apply` roles; a separately authenticated operator session |
| Saved binary plans | the trusted plan job, as content-addressed objects in the separate **plan bucket** under Object Lock governance retention | the `staging-plan` role, creating new objects only | the `staging-apply` role, for the one approved object version only; a separately authenticated operator session |

- Terraform creates **secret containers without versions**; the bootstrap task puts the
  values, so **no database password enters Terraform state**.
- Terraform runs **no SQL**: no PostgreSQL provider, no `local-exec`, no `remote-exec`.
- **Terraform state and saved plan files are equally sensitive.** State holds the Cognito
  client secret, and a saved plan carries the prior state with it. State lives only in the
  KMS-encrypted, versioned state bucket; plans live only in the separate KMS-encrypted plan
  bucket. `sensitive` output markers remove nothing from either.
- **No static AWS access keys** anywhere, including GitHub environment secrets: humans use
  short-lived credentials; CI uses OIDC.

## 8. Terraform layout and module expectations

```text
infra/terraform/
  bootstrap/                 the state bucket (versioned, KMS-encrypted, public-blocked,
                             its own retention) and the separate plan bucket (versioned,
                             KMS-encrypted, public-blocked, Object Lock governance
                             retention, lifecycle expiry of plan versions and delete
                             markers); their KMS keys; then `init -migrate-state` moves
                             the bootstrap's own state into the state bucket
  policy/                    the reviewer allow-list policy check and its own tests
  modules/
    network/  edge/  compute/  database/  identity/  secrets/  observability/  delivery/
  environments/
    staging/                 root: one state key, pinned versions, .terraform.lock.hcl,
                             a values-free tfvars example
    production/README.md     "a separate root, account and state; not created by M3"
```

| Module | Expectation |
| --- | --- |
| `network` | VPC, subnets, the NAT gateway and EIP, the S3 gateway endpoint, and one security group per service and per one-off task, with RDS ingress from exactly those five |
| `edge` | Route 53 records, the regional ACM certificate, the ALB, the 443 listener and rules, the 80 listener whose only action is the HTTPS redirect, both fed by the one structurally validated allow-list variable. **No WAF.** |
| `compute` | The ECS cluster; the `web-api` and `identity-broker` services; the `migrate`, `bootstrap` and `identity-binding` one-off task definitions; each parameterized by image digest, command and secret reference; not operational until M3.3c's image passes review |
| `database` | RDS, the parameter group, the subnet group, the RDS-managed master secret |
| `identity` | The Cognito user pool, domain, managed-login branding, app client, the `us-east-1` certificate, and **the Cognito-associated WAF** with the reviewed list and the separate NAT EIP `/32` |
| `secrets` | Secrets Manager containers with no versions, including the identity-binding DB URL; the refresh-token KMS key and grants |
| `observability` | CloudWatch log groups with explicit retention, alarms, the budget, and the retention, encryption and access settings M3.3d's review of AWS-managed logs requires (§10) |
| `delivery` | ECR; the GitHub OIDC provider; the **distinct** `staging-plan` and `staging-apply` roles, each trusting only its exact repository and environment, the apply role under a **permissions boundary**; the operator permission to run only `identity-binding`, with `PassRole` for its own roles only |

- Separate roots and state keys per environment; **no workspaces**.
- **S3 backend with `use_lockfile = true`** in the state bucket; no DynamoDB lock table.
- **State and plans never share a bucket**; state is never expired with plan artifacts.
- Terraform and provider versions **pinned**; **`.terraform.lock.hcl` committed**.
- Provider aliases: default `eu-central-1`; `us-east-1` for the Cognito certificate only.
- Git excludes (added with the code in M3.3b): `*.tfstate`, `*.tfstate.*`, `*.tfplan`,
  `*.tfvars` (a `*.tfvars.example` with no values is tracked), `crash.log`, `crash.*.log`,
  `override.tf`, `override.tf.json`, `*_override.tf`, `*_override.tf.json`, `.terraform/`.
  No reviewer CIDR is committed; tests use synthetic entries.
- Account enforcement: `allowed_account_ids` on the provider plus a caller-identity
  precondition; region as a variable with the recommended default and a confirmation step
  outside Terraform.
- The policy guard already denies `apply`, `destroy`, `import`, `taint`, `untaint` and
  `state rm|mv|push`, and allows `fmt`, `init`, `validate`, `test` and `plan`. **`terraform
  test` is not harmless**: its `run` blocks apply real resources unless they use
  `command = plan` or mocked providers, so M3.3b's tests run with mocks or plan-only and with
  no credentials. `AGENTS.md`'s rule, not the hook, keeps an agent from creating a resource.

## 9. Delivery pipeline

```text
pull request ──► static checks — no GitHub environment, no AWS credential
                 fmt -check · init -backend=false · validate · lint/policy (incl. the
                 allow-list policy check) · terraform test with mocks

manual dispatch, default branch only; github.ref must be exactly refs/heads/main;
source commit must be reachable from and currently approved on protected main;
workflow files under CODEOWNERS and branch protection; never from a fork or pull request
   │
   ├─► environment `staging-plan`  (main only · required reviewers · self-review prevented
   │     where supported · no permanent AWS credential)
   │     plan role, OIDC sub = repo:chamsrut/firmbatch:environment:staging-plan
   │     read + refresh state · state lockfile while planning · NO apply permission
   │     terraform plan -out → NEW object in the plan bucket, key = source commit + SHA-256
   │       (versioned · Object Lock governance retention · no overwrite of an approved
   │        version · no retention change · no historical read)
   │     GitHub shows ONLY: action counts · policy results · cost summary · checksum
   │     (no binary plan, no full rendering, no artifact, nothing in a public log)
   │
   │   human inspects the full plan in a separately authenticated operator session
   │
   ├─► manual dispatch of apply with the reviewed object's KEY, VERSION ID and expected SHA-256
   │     → environment `staging-apply`  (main only · required reviewers · self-review
   │       prevented where supported · no permanent AWS credential); the key, version ID
   │       and SHA-256 are visible in the approval request
   │     apply role, OIDC sub = repo:chamsrut/firmbatch:environment:staging-apply,
   │       under a permissions boundary, not assumable through staging-plan
   │     download THAT object version
   │     recompute SHA-256 · check out and verify the source commit named by the key ·
   │     recompute the provider-lock digest · check the Terraform version ·
   │     refuse a plan older than the allowed age
   │     terraform apply <that plan>  (Terraform rejects stale lineage or serial)
   │     any mismatch · missing version · expired plan · commit no longer reachable
   │       from or approved on main → FAIL CLOSED; a new plan is NEVER generated here
   │
   └─► application deployment — a separate, later stage; its identity and approval are
         specified with M3.3b's delivery structure, and neither approval above authorizes it
         build image → ECR (immutable tag, scan) → run `migrate` task by digest
         → abort on migration failure → roll services to the digest
         → ECS circuit breaker rolls back an unhealthy rollout

plan bucket lifecycle: Object Lock governance retention (proposed one day, tied to the
saved-plan lifetime, 24 hours recommended) → expiry of current and noncurrent plan versions
and of delete markers. The state bucket keeps its own retention and is never expired with it.
```

- **No untrusted pull request receives AWS credentials.**
- **Every property above is a required M3.3b acceptance test**, failing when absent: the
  environments' `main`-only rules, reviewers, self-review prevention and absence of
  permanent AWS credentials; the workflows' manual dispatch, `refs/heads/main` check,
  reachability and approval check, `CODEOWNERS` and branch protection, and fork and
  pull-request refusal; the exact-repository-and-environment OIDC trust; distinct roles and
  the apply role's permissions boundary and non-assumability through `staging-plan`; the plan
  role's create-only, no-overwrite, no-retention-change, no-apply permissions; and the apply
  job's fail-closed verification.
- **Approval of planning does not authorize applying.** Both environments require human
  approval, because the plan identity can read sensitive state.
- **Plan-produced metadata may aid review but is never an authority for apply.**
- **The saved plan is never a GitHub artifact.** Deleting a current object in the versioned
  plan bucket only adds a delete marker, so nothing claims a delete removes every copy;
  refused plans are left to lifecycle expiry, and apply refuses any plan past the allowed
  age even if an old version still exists.
- **Migration before rollout; abort on failure.** A database downgrade is never an
  automatic rollback; it is a tested path a human chooses.
- New workflow files, `CODEOWNERS` and a verification gate for the static checks are
  protected-file changes needing explicit approval when M3.3b proposes them.

## 10. Logging, AWS-managed records, browser evidence and what M3.3d must capture

**Firmbatch application logs** go to log groups with explicit retention; **allow-listed
metadata fields only**:

| Allowed | Excluded |
| --- | --- |
| method, route template or a fixed classification, status, duration, request ID, task ID, image digest, session and account identifiers, broker outcome codes | request and response bodies; query strings; headers and cookies; OAuth codes and tokens and every callback parameter; email addresses; SQL values; raw S3 or object identifiers; customer payload |

**Today both of the API's log lines record the raw request path.** The unhandled-error line
names `request.url.path`; the access line is meant to record the route template, but it
reads a matched route from the request scope that the locked Starlette 1.6.0 does not record,
and falls back to the raw path. Today's path parameters are identifiers, not secrets. M3.3c
replaces both with route-template or fixed-classification metadata, tests both, and never
logs a query string or a callback parameter.

**AWS-managed control-plane and delivery records can hold identity data.** The allow-list
above governs Firmbatch's own logs and nothing else. CloudTrail, Cognito user-pool logging and
export, SES delivery and event records, the Cognito-associated WAF's logs, and any CloudWatch
log destination receiving those records **can contain customer identity attributes such as
email addresses**. **M3.3d inventories and reviews each of them**, and applies least
privilege, explicit retention, encryption and access auditing. They are **never copied into
ordinary Firmbatch application logs**, and nothing claims that the application allow-list
removes identity data from AWS control-plane services.

**ALB access logs disabled** for M3.3. **Alarms**: task health, ALB 5xx, RDS free storage and
connections, the budget alert — the recipient is a parameter. **AWS Budgets alerts; it does
not cap spend.**

**Browser evidence is credential-safe.** M3.3c builds the tooling; M3.3d runs it.

| Rule | Requirement |
| --- | --- |
| Data | **Synthetic staging identities and synthetic content only.** |
| Not retained | **No** ordinary Playwright trace, HAR file, video, storage-state file, console dump, network log or failure screenshot from an authenticated or OAuth journey. |
| Playwright settings | **Trace, video, screenshot and storage-state persistence disabled** for authentication tests. |
| Never in a report | Callback URL, query string, authorization code, `state`, `nonce`, cookie, CSRF value, token, email address, refresh material. |
| Failures | **Fixed classifications and opaque correlation IDs only.** |
| Summary | The **evidence collector writes an allow-listed summary**: test name, clean host and path, result, status class, deployment digest, sanitized timing. |
| Callback and logout | Verified by **sanitized assertions**, never by captured traffic. |
| Screenshots | **Only if separately approved**: on a **clean post-authentication route** with **obviously synthetic data**; never an account email, credential, API key or browser developer tools. |
| Scan | Generated evidence is **scanned for secrets, URLs containing queries, cookies, bearer material and email addresses before it can be committed**; **a failed scan prevents publication**. If the scan belongs in the `record-evidence` skill, that change needs the human's approval. |
| Raw artifacts | CI and browser artifacts have **zero retention by default and are never uploaded**. |

**M3.3d evidence**, each under `docs/evidence/m3/` with the standard header:

1. the **sanitized plan summary** — action counts, policy results, cost summary, plan
   checksum — and the record that the full plan was reviewed in an operator session;
   **never** the binary plan or a full plan rendering;
2. the current AWS cost estimate;
3. the explicit human deployment approval, naming the approved plan object's key, version ID
   and checksum;
4. the RDS compatibility qualification (§5);
5. the controlled synthetic staging identities bound through the `identity-binding` task,
   with their success and refusal audit records;
6. synthetic identity and tenant-isolation tests against the deployed database;
7. **the browser journey's allow-listed, secret-scanned summary**: login through Cognito with
   TOTP, the callback's clean redirect, the session cookie carried by the portal's next
   request, the workspace journeys, reload, multiple tabs, session replacement, expiry and
   mismatch, and logout through `/auth/logout`, each as a sanitized assertion — **never raw
   browser artifacts**;
8. **any explicitly approved UI images** of clean, synthetic routes;
9. the backup restore drill;
10. the resource and secret inventory, by name and identifier and never by value;
11. the inventory and review of the AWS-managed records that can hold identity data;
12. post-deployment cost and alarm checks;
13. the evidence capture itself.

## 11. Slice gates

| Slice | Gate |
| --- | --- |
| **M3.3a** | This document and ADR 0011 exist, with the review corrections and the final correction pass applied; the roadmap, target §14.1, register, STATE, task file and README are reconciled; source snapshots, migrations and §17 unchanged; `./scripts/verify-repository.sh` passes. No resource, no code. |
| **M3.3b** | **Scaffolding only.** `infra/terraform/` matches §8, including the separate state and plan buckets, the five task definitions, the distinct plan and apply roles and the allow-list policy check; `fmt -check`, `init -backend=false`, `validate` and `terraform test` pass locally and in a pull-request static-check workflow; the container-build foundation builds from the pinned locks and passes every existing gate; ECR and the delivery workflow structure are defined, holding no credential and creating nothing; Git excludes in place. **Required acceptance tests, each failing when its property is absent:** every environment, workflow, OIDC-trust, role, plan-bucket and apply-verification property listed in §9; no binary plan or full plan rendering reaches a GitHub artifact or log; plan-bucket lifecycle expires current and noncurrent plan versions and delete markers and never touches state; the allow-list validation and the independently tested policy check each reject an empty list, a non-canonical or invalid CIDR, an IPv4 prefix shorter than `/24`, an IPv6 prefix shorter than `/64`, more than the maximum entries, an unspecified, multicast, loopback, link-local or otherwise non-routable range, a duplicate or overlapping entry, and a list over the maximum address-space allowance. **No cloud `plan`, no `apply`, no credential in the repository, and no deployable broker, bootstrap or identity-binding implementation.** Not operational until M3.3c passes review. |
| **M3.3c** | Every program the scaffolding runs, with its dependencies, entry points and tests: the database bootstrap command; the identity-binding command and its dedicated database boundary; the broker entry point; the Cognito authorization, callback, refresh, revocation and logout clients; JWT and JWKS verification; KMS encryption and decryption; the staging configuration mode; the `__Host-fb_session` rename with every affected test and setting; the AWS-mode route changes including `/auth/logout` and the disabled browser routes; metadata-safe access and unhandled-error logging; migration `0007`; the portal's `/auth/*` adaptation; the reviewed and pinned HTTP, JOSE/JWT and AWS SDK dependencies, the requirement files and both lock files, and the runtime-import inventory; the web/API entry point serving the compiled portal; the browser-evidence tooling — Playwright persistence off for authentication tests, the allow-listed summary collector, the evidence scanner. Adversarial tests against real PostgreSQL 16: an unbound identity is refused; an email match binds nothing; a replayed or forged `state`, handle, `nonce` or code is refused; every callback outcome is a `303` to the clean URL with the handle cleared and `no-store` and `no-referrer`; no token, claim, verifier or callback parameter reaches a response body, a log, an audit or outbox row, or an exception chain; a federated session is an ordinary session under every M3.1 and M3.2 protection; logout revokes; refresh tokens are unreadable by the application role; **the identity-binding login role's catalogue is `EXECUTE` on its one function and nothing else, and arbitrary SQL as that role opens no session, issues no credential, changes no membership, assumes no role and writes no table**; **binding is idempotent for an identical request, refuses a conflicting one, never binds by email, and commits its success or refusal audit event atomically**; **the evidence scanner fails on a planted secret, query-string URL, cookie, bearer value or email address, and the collector emits only allow-listed fields**; `verify-full` against a local certificate authority works; local authentication remains for development and test. Nothing deployed. |
| **M3.3d** | Every parameter confirmed; the plan reviewed in an operator session; the cost estimate current; the authorization recorded; apply started with the approved object's key, version ID and checksum and verified independently; bootstrap, migrations, identity binding with the dedicated credential; every evidence item of §10 captured under the browser-evidence rules; Milestone 3 closes. |

## 12. Explicit deferrals

Not delivered by Milestone 3.3, and not to be claimed: production deployment; production
public hostnames; CloudFront; static-site S3 hosting; Multi-AZ RDS; read replicas or RDS
Proxy; autoscaling; multiple NAT gateways; production identities or data; real GPU-provider
execution; operator capacity agent deployment; payload presigning and transfer; the SQS outbox
dispatcher and workers; settlement; production disaster recovery. The operator capacity agent
remains separate operator-side software; Cognito and AWS staging do not change the
multi-provider GPU boundary.

## 13. Deployment parameters requiring human confirmation

No value is chosen here.

| Parameter | Owner | When |
| --- | --- | --- |
| Staging AWS account ID | human | before the first `plan` |
| Region (recommended `eu-central-1`) | human | immediately before planning and deployment |
| Domains: Route 53 hosted zone, customer origin, Cognito custom domain (proposed `auth.staging.app.firmbatch.com`) with its callback and logout URLs | human | M3.3d |
| CIDRs: VPC and subnet ranges; the reviewer allow-list for ports 443 and 80 with its maximum address-space allowance, explicitly reviewed and never committed | human | M3.3d and on every change |
| SES identity | human | M3.3d |
| Alert recipient for alarms and the budget | human | M3.3d |
| Budget threshold (alerts only) | human | M3.3d |
| RDS sizing (instance class, storage) and exact PostgreSQL 16 minor | human | M3.3d |
| Saved-plan lifetime (24 hours recommended) and the required reviewers of `staging-plan` and `staging-apply` | human | before the first trusted plan |
| Staging identities to bind (Cognito subject → account or invitation) | human | M3.3d, per binding |
| Retention of AWS-managed logs that can hold identity data | human | M3.3d |
| Current cost estimate, including the Cognito feature plan Managed Login requires | produced at M3.3d | before authorization |
| **Explicit deployment authorization** | human | recorded before `apply` |
