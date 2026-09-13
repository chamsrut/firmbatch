# ADR 0010 — The customer portal: a same-origin TypeScript application, a readable CSRF cookie, and stated preferences

**Status:** Accepted (Milestone 3.2), corrected on 2026-09-10 after an independent review,
on 2026-09-11 for its three remaining logout findings and the session-generation race,
again on 2026-09-11 for the eight findings of a clean-context review, and on 2026-09-12 for
the final review's two P3 findings (a `next=` destination that normalised to a
protocol-relative URL, and the factual counts in the consequences below)
**Date:** 2026-09-09; decisions 2 and 4 amended and decisions 7–10 added 2026-09-10;
decision 9 amended and decision 11 added 2026-09-11; consequences corrected 2026-09-12
**Supersedes:** nothing. **Amends:** ADR 0009 in two places — migration `0006` replaces the
bodies of two `0005` functions (`verify_account_email`, `complete_account_recovery`) to bring
them under the account-plane lock order (decision 4), and the body of a third
(`workspace_membership_authority`) to compare every workspace mutation's expected workspace
with the binding under the workspace lock (decision 11), restoring `0005`'s text on downgrade
in all three cases. ADR 0009's design is otherwise used as it stands, and extended in one
place, recorded as decision 3 below.
**Context:** `docs/firmbatch-v1-roadmap.md` M3.2; `docs/architecture/v1-target-architecture.md`
§3.3, §5.2, §5.3, §5.4, §17 invariants 11 and 13; `docs/architecture/rev-d-decision-register.md`
item D8; ADR 0002 decision 6; ADR 0009.

## Context

Milestone 3.1 built the identity plane and a JSON API, and built no interface. Its own
`api/app.py` says so twice: "No HTML, no portal, no template: the customer application is
Milestone 3.2", and "No password change while signed in: recovery covers it, and a change
flow needs the re-authentication design Milestone 3.2 owns."

M3.2's scope is the authenticated customer application: the layout, account, workspace, team
and permission settings and credential management; navigation for Evaluation, Jobs, Results
and Billing, with those honestly unavailable; capture of the customer's desired policy,
profile and preferences "for later use **without claiming a quote or an execution**"; and
consent text stating `provider_policy`'s v1 scope exactly.

Three things had to be decided before any of it could be built, and reading the code surfaced
a fourth that was not in the roadmap at all.

## Decision 1 — TypeScript, Vite and React, served **same-origin** with the API

ADR 0002 decision 6 makes TypeScript "the default implementation recommendation, not a
constraint". We take the recommendation. Vite for the build, React for the view, Vitest and
React Testing Library for the tests, and **no runtime dependency beyond React** — the router,
the API client and the interface components are written here, and are about a thousand lines
in total. A routing library would carry a resolver and a data layer this application uses
none of; a component library would carry a design system this application does not have.

The consequential half is not the framework: it is that **the portal and the API are one
origin**, in development and in a deployed environment alike. Vite proxies `/v1` to the API
locally; a reverse proxy does the same job in M3.3. Three things follow, and the third is why
it is a decision rather than a convenience:

- CORS is not in the portal's path at all. The API keeps its credentialed allow-list, which
  is what the `Origin` check on every cookie-authenticated mutation reads, and which browsers
  send on same-origin unsafe methods too.
- The session cookie stays host-only with no `Domain`.
- **A cookie the API sets is a cookie the portal can read.** A cookie without `Domain`
  belongs to exactly one host, and the `__Host-` prefix forbids `Domain` outright — so a
  portal on `app.example` could never read a cookie an API set on `api.example`. Decision 3
  depends on this being true.

## Decision 2 — The customer's stated policy is a new relation, not a reused one

Roadmap M3.2 asks for the customer's desired policy, profile and preferences to be captured
"for later use", and there was nowhere to put them. Migration `0006` adds
`firmbatch.workspace_preferences`: one row per workspace holding region groups, excluded
provider classes, a note about the model and runtime profile, whether the customer intends to
run the free evaluation, and the consent version in force.

It is on the **ordinary tenant plane**, not the protected identity plane: it carries no
secret and gates nothing, so it gets what every customer relation gets — `FORCE` row-level
security, `workspace:read` to see it and `workspace:write` to state it. **The application
role holds `SELECT` on it and nothing else** (amended 2026-09-10; the first draft granted
`SELECT, INSERT, UPDATE`). Every write goes through one of two `SECURITY DEFINER` functions,
`state_workspace_preferences` and `acknowledge_workspace_consent`, which are the
authorization and audit boundary for the relation — the arrangement `audit_events` has with
`append_audit_event`, and for the same reason: a runtime role that could `INSERT` or `UPDATE`
the table itself could write a preference with no audit event, and a consent row with no
revalidated membership behind it. Four things are worth stating because they were choices:

- **The foreign key is composite.** `(workspace_id, tenant_id)` references
  `workspaces (id, tenant_id)`, not `workspaces (id)`. Referential checks bypass row
  security, so a single-column reference would let a row name one tenant's workspace while
  carrying another's `tenant_id`, and the isolation predicate would then be comparing a
  column the writer chose.
- **Each mutation function does seven things in one call, in this order.** It requires a
  browser session bound in workspace mode **with its CSRF secret verified**, so a
  transaction a `GET` opened cannot reach a write however its SQL is spelled; it validates
  its inputs against the closed vocabularies without echoing them; it takes the workspace
  row `FOR UPDATE` and re-derives the caller's membership and role under that lock, so a
  member demoted or removed since the session bound is refused whatever the bind cached; it
  compares the workspace the page expected with the one the session is bound to (decision
  7); it decides, under the lock, whether anything changes — re-stating the statement in
  force, or re-acknowledging the version in force, writes nothing and appends nothing; and a
  transition appends its audit event and writes the row inside the same call, so the two
  commit together or not at all. The `INSERT` and `UPDATE` policies remain and evaluate
  inside the functions (`FORCE` binds the owner), as defence in depth; there is no `DELETE`
  policy and no `DELETE` grant.
- **The consent actor, timestamp and version are derived, not supplied.**
  `acknowledge_workspace_consent` records the server's current version
  (`CURRENT_CONSENT_VERSION` in the migration, held equal to the API's), the bound account
  and `clock_timestamp()`; the version a caller passes is the one the portal *displayed*, and
  a displayed version that is no longer current is refused as a conflict, so assent is never
  recorded to text the customer was not shown. The `BEFORE INSERT OR UPDATE` trigger from
  the first draft stays as defence in depth and is **not** the boundary: the functions derive
  the same two columns themselves, and a test proves they do with the trigger disabled.
  Nothing clears an acknowledgement — the only transition the architecture names is to a
  newer published statement, and no function or grant offers a path to a row that says
  nobody consented after somebody did.
- **The history is the audit trail**, which is append-only and immutable. The row carries the
  acknowledgement in force; `audit_events` carries how it got there — exactly one event per
  transition, and none for a repeat.

**A row here is a statement of intent and nothing more.** It is not a `JobSpec`, it reserves
no capacity, it prices nothing, and no admission or routing path reads it. M5 owns the
contract fields that make the same ideas binding. The interface says so on the page, not only
in a comment.

The vocabularies are closed and are taken from the target: region groups are `{EU}`, which is
the only value §5.2's canonical JobSpec names; provider classes are Google, Microsoft, Amazon
and Verda, which §5.4 and §4.4 name. Adding `US` or `APAC` would be inventing configuration
no authority states. The model and profile field is deliberately **free text**: the certified
profile registry with measured throughput is M6, the model band is an open measurement
decision, and a closed list here would present the target's illustrative examples as an
available catalogue.

## Decision 3 — The CSRF secret is also set as a readable, host-only cookie

**This is the one place ADR 0009's design is extended, and the gap it closes was not
documented anywhere.**

`open_browser_session` mints the CSRF secret once and stores only its SHA-256 fingerprint. The
plaintext therefore exists in exactly one place: the login response. A single-page application
that kept it in a variable would lose it on every reload — and **nothing can re-issue it**,
because a fingerprint is one-way. A signed-in customer who pressed F5 could read every page
and change nothing, indefinitely.

Three answers were considered.

1. **Re-mint on demand**, through a new route and a new database function that replaces
   `browser_sessions.csrf_fingerprint` for a bound session. Rejected: it reopens the identity
   plane that three M3.1 security reviews settled, and rotating on page load breaks every
   other open tab, which then has to be recovered by retrying a mutation after a `401` — a
   retry path on exactly the requests that must not be retried blindly.
2. **Step-up re-authentication**: a reloaded tab is read-only until the customer re-enters
   their password. Rejected as the primary mechanism: it makes an ordinary reload cost a
   password, and it accumulates orphaned sessions.
3. **Set the same secret as a second cookie**, readable by script, host-only,
   `SameSite=Strict`, with the session's own lifetime, cleared with the session cookie, and
   `__Host-` prefixed wherever it is `Secure`. **Chosen.**

Why it is not a weakening, stated precisely:

- **It is not a credential.** The session cookie beside it stays `HttpOnly` and is the only
  thing that authenticates. Holding the CSRF secret alone authenticates nobody.
- **The boundary never compares the cookie with the header.** A double-submit check that only
  proved "these two values match" would be satisfied by any value a caller set on both sides.
  The header is verified *inside PostgreSQL* against the session's stored fingerprint, so a
  caller must produce the session's actual secret. `test_portal_http.py` sets both sides to
  the same forged value and the mutation is still refused.
- **Two further layers are unchanged**: the session cookie is `SameSite=Strict`, so a
  cross-site request carries no credential at all, and every cookie-authenticated mutation
  checks `Origin` against the explicit allow-list.
- **`__Host-` is browser-enforced**: set over HTTPS, `Path=/`, no `Domain`, so no sibling
  subdomain can set or shadow it. The prefix is a property of the deployment rather than a
  second configuration knob — `csrf_cookie_name()` derives it from `cookie_secure` and
  nothing else, because a browser rejects a `__Host-` cookie that is not `Secure` and the
  test environment is permitted an insecure cookie for a plain-http local client.
- **Exposure under XSS is unchanged.** A script on the page origin that could read this cookie
  could equally read a variable, patch `fetch`, or act as the user directly. This does not
  move that line.

The portal reads the cookie **fresh on every mutation** and never caches it: another tab that
signed in, or a password change that replaced the session, rewrites it, and a cached copy is
exactly the stale value that produces a baffling refusal.

A note on the client's own refusal (2026-09-10): a mutation attempted with no CSRF cookie is
refused by the client before it is sent, with the status a server would use. That refusal is
marked as the client's, not the server's; and a sign-out decides nothing from any refusal's
status at all, the client's or the server's (decision 9).

## Decision 4 — The signed-in password change, and what it ends

M3.1 handed this to M3.2. Migration `0006` adds two functions on the **trusted-issuer
boundary** — granted to the authenticator role alone and to the application role not at all,
the same split, for the same reason, as the eight M3.1 put there. It confers no capability the
authenticator lacked: it already held `request_account_recovery` and
`complete_account_recovery`, so it could already replace any account's password. This path is
strictly narrower, because it additionally requires proof of the *current* password and a live
browser session.

The flow is two transactions on two engines, in this order and for this reason. The first
binds the session on the **application** engine — that is where a session secret is proved,
and the authenticator deliberately cannot bind one — and yields the account id, the session id
and the two passwords. It is closed before the second begins: holding a transaction open on
one engine while a second runs on another is how an avoidable deadlock gets written. The
second, on the **authenticator** engine, is atomic and is where everything that changes state
happens: verify the current password against the hash the database just locked, replace it by
**compare-and-swap against that same hash**, supersede every outstanding token, advance the
security epoch, revoke every membership-bound credential and **every** browser session, and
mint the replacement afterwards so it survives the sweep.

Two race controls are kept because they fail on different things. The compare-and-swap catches
a concurrent change that moved the hash. The epoch comparison catches a change that moved the
epoch — and makes the loser's credentials dead rather than merely stale. In practice a third
control decides the common race first: the lookup takes the account row `FOR UPDATE` and holds
it to end of transaction, so a second attempt blocks there and, by the time it proceeds, its
own authorizing session has been revoked by the winner.

**The account-plane lock order** (added 2026-09-10; independent review, finding 3). That
third control only works if every account-plane writer takes the account row *first*. At
`0005` two did not: `complete_account_recovery` and `verify_account_email` each locked their
token row and only then updated `accounts`, while the change locks the account row and then
supersedes every token. Overlapped, the change held the account row and waited for the token
row, the recovery held the token row and waited for the account row, and PostgreSQL resolved
it by killing one with `40P01` — a transient outcome a customer saw as a 500. The order is now
stated once, in migration `0006`, and every writer follows it: **`accounts` row `FOR UPDATE`
first, then `account_tokens`, `account_passwords`, `auth_bindings`, `browser_sessions`.** The
two `0005` bodies are replaced with `CREATE OR REPLACE` — each reads its token unlocked only to
learn which account row to lock, locks that row, then re-reads, locks and re-validates the
token under it, which keeps the token exactly one-time — and `change_account_password` is
written to the same sequence. The downgrade restores `0005`'s text verbatim and a test proves
a database taken back to `0005` has the catalogue a fresh migration to `0005` produces. The
overlap is driven for real in `test_portal_password_change.py`: one transaction holds the
account row, the recovery (and, in a second test, a login, a recovery and a second change at
once) are proven through `pg_locks` to be waiting on it with their token rows still unlocked,
and the outcome is one winner, a neutral refusal for every loser (`401 invalid_credentials`
for the login, `400 invalid_token` for the recovery, `409 conflict` for the second change),
no partial state, and no connection or lock left behind.

`change_account_password` mints its replacement session inline rather than calling
`open_browser_session`. That is not duplication for its own sake: `identity_context_write`
refuses to re-point a context inside one transaction — it is what "a transaction carries one
identity" means — so a function that has already written a `password_change_challenge` cannot
then write the `login_challenge` the other requires. Rewriting an M3.1 function three security
reviews settled, to save nine lines, was the worse trade.
`test_portal_password_change.py` asserts the two paths produce session rows of the same shape,
which is the drift control for it.

**One status mapping is deliberately different from the rest of the boundary.** An
`IdentityRefused` from this path is rendered `409 conflict`, not `404 not_found`. The neutral
refusal normally means "absent, hidden, in another tenant, revoked or expired", and `404` is
honest for that. It cannot mean "absent" here: the bind one transaction earlier proved this
session was live for this account, so a refusal now says the account state moved in between.
`409` is what a client can act on, and the portal renders it as "changed somewhere else;
nothing was changed here".

## Decision 5 — The consent text lives in the API, and the portal renders what it is served

Register item D8 closes with: "The customer-facing consent text is an M3.2/M5 deliverable and
**must match the rule**." So the text is held in `control_plane/api/consent.py`, versioned,
served by `GET /v1/consent`, and rendered by the portal from that response. A second copy in
the frontend would be a second copy that can drift from the one the database validates an
acknowledgement against; `models.CONSENT_VERSIONS` renders as a check constraint, so a row
cannot record assent to text that does not exist, and a test holds the two inventories equal.

`GET /v1/consent` is **unauthenticated**, deliberately: somebody deciding whether to sign up
is entitled to read what they would be agreeing to before they have an account. It carries no
customer data and no identifier.

The text states, because §5.4 and invariant 13 require exactly this: `provider_policy` names
*whose*, never *where*; it governs **execution placement only** — first placement, every
retry, every move to shared capacity and every hedge; it does **not** govern the payload
plane, which is Amazon S3 for every tenant until a bucket per supplier cloud region exists;
and therefore **a customer who excludes Amazon altogether cannot be served in v1**.

That last exclusion is neither silently refused nor silently accepted. It is accepted,
recorded and flagged — in the interface, in the API response (`unservable_exclusion`, derived
from the architecture rather than stored, so it stops being true when a bucket per supplier
cloud exists) and in the audit trail. Refusing the value would deny the customer the ability
to record the requirement that makes them unservable, which is a fact the business needs;
accepting it silently would promise an exclusion the design cannot honour.

## Decision 6 — The verification script gains one gate

`./scripts/verify-repository.sh` is the repository's one verification entry point, and the
portal's checks are its own toolchain's. Rather than re-spelling them, the script gains a
single **customer portal** gate that runs `npm run verify` in `portal/`: `biome ci . && tsc
--noEmit && vitest run && vite build`. Fourteen gates become fifteen.

It **fails rather than skips** when `npm` or `portal/node_modules` is absent, for the reason
the PostgreSQL gate does: a portal whose type check and tests silently did not run reports
exactly the same green as one where they passed. `.github/workflows/ci.yml` gains
`actions/setup-node` pinned to Node 24 and an `npm ci` step, so the same gate runs in the same
way for the human, the agent and CI. Both files are protected by `AGENTS.md` and both changes
were approved explicitly before they were made.

## Decision 7 — Every preference mutation names the workspace the page loaded for

*Added 2026-09-10; independent review, finding 1.* The browser session is shared between
tabs, and selecting a workspace re-binds it server-side. A preferences form loaded for
workspace A in one tab, saved after another tab switched the session to workspace B, was
applied to B: the handler took the workspace from the binding and the form from the page,
and nothing compared the two.

Both mutations now carry the identifier the page loaded its form for (`workspace_id` in the
body; the API refuses an absent or malformed one as `422`), and the database function compares
it, **under the workspace lock**, with the workspace the bound session acts in. (Decision 11
extends the same contract to every workspace mutation, through the `X-Workspace-Id` header
and one replaced `0005` function; these two keep their body field as well.) A mismatch is
one neutral refusal, SQLSTATE `FB014`, rendered `409 workspace_mismatch` — the same for a stale
page, a forged identifier and another tenant's identifier, so the refusal is not an existence
oracle. The portal reports that nothing was saved and reloads the page for the current
workspace rather than ever showing one workspace's values under another's name.

What actually serialises the concurrent case is worth recording: a bound transaction holds
its own session row (the bind stamps `last_seen_at`), and re-binding the session is an update
of that row, so a switch that starts while a save is in flight waits for the save to commit,
the save lands on the workspace it named, and only then does the session move. The tests
assert the wait through `pg_locks`.

## Decision 8 — One-time tokens are held in memory by the router, and the invitation page is public

*Added 2026-09-10; independent review, findings 5 and 6.* The first draft read a verification,
recovery or invitation token from the URL inside a React effect and scrubbed the URL in the
same tick. Under `StrictMode` — which `main.tsx` uses, and which replays every effect on mount
— the replayed effect found an already-scrubbed URL and forgot the token, and a submission
inside an effect would have run twice. The invitation landing page was also behind the
authentication guard, so a signed-out visitor was redirected to sign in and the token left
with the URL.

The token now leaves the URL in **one** place: the router's initial state, the first thing
that reads the URL and the last that should ever see a secret in it (`lib/one-time-token.ts`).
It is captured once — a second capture finds nothing in the URL and keeps the held value —
scrubbed with `replaceState` so it is in no address bar, history entry or `Referer`, held only
in memory for the mounted application, submitted at most once at a time (a replayed effect
joins the submission in flight), kept for an explicit retry after a transport failure, and
released once used. A reload loses it by design, and each page then says to open the link
again. It is never in `localStorage`, `sessionStorage`, a cookie, a log or another URL.

`/accept-invitation` is a public route. Signed out, it captures the token, offers sign-in and
sign-up with `/accept-invitation` as the checked `next` continuation — a route, never a token
— and accepts once the customer is back in the same mounted application. A signed-in visitor
accepts directly; a spent, revoked, malformed or mis-addressed token is the API's neutral
`404`, rendered as one sentence that names no identifier.

## Decision 9 — A sign-out is a server outcome, not a local one

*Added 2026-09-10; independent review, finding 4; corrected the same day for the review's P2
follow-up.* The first draft forgot the session locally whatever the logout request returned,
and navigated to the sign-in page: a customer at a shared machine whose sign-out had failed
on a dropped connection or a `5xx` was shown a signed-out screen over a live session. The
first correction still took a server `401` from the logout as proof that the session had
ended — and it is not: the API answers a wrong CSRF secret on a perfectly live session with
the same neutral `401`, deletes no cookie, and goes on serving the account read.

Local authentication is now cleared immediately only after a **successful** logout. After any
other outcome — a `401`, a `5xx`, a timeout (the request carries a deadline), a transport
failure, a lost response — the portal makes **exactly one** safe validity check, the existing
authenticated account read (a `GET`, so there is no CSRF proof to get wrong), and acts on
what that read says: a definitive `401` clears local state and goes to sign-in, because the
server itself has bound the cookie and refused it; a `200` keeps the authenticated state,
stays in the application and shows, next to the button, that the customer is still signed in
and why the request failed, with the same button there to retry; anything else — a transport
failure, a timeout, a `5xx` — keeps the state and says the session could not be checked and
must be treated as open. Nothing retries the logout on its own, and nothing is inferred from
the logout's status, its body or the cookies the page can see. `ApiError` still records where
a refusal came from (`server` or `client`); sign-out no longer decides anything from it.

*Amended 2026-09-11 for the three remaining logout findings.* They had one root: the
sign-out lived in the button. Each `SignOutButton` ran its own logout with its own busy flag
and its own message, so two controls clicked together sent two logouts; a logout or validity
read still pending when a password change adopted a replacement session applied its answer
— clearing the new session, navigating to sign-in, or publishing "could not be checked" —
over a session it had never been about; and the validity read carried no deadline, so a
stalled read left every control at "Working…" indefinitely.

The sign-out is now **one operation owned by the session provider, fenced to the session it
began under.** The provider keeps a monotonic *generation* that moves whenever it adopts,
replaces or clears the authenticated session — a change of session identity: a login, a
password change, a forget, a read that finds a different session. A same-session re-read,
such as a workspace switch, is not a change. An operation captures its identity, the
generation and the session id at the synchronous moment it is registered, and applies
nothing — not the logout's answer, not the read's, not local clearing, not the failure
state, and not the navigation, which the control performs only on the outcome the provider
reports — unless both are still current. Adopting a replacement session disowns the pending
operation, aborts its requests through its `AbortController`, and resets the shared status;
an answer that arrives anyway is dropped; the replacement session is never cleared and no
error is published over it. A `refresh` is fenced the same way, so a read begun under one
session cannot re-publish it after a sign-out has ended it.

**Single flight.** The first `signOut` registers the operation synchronously, before any
network activity; every call while it is pending — the masthead, the security page, direct
calls in the same tick — receives the same promise, and no second logout is sent. Every
control renders the provider's shared `pending` and `failure`; none keeps a busy flag of its
own. An explicit retry after settlement is exactly one new operation and one new request.

**Deadlines.** The logout (15 s) and the validity read (10 s) each run under a real
deadline: `withDeadline` in the client arms a `setTimeout` that aborts the request's own
signal, follows the operation's signal, and releases both in `finally`, whichever way the
request settles. When the read's deadline passes, validity is `unknown`, authentication is
retained, the shared pending state clears, the message says so and every control is
restored. The provider aborts a pending operation on teardown. The read bypasses every
cache (`cache: "no-store"`, over the API's own `Cache-Control: no-store`), and it is the
same `GET /v1/account` as the page's own read: a bounded, abandonable variant of it, not a
new route.

**Leases (2026-09-11, the same design, extended to every route).** The fence is not the
sign-out's alone. Every request a route makes under the session captures a *lease* — the
generation and the session identity — when it starts, and nothing its answer implies is
applied unless the lease is still current: not the data, not a message, not a navigation,
and not a clearing. The routes hold no `forget`; the provider's `reconcile(lease, error,
kind)` is the only path from a refusal to the session, and it reads the refusal for what it
can mean. A definitive `401` from a **safe read** under the current lease clears the
matching session, and the application redirects with the page remembered. A `401` from a
**mutation** is ambiguous — a wrong CSRF secret on a live session gets the same neutral one
— and leads to the bounded validity read above, which alone may clear; while it is pending
the page shows nothing, and a live answer is reported as "this session is still open", not
as "your session has ended". `401 invalid_credentials` is a verdict on a password and
touches nothing. A `403` re-reads authority. `refresh` takes a lease too, so a read begun
under one session can neither re-publish it nor clear its successor, and a first load that
StrictMode replays clears nothing the first adopted. The generation moves only when the
browser session is adopted, replaced or cleared; selecting a workspace under the same
session moves nothing. A pending bounded read is aborted when the session changes, and
correctness rests on the lease regardless, because an answer may arrive despite the abort. A
source-scan test holds every production caller to this: no `forget` outside the provider, no
`refresh()` without a lease, no `reconcile` without one, and a lease in every module that
calls the API under the session.

## Decision 10 — Focus follows the route

*Added 2026-09-10; independent review, finding 7.* The shell moved focus to the main region
only on its first mount and skipped that one deliberately, which is to say never. Focus
management now lives at the top of the tree, where every transition is visible: after each
**actual** route change it hands focus to the new page's `h1` (or to the main region until the
heading appears, and then to the heading if the customer has not moved focus elsewhere), and
it moves nothing on the first render or on a re-render that did not change the route. The
public pages' titles became their `h1` and the wordmark a paragraph, so that the heading
announced is the page's own.

## Decision 11 — Every answer is fenced to what asked for it

*Added 2026-09-11; the clean-context review's eight findings, treated as one design.* The
corrections of decision 9 fenced the sign-out and then every route's refusal to the session
that started them, and the review found what those fences did not cover: a replacement
session raced by an old response, a refresh whose reads straddled a workspace switch, a
switch whose follow-up read failed, eight workspace mutations that carried no expected
workspace, page completions applied after the page had moved on, and StrictMode issuing
mount-time reads twice. The design that closes all of them has four parts.

**The replacement barrier.** The browser's cookie changes the moment a login or a password
change answers, so the session provider adopts the replacement **synchronously from that
answer** (`adoptFrom`): the generation moves, the replacement's `session_id` is recorded,
every pending operation of the former session is disowned and aborted, every in-flight
account load is made a stranger, and only then is the account read under the new identity.
There is no window in which an old answer can be applied to the new session, because the
new session exists in the provider before any read under it is started. While a replacing
request is in flight, a definitive refusal of the *current* session is **deferred** rather
than believed — it may be the replacement's own effect — and is settled by the request's
outcome: adopted, the refusal is moot; failed, one bounded validity read decides. Both
schedules the review reproduced (the old `401` after the replacement response but before its
read, and before the response) end with the replacement held, no detour through sign-in and
the page's success state intact. A replacement whose follow-up read fails is a **live session
with an unloaded account** and a retry — a password change keeps the account on screen, a
sign-in shows a signed-in loading screen — never the old session put back and never an
anonymous state. The same operation adopts a session a validity read discovers another tab
opened, and a session the first read finds is claimed in place.

**Ordered, coherent reads.** Every account load takes a sequence; only the latest may
publish or finish the loading state, and a workspace switch moves the sequence past every
load in flight. A load reads the profile, the memberships and the bound workspace's detail,
and publishes only if the profile and the detail name the same workspace; an incoherent set
is read once more and then dropped with a load problem rather than shown, so a state that
pairs workspace A's binding with workspace B's role cannot exist. Selecting a workspace is
two things: the mutation's own answer is published as the binding at once, the page leaves
for the overview, and the supplementary read runs separately — its failure keeps the binding
and reports itself as a retryable load problem, never as a workspace that could not be
opened. The provider's account load and validity read are single-flight, so a StrictMode
replay of the mount effect and two controls asking one question in one tick each produce one
request.

**The expected workspace, everywhere.** Every workspace-scoped mutation the portal makes —
rename, member removal and role change, invitation creation and revocation, credential issue,
rotation and revocation, and the two preference mutations — carries the workspace its page or
action began under, as the `X-Workspace-Id` header (the preference mutations also in the body,
their original contract). The HTTP boundary records it in the transaction once, after the bind
and before the handler, through the new `identity_expect_workspace` function into the new
transaction-scoped `identity_expected_workspace` relation (keyed like the identity context, so
a pooled backend cannot inherit an expectation), and migration `0006` **replaces the body of
`workspace_membership_authority`** — the one revalidation every `0005` workspace mutation
makes, under the workspace lock, before it writes — to compare the expectation with the
binding and refuse a mismatch with the same neutral `FB014`. The comparison is therefore
atomic with the mutation it guards: one transaction, one binding, one lock, nothing written
or appended first; a forged identifier and another tenant's identifier get the same answer.
A mutation without the header is a `422`. `0005`'s body is restored verbatim on downgrade.
Every workspace read answers with the workspace it describes (`workspace_id` in the envelope
of the member, invitation, credential and history lists; the detail and the preferences
already did), and a page compares it with the workspace it began under before rendering:
a late answer for A after the session moved to B is never rendered under B, and a page that
receives another workspace's data says so and re-reads the binding. None of this relies on
the session lease alone, because switching workspaces deliberately keeps the browser session
and its generation.

**Page tickets.** Every request a page makes takes a ticket (`usePageRequests`): a load
ticket carries a sequence and is *latest* only while no newer load has started; an action
ticket is *live* while the page is mounted, under the same session, in the same workspace.
Only the newest load may publish data, end the loading state or say why it failed; an action
publishes its message, clears its form, reconciles and navigates only while live; and a
stranger completion may do one thing, put back the control it disabled. After the customer
leaves a page, every completion from it is inert. Page reads go through one keyed single
flight (`reads`), so a StrictMode replay issues each mount-time read once while a reload after
an action, and a customer coming back to a route, read afresh. Two smaller things the review
named are closed with it: the invitation page takes its ticket before it starts the request,
and the account page says a confirmation link is on its way only once the server accepted the
request. `clearWorkspace` had no production caller and is gone; the account page's dynamic
import of a statically imported module is gone, and the production build is warning-free.

What the tests prove, against the fake wire on the portal's side and against PostgreSQL 16
on the API's: both replacement schedules; a mixed A/B refresh never published and an
incoherent one dropped; a switch during a refresh and a refresh during a switch; a bind that
succeeds followed by a read that fails; every workspace mutation carrying the header and every
one refused as a mismatch for a stale page, a forged identifier and another tenant's, with no
write and no audit event; a concurrent switch and stale rename never applying one workspace's
action to another; the envelope on every workspace read; a late A answer never rendered under
B; an older load's late answer neither publishing nor ending a newer load; completions after
leaving a page inert; and one request per mount-time read under StrictMode. A source scan
remains as supporting evidence that no route holds a `forget`, a lease-less `refresh` or a
`clearWorkspace`; it is not the proof.

## Alternatives rejected

- **A server-rendered portal in Python**, avoiding the Node toolchain entirely. Rejected: it
  contradicts ADR 0002's TypeScript recommendation, and it fights ADR 0009's design — the
  cross-origin allow-list, the `SameSite=Strict` host-only cookie and the login-returned CSRF
  token exist for a browser client. A server-rendered portal would need its own session store
  to hold them, which is a second credential store.
- **Reusing an existing table for preferences**, or storing them as workspace metadata.
  Rejected: `workspaces` has no metadata column, and adding one would make a typed, closed,
  constraint-checked vocabulary into an untyped document.
- **Making the exclusion of Amazon a validation error.** Rejected under D8: the customer's
  requirement is worth recording even when v1 cannot meet it, and the honest answer is to say
  so rather than to refuse the input.
- **A real-browser end-to-end suite** (Playwright) for the reload, multi-tab, expiry and
  mismatch cases. Not built at this milestone — see "What this does not claim".

## Consequences

- The repository gains a Node toolchain: Node 24 LTS; two runtime packages, React and
  ReactDOM; a development toolchain of Vite with its React plugin, TypeScript, Biome, Vitest
  with jsdom, Testing Library (DOM, React, user-event and jest-dom) and the type packages for
  Node and React; a tracked `package-lock.json`, which `npm ci` installs exactly; and one
  verification gate. `portal/package.json` is the authority for the exact list and versions.
- Migrations `0001`–`0005` are unedited. `0006` adds two relations (the tenant-plane
  `workspace_preferences` and the transaction-scoped `identity_expected_workspace`), one
  trigger and six functions, replaces the bodies of three `0005` functions — two under the
  account-plane lock order and `workspace_membership_authority` under the expected-workspace
  contract (decision 11) — and its downgrade restores those bodies verbatim and returns the
  catalogue to exactly `0005`'s.
- The authenticator role's grant grows from ten functions to twelve. The application role
  gains three functions — the two preference mutations and the expected-workspace writer
  `identity_expect_workspace` — and loses `INSERT` and `UPDATE` on `workspace_preferences`,
  keeping `SELECT`; it holds nothing on `identity_expected_workspace`.
- `app.firmbatch.com` and `api.firmbatch.com` remain the deployed names, but the portal must
  reach the API through one origin. M3.3's infrastructure has to provide that, and it is now
  a requirement on that milestone rather than a preference.

## What this does not claim

- **Not deployed, and not VERIFIED LIVE.** No evidence artifact was captured. M3.3 owns the
  protected AWS staging preview, and it is authorized separately.
- **No real-browser end-to-end test.** The cookie contract is asserted at the header level
  against real PostgreSQL (`test_portal_http.py`) and the client behaviour is asserted in
  jsdom with a real cookie jar (`portal/tests`). What neither covers is the *browser's own*
  enforcement of `__Host-` and `SameSite`, which is vendor behaviour rather than this
  repository's code. A Playwright suite against a deployed staging environment is the natural
  home for it and belongs to M3.3, whose gate is already "the real customer portal can be
  opened and reviewed on AWS with verified test identities".
- **No email is delivered.** The capture adapter is still the only one that exists, so
  verification, recovery and invitation links do not leave the process.
- **Nothing about jobs, quotes, invoices, evaluation runs or supplier operations is
  implemented.** The four product sections are navigation and honest unavailability, with no
  fabricated record of any kind.
