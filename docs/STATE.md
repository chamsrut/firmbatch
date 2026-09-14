# Firmbatch — current state

**This is the canonical state document.** The roadmap's references to a "current-state
document" mean this file. There is no `docs/current-state.md`; do not create one.

Five labels, kept strictly apart:

- **CURRENT** — what the code does today, established by reading it.
- **PLANNED** — intended, not built.
- **VERIFIED LIVE** — observed in a real run, with a captured artifact under
  `docs/evidence/`.
- **HISTORICAL** — captured at an older commit. Stays HISTORICAL until the relevant code
  is confirmed unchanged since.
- **NOT VERIFIED** — asserted, expected, or reasoned about, with no captured run behind it.
  Documentation, comments, and passing-in-the-moment are not evidence.

Last updated: 2026-09-14, on `feat/milestone-3-3b-terraform-foundation` from `main` at
`86d4195`, with **Milestone 3.3b — the Terraform, container and delivery foundation — as the
current slice, implemented, statically tested and independently reviewed at implementation commit
`cff27c8`, with every actionable review finding closed, and awaiting pull-request CI and merge** (ADR 0012).
Its final local canonical run was **16 gates passed, 0 failed**, with **257** required files; the image has not
been built locally because Docker is unavailable, and the first actual container build remains a required PR CI
condition. **Milestone 3.3a — the AWS staging, Cognito and Terraform architecture adoption — is merged** through
PR #11 at `86d4195` (documentation only, ADR 0011). **No Terraform plan or apply has run, no AWS or GitHub
resource has been created, no image has been pushed, and no deployment or evidence artifact exists for
Milestone 3.3; nothing of it is VERIFIED LIVE.**
**Milestone 3.2 — the customer-only product portal — is merged** through PR #10 at
`ae61747` (implementation commit `ce097cb`, status commit `59d82a7`), implemented, tested
and independently reviewed: every actionable finding from its four review passes — the
independent review's eleven, the three remaining logout findings and the session-generation
race, the clean-context review's eight, and the final review's two P3 findings — is closed
(see the M3.2 correction sections below). **Milestone 3.1 is merged** at `87159d5` (PR #9,
implementation commit `f92ecb9`, status commit `c841f77`), after two independent review
correction passes whose ten findings and two gaps (Codex) and six findings (GPT-5.6 Sol) are
all corrected, and a third, clean independent review (GPT-5.6 Sol at xhigh effort) that
verified all six of those findings as fixed and raised no actionable regression — see the
three M3.1 review sections below. M3.2 is **not deployed and not VERIFIED LIVE**, and no
evidence artifact has been captured for it. **No AWS deployment and no deployment evidence
exists.**
Milestone 1 merged at
`6b4f341`; M2.1 merged at `712b51a` (implementation commit `521870b`, with the bootstrap
trust-boundary correction `78eae1d` — see the CI correction section below); M2.2 merged at
`b028f21` (implementation commit `d362717`); M2.3 merged at `dca2d49` (implementation
commit `89fbdd9`), after four independent security reviews whose twenty-three findings are
all corrected (see the four correction-pass sections below); **M2.4 merged at `4511f7d`
(PR #7, implementation commit `d91e4f2`, status commit `290f715`)**, after three
independent reviews whose six, five and two findings are all corrected (see the three M2.4
correction-pass sections below). Wherever this document says "at M2.3", it means the state
of commit `89fbdd9`; "at M2.4" means `d91e4f2`.

**Milestone 2 status: complete and merged.** Its four slices — **M2.1, M2.2, M2.3 and
M2.4 — are implemented, tested and merged to `main`** through PR #7 at `4511f7d`. Milestone
2 is **not deployed and not VERIFIED LIVE**: **no evidence artifact has been captured** for
any of the four. The last verification pass recorded before the merge, at implementation
commit `d91e4f2`, was **14 gates passed, 0 failed**, with **97** required files in the
layout gate and the PostgreSQL foundation suite at **1,746 collected — 1,745 passed,
1 skipped**; the supplied post-merge transcript reported the same 14 gates and 97 files.
Those are HISTORICAL observations at those commits, not this document's claim about any
later commit — see "Asserted — artifact pending" for the run at the current one. Every
actionable M2.4 review finding is corrected and migration `0003` is unchanged history.

**Architecture revision D.1 is adopted as PLANNED (Milestone 3.0, merged at `116b5ee`, PR #8).** The
target is now `docs/architecture/v1-target-architecture.md` at revision D.1 (Phase 0
purchased capacity, evaluation and internal qualification tiers, bridge envelope with gross
accrued enforcement, purchase and measurement records, cost-aware routing, and the ten rev D
review items resolved against the settlement canon, plan v3.4 and roadmap r2_4), with the
verbatim D.1 and D sources under `docs/architecture/sources/`, the resolutions and the
genuinely remaining choices in `docs/architecture/rev-d-decision-register.md`, and the
decision in ADR 0008. **Nothing rev D or D.1 adds is implemented.** The operator capacity
agent remains separate operator-side software, now scheduled for Phase P (after a supplier
signs) rather than Milestone 6. **Milestone 3.1 — membership-bound identity, sessions and
credential issuance — is merged at `87159d5` (PR #9); it is not deployed and not VERIFIED
LIVE.** **Milestone 3.2 — the customer-only product portal — is merged at `ae61747` (PR #10,
implementation `ce097cb`); implemented, tested and independently reviewed, not deployed and
not VERIFIED LIVE** (ADR 0010). **Milestone 3 remains active.** M3.3a — the AWS staging,
Cognito and Terraform architecture adoption (ADR 0011) — is merged through PR #11 at `86d4195`;
it records the Cognito adoption decision and splits M3.3 into four slices — M3.3a architecture,
M3.3b Terraform and task scaffolding, M3.3c the bootstrap, identity-binding and broker programs
with the identity mapping and dependencies, M3.3d authorized deployment and evidence. **M3.3b
is the current slice**: implemented, statically tested and independently reviewed at `cff27c8`, awaiting
pull-request CI and merge; scaffolding only, with nothing planned, applied, pushed or deployed (ADR 0012). **M3.3c is next** and owns the
executable identity broker, database bootstrap and identity-binding programs and migration
`0008` (renumbered: `0007` is the incidental password-hash correction found by M3.3b's
verification, ADR 0012 decision 14). Nothing of M3.3 is deployed; the customer can see the real hosted portal only after
M3.3d. See the CURRENT sections and PLANNED below.

---

## CURRENT — Milestone 0 documentation baseline

Milestone 0 aligned repository guidance with revision C of the approved v1 target
architecture (the target has since moved to revision D.1 at Milestone 3.0 — see that section
below; the authority structure Milestone 0 established is unchanged):

- `docs/architecture/v1-target-architecture.md` is the repo-native target specification.
- `docs/firmbatch-v1-roadmap.md` is the active implementation sequence.
- `docs/architecture/v1-capability-baseline.md` records the initial target gap map.
- `docs/firmbatch-pilot-roadmap.md` is retained as superseded historical context.

This milestone changes documentation and authority only. Product behavior remains the v0 prototype described below.

---

## CURRENT — Milestone 1 migration audit — **COMPLETE**

Milestone 1 reconciles every v0 product module against the target:

- `docs/architecture/v0-to-v1-migration-audit.md` is the code-cited migration matrix.
- `docs/adr/0003-v0-v1-cutover-strategy.md` records the parallel-build and deletion boundary.

The audit retains measured concepts and diagnostic assets, replaces all production authorities,
and requires no v0 database or public API compatibility layer. It changed no product behavior.

**Completed and merged at `6b4f341`** ("Merge pull request #3 from
chamsrut/audit/milestone-1-v0-target"). The canonical gate — a reviewed migration matrix
accounting for every product module, with the destination and required proof for each — is
satisfied by that document. No repository evidence artifact was captured for the merge itself;
the gate is a reviewed document, not an observed run.

---

## CURRENT — Milestone 2.1 PostgreSQL and tenant-isolation spine

The first slice of Milestone 2, built beside frozen v0 under ADR 0003. Nothing in
`control_plane/` imports or modifies `control/`, `controller.py`, `worker/`, `providers/` or
`fb.py`, and v0 runtime behavior is unchanged.

**Implemented and tested.** Not deployed, and not VERIFIED LIVE — see the qualification at the
end of this section.

> **One mechanism in this section has been replaced.** M2.1's tenant context was the
> transaction-local `app.tenant_id` setting, which the runtime role could write. Milestone
> 2.3 replaced it with a context the runtime cannot write, dropped
> `firmbatch.app_current_tenant_id()`, and rewrote every policy. This section is kept as
> the record of what M2.1 built and why; where it describes `app.tenant_id`,
> `set_tenant_context` or `tenant_transaction`, read the M2.3 section below for what those
> became. Everything else M2.1 established — forced RLS, the pinned schema, the verified
> principal, the separated credentials, the connection and identity-map hardening, the
> disposable-cluster safety — is unchanged and still asserted.

| Component | Behaviour |
| --- | --- |
| `control_plane/config.py` | The configuration boundary. `FIRMBATCH_ENV` must be `test` or `production`, with **no default**. Application and migration/admin URLs are separate variables. Any non-PostgreSQL URL is rejected — there is no SQLite fallback. Test helpers refuse any database not matching `firmbatch_test_[0-9a-f]{12}` and any admin URL not pointing at a maintenance database. Every URL rendered for a human has its password redacted, including in `__repr__`; generated secrets are scrubbed from exception text. |
| `control_plane/db/base.py` | Pins the dedicated `firmbatch` schema, the version table, and the `search_path` (`firmbatch, pg_catalog, pg_temp` — `pg_temp` explicitly **last**). |
| `control_plane/db/models.py` | `tenants` and tenant-owned `workspaces`, schema-qualified. UUID primary keys with `gen_random_uuid()` server defaults, `timestamptz` throughout, explicit `ON DELETE CASCADE` foreign key, tenant-local uniqueness on workspace slug **and** name, a `UNIQUE (id, tenant_id)` composite key for future child tables, and slug-format/name-length check constraints. |
| `control_plane/db/migrations/` | One Alembic migration, `0001_tenant_workspace_spine`, hand-written. Creates the schema, the tables, `firmbatch.app_current_tenant_id()` (with `EXECUTE` revoked from PUBLIC), and the RLS DDL. Role-agnostic (`TO PUBLIC`), so it is deterministic across environments. Version table pinned to the same schema. Reversible: `downgrade` to `base` and back up is tested. |
| RLS | Row-level security **enabled and forced** on both tables, with one `FOR ALL` policy per table comparing the tenant column against the transaction-local `app.tenant_id` setting. Absence of context makes the predicate NULL: reads return nothing, writes are rejected. |
| `control_plane/db/engine.py` | Engine factories and `tenant_transaction` / `transaction` helpers. Every transaction opens by clearing `app.tenant_id` before applying the requested context, so a session-level value cannot be inherited. Any change of context expunges the SQLAlchemy identity map. Every new pooled connection pins `search_path`, clears the tenant setting, and verifies its principal; a connection that fails is closed, not leaked. |
| `control_plane/db/principal.py` | Asks the live catalogue whether a connection authenticated as a superuser, a `BYPASSRLS` role, a tenant-table owner, or a member of any role that is (`pg_has_role(..., 'MEMBER')`). Inspects the **authenticated `session_user`**, not just `current_user`: a privileged login can preselect a restricted role and hide behind it. `RESET ROLE` first, then require the two to agree and to match the role the URL claimed. Fail-closed, including when the inspection itself fails. |
| `control_plane/db/roles.py` | The grants that separate the owner, the restricted application role, and the narrow provisioning role. Revokes `TEMP` on the database, `CREATE` on schemas, and `EXECUTE` on the tenant-context helper from PUBLIC first — nothing is inherited from a PostgreSQL default. Deliberately outside the migration: role names are environment-specific. |
| `control_plane/db/repositories.py` | `TenantRepository` (provisioning) and `WorkspaceRepository` (tenant-scoped). Neither writes a `WHERE tenant_id = ...` clause; RLS is the filter. |
| `control_plane/testing/attestation.py` | The disposable-cluster marker (a `NOLOGIN` role with an exact comment) and the cluster fingerprint, plus a `--mark`/`--check`/`--unmark` CLI. No database or role is created or dropped on an unattested server. |
| `control_plane/testing/bootstrap.py` | Creates a disposable `firmbatch_test_<random>` database plus **three** per-run `NOSUPERUSER NOBYPASSRLS NOREPLICATION` login roles -- a per-run owner (the migration principal and the deletion authority), an application role and a provisioning role -- migrates it, applies the grants, and drops all three afterwards. Cleans up after any failure, including during migration and grants. Teardown re-checks attestation, cluster identity, URL consistency, the recorded endpoint, and that the handle was produced by this process and is unaltered. The bootstrap administrator is **trusted** and confined to `TestBootstrapSettings` and an attested disposable cluster; the temporary `SET` membership taken for `CREATE DATABASE ... OWNER` is given back and that is verified from the catalogue, but nothing asserts the administrator cannot reach the roles it creates -- CI runs it as the `postgres` superuser, which reaches every role by fiat. See ADR 0004 section 8f. |
| `control_plane/tests/` | **382 pytest checks at M2.1** (the suite is larger now — see the Milestone 2.2 section below) against real PostgreSQL 16, in nineteen modules: configuration boundary, settings separation, connection specification, connection environment, migrations, migration entry points, version preflight, tenant isolation, isolation hardening, bind forms, ownership boundary, admin escalation, bootstrap safety, bootstrap lifecycle, connection identity, destructive safety, verification reporting, role privileges, plus the shared conftest. They **fail rather than skip** when the server, the attestation, or `FIRMBATCH_TEST_DATABASE_URL` is absent, and refuse any PostgreSQL major version other than 16. |
| `requirements-v1*-lock.txt` | Fully resolved, hash-pinned dependency graphs for CPython 3.11 on Linux, generated with `pip-compile --generate-hashes`. CI installs from these with `--require-hashes`. |

Design decisions are recorded in `docs/adr/0004-postgresql-tenant-isolation-foundation.md`,
including what this does **not** claim: RLS bounds what a query reaches given a context; it
does not bind the context to an authenticated credential. That is M2.3/M3 work and is not
implemented.

### Not implemented in M2.1 — deliberately

No HTTP endpoints, customer accounts, memberships, sessions, or API credentials. No
idempotency records, transactional outbox, audit events, or lifecycle state machines. No job
tables, quotes, billing, payload plane, providers, or workers. Those are M2.2, M2.3, M2.4 and
later milestones; building them here would be the opportunistic later-milestone work the
working contract forbids. (M2.2 has since added the first two of those; the rest are still
not built.)

### Hardening pass — nine defects found by review, all reproduced and closed

A review after the first M2.1 implementation found fifteen issues; six were security or
destructive-safety defects that were **reproduced against a real server** before being fixed,
and are now regression-tested:

| Defect | What was demonstrated | Closed by |
| --- | --- | --- |
| Temporary-table shadowing | `CREATE TEMP TABLE workspaces (...)` as the application role, then an unqualified `SELECT` with **no tenant context**, returned the forged row. PostgreSQL searches the temporary schema before `search_path`, and the policy is attached to the table the query never reaches. | Dedicated `firmbatch` schema, everything qualified, `search_path` naming `pg_temp` last, `TEMP` revoked from PUBLIC |
| Inherited tenant context | A session-level `app.tenant_id` — set by a plain `SET` on a pooled connection, or through a URL `options=-c ...` — became the effective tenant of a transaction that set none, and read another tenant's rows. | Empty transaction-local baseline at the top of every transaction; setting cleared on connect |
| ORM identity-map leakage | A reused `Session` holding a strong reference returned tenant A's object under tenant B, with PostgreSQL never consulted. | `expunge_all()` on any change of tenant context |
| Unverified runtime principal | Nothing checked that the application URL named an unprivileged role; a superuser or owner URL would have left forced RLS decorative. URL comparison cannot establish this. | Per-connection catalogue check of `rolsuper`, `rolbypassrls`, table ownership, and role membership |
| Teardown trusted its handle | A handle whose URLs pointed at two different servers was accepted, because the endpoint check used `inet_server_port()`, which is NULL over a unix socket. **The real database was dropped.** Found by the new safety tests. | Endpoint recorded at creation; cluster fingerprint; per-process provenance and field-by-field comparison |
| Generated password disclosure | The password appeared in the exception text of a failing `CREATE ROLE`, which psycopg echoes — and CI retains. | psycopg literal composition plus scrubbing of every raised error |

Also closed: no disposable-cluster attestation (a `/postgres` URL is not evidence a server is
throwaway); orphaned databases and roles after a failed bootstrap; `EXECUTE` on the tenant
helper left at PostgreSQL's PUBLIC default; a cross-tenant write test that passed because a
later `assert` raised inside `pytest.raises(Exception)`; an unused PostgreSQL-16 fixture; a
dependency graph pinned only at its direct edges; verification documentation that still called
the pass side-effect free; and a gate that showed only the tail of pytest output, hiding the
root database exception.

### Second hardening pass — ten more findings, all confirmed and closed

A second independent review found ten further issues. Six were confirmed by reproducing
them against a real server before the fix:

| Finding | What was demonstrated | Closed by |
| --- | --- | --- |
| Query-level database redirection (P1) | `/postgres?dbname=template1` validated as `postgres` and libpq connected to `template1`. `_swap_database` preserved the override, so migrations would have run somewhere other than the database just created. | Allowlist of connection parameters; every routing/identity override rejected; live `current_database()` checked after connecting and again before migrations and grants |
| `session_user` never inspected (P1) | With the owner `SET ROLE`d to the restricted app role, the principal check reported `is_safe` while the authenticated identity was the table owner, one `RESET ROLE` away. | `RESET ROLE` before inspecting; `current_user` and `session_user` must agree; both identities drive every privilege, ownership and membership test; `session_user` must match the role the URL named |
| No revalidation on pool checkout (P1) | A pooled connection was accepted on checkout after its role was granted ownership of a tenant-scoped table. | `checkout` event revalidates the principal and invalidates the connection on failure |
| Nested-savepoint identity-map leakage (P1) | After a savepoint rollback PostgreSQL correctly restored tenant A, and `session.get()` still returned the tenant B object from the identity map. | Tenant switches prohibited inside a savepoint; class-wide `after_transaction_end` guard expunges when any savepoint ends on a hardened engine |
| Same-name object replacement (P2) | The disposable database was dropped and recreated under the same name; teardown destroyed the replacement. | Every created object recorded by OID plus a random `COMMENT` marker, re-checked immediately before each drop |
| SIGPIPE in the failure reporter (P2) | `awk ... \| head -n 60` over a 5,000-line log exited **141** under `pipefail`, aborting the script and losing the traceback, the log path, the gate result and the final summary. | Pipe removed; each `awk` reads the log directly |

Also closed: partial-bootstrap cleanup bypassed the validated path and could drop a
pre-existing role that merely shared a generated name (P2); an existing
`firmbatch_test_<hex>` database was accepted as a maintenance connection (P2);
`AGENTS.md` claimed no pytest suite exists (P3); and `docs/STATE.md` said CI installs the
unlocked requirements input rather than the hash-pinned lock (P3).

### Third hardening pass — eight more findings, all confirmed and closed

A third independent review found eight further issues, five of them P1. Six were confirmed
by reproducing them against a real server before the fix:

| Finding | What was demonstrated | Closed by |
| --- | --- | --- |
| Multi-host and omitted identity fields (P1) | A URL could name two hosts, or omit user/host/port entirely -- libpq then fills them from `PGUSER`/`PGHOST`/`PGPORT`, or picks one host of a failover set at connect time. Six such URLs were accepted. | A canonical `ConnectionSpec`: every field required and singular, the connection rebuilt from the parsed spec, and the same spec used for validation, creation, swapping, fingerprinting and the expected-user check |
| Alembic opened a second connection (P1) | The bootstrap probed one connection; Alembic resolved the URL and opened another. DNS or failover can put the second on a different cluster. | Alembic is handed the already-validated connection and re-validates it -- database, cluster, endpoint, principal -- immediately before the first DDL, and again before the grants |
| `rolreplication` unchecked (P1) | The runtime-principal check tested only SUPERUSER and BYPASSRLS. RLS has no bearing on the WAL: a REPLICATION role streams every tenant without a `SELECT`. | The full documented profile is enforced: SUPERUSER, BYPASSRLS, REPLICATION, CREATEDB, CREATEROLE, direct and reachable |
| Identity map survived the outer transaction (P1) | With `expire_on_commit=False`, a committed `Session` kept its cache: a later context-free transaction returned the tenant-A object from memory while the same row read through SQL returned `[]`. | The class-wide guard now fires on the outermost transaction as well as on savepoints |
| Bind forms unrecognised (P1) | `Session(bind=engine.connect())` and `engine.execution_options(...)` were not recognised as hardened, so the savepoint guard silently did nothing for them -- a cross-tenant object survived a savepoint rollback. | The marker moved from Engine identity to the **pool**, which every bind form shares; bind resolution tolerates mapper binds and a raising `get_bind()` |
| Reporter hid the terminal exception (P2) | The 60-line window after the FAILURES heading contains wrapper frames; the actionable `OperationalError` is at the *end*. | Two windows: opening context and the tail of the log |

Also closed: the destructive `DROP` is now bound to a per-run owner identity rather than
ambient admin authority, with the residual threat named rather than claimed away (P2, see
ADR 0004 section 8e); a disposable `firmbatch_test_<hex>` database was accepted as a
maintenance connection (P2); and CI validated only the development lock, so a broken
runtime lock could pass (P2 -- both locks now install into separate clean environments).

Two modelling errors of my own were found by these changes and fixed: the cluster
fingerprint compared `server_port` and `database`, which describe a *connection* rather
than a cluster and rejected a valid owner connection; and the savepoint guard was scoped to
sessions built by this module, which missed the hand-constructed case it most needed to
cover.

### Fourth hardening pass — ten more findings, all confirmed and closed

A fourth independent review found ten further issues, five of them P1. Every one was
reproduced against a real server before being fixed, and two of the reproductions changed
what the fix had to be.

| Finding | What was demonstrated | Closed by |
| --- | --- | --- |
| Encoded authority hosts (P1) | `urlsplit` does not percent-decode the host, so a raw scan for commas and slashes missed `h1%2Ch2` and `%2Fvar%2Frun%2Fpostgresql`. Both were accepted and both reached psycopg. Whether they decode first is a property of whichever URL library sits in between -- SQLAlchemy happens not to unquote hosts today, which is luck. | The **decoded** host is validated against a closed grammar: IPv4, IPv6, or DNS name. Host lists, socket paths and every delimiter are outside it. The rendered URL is then re-parsed and compared, and the tests assert through `create_connect_args` -- what psycopg is actually handed |
| Ambient libpq environment (P1) | An explicit URL does not neutralise the environment. `PGOPTIONS='-c search_path=pg_temp,public'` reached the server through a fully explicit socket URL; `PGHOSTADDR` overrides the host of a validated URL outright. | One central policy, checked from the `do_connect` dialect event and again on pool checkout, on **every** engine this package builds. Fail-closed and never mutating `os.environ`, because unsetting around a connect would race the very moment the connection is made. `PGPASSWORD`/`PGPASSFILE` are exempt and documented: they can decide whether authentication succeeds, never who or where |
| Optional migration validation (P1) | `downgrade_to(url, rev)` took a bare URL and no validator, and `alembic upgrade head` opened its own connection with no validation at all. A downgrade drops tables and policies, so it was the more dangerous of the two. | Every online entry point now requires a live pre-validated `Connection` **and** a validator; `env.py` refuses a direct invocation before `SET`, `CREATE SCHEMA` or any DDL. Offline `--sql` rendering is untouched -- it executes nothing |
| Ownership checked too narrowly (P1) | The check covered two tenant tables. The database, the `firmbatch` schema, every other relation, `app_current_tenant_id()` and every type were all unguarded -- and an owner does not have to defeat a policy, it can remove one. | One `UNION` over all five object kinds, direct and SET-ROLE-reachable, from both identities, with a precise rejection reason |
| Persistent admin reachability (P1) | `CREATE DATABASE ... OWNER` needs `SET ROLE`, and the grant that provided it was never revoked, leaving an explicit standing membership row on every per-run owner. | Granted for one statement, revoked in a `finally`, and verified on a **new** session against `pg_auth_members`. Verified live on a non-superuser admin: afterwards it gets `must be owner of database` for `COMMENT`, `ALTER ... CONNECTION LIMIT`, `ALTER ... RENAME` and `DROP DATABASE`. **The isolation claim originally attached to this row was wrong and has been withdrawn** — see "CI correction" below and ADR 0004 section 8f |
| Altering before identifying (P2) | `REVOKE CONNECT` and `pg_terminate_backend` ran by name, on the admin connection, **before** any OID or provenance check. Pointed at a same-name replacement they would have hit it. | Both now run as the owner, after the target's OID, marker and live `datdba` are re-read on that same connection. Tested with a live session on a replacement: grants, connection limit and session all untouched |
| Non-transactional role creation (P2) | `CREATE ROLE`, `COMMENT` and the identity read were three autocommit statements. A failure at the second or third left a real role behind that no cleanup list knew about -- and this module refuses to drop what it cannot prove it created, so that role was permanent. | One transaction, with the identity recorded *before* the commit. Recording after leaves a window holding a real unrecorded object; recording before leaves one holding an identity for a role that never existed, which cleanup treats as a no-op |
| Unproven states around `CREATE DATABASE` (P2) | The owner's maintenance URL was built *after* the admin block, so any failure between `CREATE DATABASE` and the end of that block cleaned up with no owner authority and left the database behind. | An explicit state machine. The owner's cleanup authority is proven before anything is created; the database OID is recorded the instant `CREATE DATABASE` returns, before the marker is written |
| CI never ran the product on the runtime lock (P2) | The lock job imported `sqlalchemy`, `alembic`, `psycopg`. A production module importing something only the development lock provides would install, import and test cleanly, and fail in production. | `scripts/check-runtime-imports.py`: `--static` in `verify-repository.sh` checks every production import against the runtime lock; `--dynamic` in CI imports all of it on a clean runtime environment, runs a real entry point, and proves nothing leaked in from the development one |
| Wrong `FORCE` guidance (P3) | `docs/tasks/current.md` said non-superuser teardown *needs* `DROP DATABASE ... WITH (FORCE)`. The implementation deliberately has none. | Corrected, with the reason: `FORCE` needs the privileges of the roles whose backends it terminates, so it broadens teardown authority rather than narrowing it |

Two of my own errors surfaced while fixing these. `pg_has_role(..., 'MEMBER')` is the wrong
probe for "can this role become that one" -- in PostgreSQL 16 it stays true for the implicit
`ADMIN` grant a `CREATEROLE` creator receives, even when `SET ROLE` is refused; `'SET'` and
`'USAGE'` describe real reach. And granting `WITH SET TRUE` without `INHERIT FALSE, ADMIN
FALSE` leaves an *inheriting* membership row behind after `REVOKE SET OPTION FOR`, which is
a standing grant under another name. Both were caught by the new assertions rather than by
reading. A third error, larger than either, is recorded under "CI correction" below:
`pg_has_role` was then used as a *bootstrap-success requirement*, which asked the wrong
question entirely of a trusted administrator.

### Fifth hardening pass — ten findings, nine closed and one reclassified

A fifth independent review found ten issues, five of them P1. Nine are corrected. **One was
reported as a design blocker and has since been reclassified as an accepted boundary** —
see below, and ADR 0004 section 8f.

| Finding | What was demonstrated | Outcome |
| --- | --- | --- |
| Shared-admin access to the owner role (P1) | The request was to revoke the *entire* membership, ADMIN included. PostgreSQL 16 does not permit it. | **Not a defect.** Reclassified: the bootstrap administrator is trusted and confined, not isolated. See the note below |
| Bypassable migration validation (P1) | `upgrade_to_head(conn, validate=lambda c: None)` authorised DDL against anything at all, and read like a checked migration. A seam in a safety check is a bypass with extra steps. | The callback is gone. What travels is an immutable `ExpectedIdentity` (database, cluster system identifier, endpoint, principal); `env.py` calls the canonical validator itself and refuses anything that is not that type — a callable, a flag, or a look-alike object |
| Unguarded attestation connections (P1) | `attestation._admin_engine` built a bare engine. Marking and unmarking decide whether anything else may create or drop, so a misdirected connection there is worse than an ordinary one. | The same `do_connect` guard as every other engine |
| A race window before `engine.connect()` (P1) | The migration path checked the environment once, then connected. An engine can be built, the environment can change, and the connection opens under it. | The check moved onto the engine as a `do_connect` handler, so it runs immediately before *each* physical DBAPI connection. Every engine constructor in the package audited |
| Credentials in the retained pytest log (P1) | `--tb=long` renders every fixture value at the head of a failure, so `environment = {'FIRMBATCH_TEST_DATABASE_URL': '...'}` publishes the privileged URL; psycopg echoes `CREATE ROLE ... PASSWORD '...'`. Redacting only the printed excerpt leaves the file the failure message names. | `--tb=short`, both files created 0600 before writing, the retained file is the sanitized one, the raw capture deleted, and the displayed windows read the sanitized file |
| User information never decoded (P2) | `urlsplit` does not decode user info, so `p%40ss` reached psycopg as seven literal characters and authentication failed with a correct password. All seven test cases wrong. | Decoded exactly once, with malformed escapes refused; `URL.create` re-encodes canonically. `@ : % space` and Unicode all verified through `create_connect_args` |
| Incomplete libpq environment boundary (P2) | The denylist omitted `PGSSLMINPROTOCOLVERSION`, `PGSSLCERTMODE`, `PGSSLSNI`, `PGCLIENTENCODING`, `PGGSSDELEGATION` — precisely the TLS and session controls that matter. | Inverted to an allowlist: every `PG*` variable is refused except `PGPASSWORD`, `PGPASSFILE` (credential-only) and `PGDATA` (read by the server, never by libpq). A variable PostgreSQL has not shipped yet is refused too |
| Bind forms sampled, not enumerated (P2) | Both identity-map defects were in one cell of *bind form* × *transaction outcome*, not in the guard. | The grid is enumerated: four bind forms × outer commit/rollback/exception, nested commit/rollback/exception, context clear, and an A→B transition, plus an unrelated-engine control |
| "Zero roles" was the wrong assertion (P2) | The cluster is supposed to keep exactly one role forever — the attestation marker. A count that ignored the distinction could pass while a per-run role survived. | Per-run objects are named by kind and asserted individually; the marker is asserted **present**. Two consecutive lifecycles compared against the starting state |
| Stale documentation (P3) | Counts and descriptions had drifted. | Corrected here and in the roadmap task notes |

**The PostgreSQL 16 mechanism, stated precisely.** When a non-superuser `CREATEROLE` role
creates a role, PostgreSQL 16 gives the creator a `pg_auth_members` row whose **grantor is
the bootstrap superuser**, carrying `admin_option`. A non-superuser cannot remove that row:
a plain `REVOKE` and `REVOKE ADMIN OPTION FOR` both warn and change nothing, and
`REVOKE ... GRANTED BY postgres` is refused outright. All three spellings were verified
against a real server. Holding `ADMIN OPTION`, that administrator can re-grant itself `SET`
and become the owner at will. A superuser administrator receives no such row and needs
none.

**This was reported as a blocker, and that classification was wrong.** It is not a defect
to be closed; it is the boundary the architecture already draws. The bootstrap
administrator is trusted, and the row is also what lets a non-superuser administrator
`DROP ROLE` the per-run roles at teardown — removing it, were that possible, would trade an
accepted property for a guaranteed leak of three roles per run. The correction is recorded
in full below.

### CI correction — the bootstrap administrator is trusted, not isolated

The reclassification above was forced by a real failure rather than by an argument. The
Milestone 2.1 foundation branch could not pass CI:

```
DisposableDatabaseError: the shared admin can still reach the per-run owner
(pg_has_role reports SET and USAGE)
```

`bootstrap._require_no_set_reachability()` required
`pg_has_role(admin, owner, 'SET'/'USAGE')` to be **false** before it would return a handle.
CI's bootstrap administrator is the `postgres` **superuser** of an ephemeral `postgres:16`
service container, and a superuser satisfies `pg_has_role` for every role in the cluster by
definition. The assertion was unsatisfiable there, and it was asserting a property the
accepted test-infrastructure boundary never promised.

**What the code now states, consistently, in `bootstrap.py`, ADR 0004 section 8f and here:**

- the bootstrap administrator is **trusted**;
- **CI** runs it as the `postgres` superuser inside an ephemeral PostgreSQL service
  container, created and destroyed by the job;
- **local verification** runs it as a non-superuser `CREATEROLE` administrator on an
  explicitly attested disposable cluster;
- PostgreSQL administrative reachability into the per-run roles is **accepted inside that
  boundary** and nowhere else — no isolation from it is claimed;
- **customer and runtime roles remain untrusted and separated**, and that is asserted
  identically in CI and locally.

**What changed.** `_require_no_set_reachability()` is gone as a bootstrap-success
requirement, replaced by `_require_temporary_membership_released()`: same catalogue reads —
every direct `pg_auth_members` row plus a recursive walk for indirect paths — with the
`pg_has_role` questions removed. The one-statement `SET` grant is still taken and still
given back in a `finally`, and an explicit `set_option` or `inherit_option` row surviving
where PostgreSQL permits revoking it still fails bootstrap. That property holds for a
superuser and a non-superuser administrator alike.

`tests/test_admin_escalation.py` was rewritten to match. The test that asserted the
administrator could re-acquire the owner role and perform an owner-only operation is
**removed**: a passing test whose subject is a working escalation is not evidence of
anything the product sells. What replaces it tests containment — bootstrap completes under
either kind of administrator; no revocable membership row or path carries `SET` or
`INHERIT`; the three per-run roles hold no administrative attribute, gain no route into the
administrator, and (for the runtime pair) none into the migration owner; the
administrator's credentials appear in no runtime URL. The PostgreSQL 16 `CREATEROLE`
limitation stays asserted for a non-superuser administrator and skips, with a stated
reason, for a superuser. The two owner-only-refusal assertions that are meaningless for a
superuser now `skip` with that reason rather than `continue` past a green they did not
earn.

Nothing else moved. Runtime-principal validation, application-versus-migration settings
separation, forced RLS, the tenant transaction and identity-map guards, exact migration
connection validation, disposable-cluster attestation, database and role identity checks,
and the refusal to load bootstrap settings as application settings are all unchanged and
still asserted.

### The tenant-context limitation, and what it blocked — **closed by M2.3**

**This limitation no longer holds.** Milestone 2.3 replaced the mechanism it describes;
what follows is the record of what M2.1 delivered and what it deliberately did not, kept
because the shape of the gap is the reason the M2.3 design is what it is. For what is true
now, see the Milestone 2.3 section below.

Milestone 2.1 provides **structural** tenant isolation. It is worth stating exactly what
that buys, because "tenant isolation" will otherwise be read as more than it is.

**What holds now (interim, Milestone 2.1):**

- forced row-level security on `tenants` and `workspaces` — `FORCE` binds the owner too;
- a missing `WHERE tenant_id = ...` in application code exposes nothing;
- a transaction with no context fails closed: reads return nothing, writes are rejected;
- pooled connection state and ORM identity maps do not carry one tenant into another's
  transaction;
- application and migration credentials are separated by type, and the runtime process
  cannot load the privileged one;
- **the application service remains a trusted setter of tenant context.**

**What does not hold.** The runtime role can execute
`set_config('app.tenant_id', <any uuid>, true)`, and RLS then evaluates faithfully against
whatever tenant it was told. An attacker holding the runtime database credential, or
reaching arbitrary SQL through injection, can select any tenant they can name. This defends
against *mistakes* — a forgotten filter, a stale pooled connection, an ORM cache — not
against a compromised runtime credential.

**Required before customer-facing v1** (unchanged, and not yet met): the runtime service
cannot select an arbitrary tenant UUID; context is derived from a verified customer
credential; the database trusts an opaque or signed capability rather than a raw
`app.tenant_id`; the runtime cannot mint a capability for an arbitrary workspace; a leaked
runtime credential or SQL injection cannot select another tenant.

**Customer-facing deployment is blocked until that is implemented and tested.** Tracked as
`AUTH-BOUND-TENANT-CONTEXT` in Milestone 3 of `docs/firmbatch-v1-roadmap.md`, with the five
adversarial tests that must pass. ADR 0004 §8g records the reasoning.

No test asserts that the limitation exists. A passing test whose subject is a vulnerability
reads as a specification for it, and would have to be deleted rather than fixed when the
capability lands.

**Where that stands at M2.3.** The **database and GUC portion is closed.** Cases 1 to 4 of
the completion gate — arbitrary context, a leaked runtime credential, SQL injection reaching
arbitrary statements, and replay or forgery of a capability — are met and tested
adversarially against real PostgreSQL 16; see "What M2.3 proves" below. Arbitrary runtime
SQL can no longer select a tenant without possessing a valid tenant-bound credential.

Case 5 — an authenticated user with no membership in a workspace — is **not** the same
question and is no longer tracked under this name. There are no users and no memberships
yet to be a non-member of, so what remains is a Milestone 3 boundary and it is recorded as
one: **`AUTH-MEMBERSHIP-BOUND-IDENTITY`**, in the PLANNED section below. Keeping the old
name on it would mean a blocker whose description no longer matches what is missing.

**Customer-facing deployment remains blocked** until Milestone 3 supplies identity,
membership and credential lifecycle. Nothing in this section was deleted when the database
half landed: the prose was the tracking, which is what the paragraph above was for.

### What the passing tests establish, and what they do not

They establish **implemented and tested** behaviour on a locally provisioned PostgreSQL 16
server, in a database created and destroyed by the run. They are **NOT VERIFIED LIVE** under
this document's taxonomy: no artifact under `docs/evidence/` captures the run, no RDS instance
exists, and nothing is deployed. Do not cite the test count as deployment proof.

---

## CURRENT — Milestone 2.2 idempotent mutations and the transactional outbox

The second slice of Milestone 2, delivered on `feat/milestone-2-2-idempotency-outbox` by
implementation commit `d362717` and **merged at `b028f21` (PR #5)**. It preserves everything
M2.1 established — PostgreSQL isolation, credential separation, migration validation,
connection hardening, disposable-database safety, and the frozen-v0 boundary — and adds
two tenant-scoped tables behind the same forced row-level security, plus one typed
primitive that writes them.

**Implemented and tested.** Not deployed, and **not VERIFIED LIVE**: no evidence artifact
was captured for this slice.

| Component | Behaviour |
| --- | --- |
| `control_plane/db/models.py` | Two new tenant-owned tables. `idempotency_records` — UUID key, `tenant_id`, `operation`, `idempotency_key`, `request_fingerprint` (hex SHA-256), a `status` column constrained to the single value `completed`, and a bounded `jsonb` `result`. Unique on `(tenant_id, operation, idempotency_key)`; composite `(id, tenant_id)` key. `outbox_events` — `tenant_id`, a **nullable** `idempotency_record_id` causation link, `event_type`, `aggregate_type`, `aggregate_id`, bounded `jsonb` `attributes`, `occurred_at`. Composite foreign key to `(id, tenant_id)` of the claim when the link is present, unique on `(tenant_id, idempotency_record_id)` (**at most one** linked event per claim), index on `(tenant_id, occurred_at)`. Neither table has a binary column. |
| `control_plane/db/migrations/versions/0002_idempotency_and_outbox.py` | Hand-written, `down_revision = 0001`, reversible (downgrade to `base` and back up is tested). Row security **enabled and forced** on both tables, `REVOKE ALL ... FROM PUBLIC`, and a **`FOR SELECT` policy plus a `FOR INSERT` policy and nothing else** — with no `UPDATE` or `DELETE` policy, those commands reach no row for any role, the owner included. Role-agnostic (`TO PUBLIC`); grants stay in `db/roles.py`. |
| `control_plane/db/idempotency.py` | The primitive. In one transaction: validate the operation, the key and the `request_identity` **before anything runs**, refuse a session carrying unflushed ORM state, require a tenant context, refuse a non-`READ COMMITTED` transaction, fingerprint the identity, replay a matching claim, reject a conflicting one, otherwise run the mutation inside a `SAVEPOINT`, write the completed claim and exactly one linked outbox event, and return a typed `IdempotentResult`. A caller that loses a race rolls its savepoint back — undoing its own business write — re-reads the winner's row and replays it. Metadata policy: flat objects, no binary values, ≤ 32 keys, ≤ 256-character strings, ≤ 2 KiB documents, lowercase identifier keys matched with `fullmatch`, and a **whole-name** denylist of key names meaning content or a credential. |
| `MutationUnitOfWork` (`db/idempotency.py`) | What the mutation callback is given **instead of the caller's `Session`**. Forwards `add`, `flush`, `execute`, `get`, `scalars`, `delete`, `merge`; refuses `commit`, `rollback`, `close`, `begin`, `begin_nested`, `connection`, `get_bind`, `expunge_all` and the legacy bulk API with an explanatory error. |
| The scoped commit guard (`db/idempotency.py`) | `Session.commit()` in SQLAlchemy 2.x commits the **outermost** transaction from inside a `begin_nested()` SAVEPOINT, and the real session is one `object_session(row)` away from any callback. So for the duration of the callback — and only that — a `before_commit` listener is attached to the real session and **refuses the commit before it happens**, ahead of the flush a commit performs, so nothing is written. It is removed in a `finally` before the primitive releases its own SAVEPOINT and before the caller commits, so nothing stays attached to a session that outlives the call. `_require_intact_boundary` remains as **secondary detection** of a boundary destroyed another way (a rollback through the real session); it is not a preservation of atomicity, because nothing in Python can un-commit. |
| `append_outbox_event` (`db/idempotency.py`) | The one outbox writer, usable by **any** authoritative state transition. `idempotency_record_id` is an optional causation link, so an internal transition — controller, reconciler, validator, lifecycle — can commit its event with its state change without manufacturing an API idempotency record. |
| `control_plane/db/roles.py` | The application role gains `SELECT, INSERT` on both new tables and nothing else. The provisioning role gains **nothing**. No role attribute changed. |
| RLS and grants together | Append-only is enforced twice, in two directions: no `UPDATE`/`DELETE` privilege for the application role (an error it can see), and no `UPDATE`/`DELETE` policy at all (zero rows for anyone who holds the privilege, including the owner under `FORCE`). |
| `control_plane/tests/` | **512 pytest checks** (511 passed, 1 skipped locally), up from 382: three new modules — `test_idempotency.py`, `test_idempotency_concurrency.py`, `test_outbox_isolation.py` — plus new schema and policy assertions in `test_migrations.py`. |

Design decisions are recorded in
`docs/adr/0005-idempotent-mutations-and-transactional-outbox.md`.

### What M2.2 proves

| Property | Where |
| --- | --- |
| An identical retry returns the stored result and runs the mutation zero times. | `test_idempotency.py::test_an_identical_retry_returns_the_stored_result`, `::test_the_second_call_never_runs_the_mutation` |
| Four identical calls leave one workspace, one claim, one event, and invoke the mutation once. | `::test_an_identical_retry_makes_exactly_one_contractual_effect` |
| The primitive writes **exactly one** linked event, atomically with the claim — counted after a real commit, because the uniqueness constraint can only bound duplicates and cannot require existence. | `::test_the_primitive_writes_exactly_one_linked_event` |
| Reuse of a key with a different request is rejected, and changes nothing. | `::test_reusing_a_key_with_a_different_request_is_rejected` |
| Two **concurrently contending** callers commit one effect and one event; the loser executes, is rolled back, and replays. Contention is verified by watching `pg_stat_activity` for a blocked backend, and the test fails if the block is never observed. | `test_idempotency_concurrency.py::test_two_concurrent_callers_produce_one_effect_and_one_event` |
| A concurrent *conflicting* reuse is still rejected rather than handed the winner's result. | `::test_a_concurrent_conflicting_reuse_is_rejected` |
| A failure inside the mutation, a failure after the primitive returns, and a refused result each leave no workspace, no claim and no event — and do not block the retry. | `test_idempotency.py::test_a_failure_inside_the_mutation_leaves_nothing_behind`, `::test_a_failure_after_the_primitive_returns_rolls_the_whole_thing_back`, `::test_a_rolled_back_claim_does_not_block_the_retry`, `::test_a_refused_result_leaves_nothing_behind` |
| The same key is independent between tenants, sequentially and concurrently. | `::test_a_key_is_independent_between_tenants`, `test_idempotency_concurrency.py::test_concurrent_callers_in_different_tenants_do_not_collide` |
| Cross-tenant reads and writes on **both** new tables fail closed, and an event cannot be attached to another tenant's claim. | `test_outbox_isolation.py::test_tenant_a_cannot_read_tenant_b_claims_or_events`, `::test_tenant_a_cannot_append_into_tenant_b`, `::test_an_event_cannot_be_attached_to_another_tenants_claim` |
| Missing tenant context fails closed, in the primitive and again in PostgreSQL. | `test_idempotency.py::test_without_an_authenticated_context_an_idempotent_mutation_is_refused`, `::test_the_database_also_refuses_a_claim_written_without_context`, `test_outbox_isolation.py::test_without_tenant_context_an_append_is_rejected` |
| A committed event is immutable: the application role is refused, and even the owner's `UPDATE`/`DELETE` matches zero rows. | `test_outbox_isolation.py::test_a_committed_event_cannot_be_rewritten_through_the_orm`, `::test_even_a_privileged_role_reaches_no_row_to_update_or_delete` |
| A mutation callback cannot commit or roll back the primitive's transaction: the unit of work refuses both, and a commit reached through `object_session()` is refused **before** it happens, leaving no workspace, no claim and no event. | `test_idempotency.py::test_a_mutation_cannot_commit_the_outer_transaction`, `::test_a_mutation_that_rolls_back_fails_cleanly_and_leaves_nothing`, `::test_the_unit_of_work_refuses_every_transaction_control_operation`, `::test_an_escape_around_the_unit_of_work_is_detected_and_refused`, `::test_the_transaction_boundary_survives_the_callback` |
| The commit guard is scoped to the callback and removed afterwards: the SAVEPOINT release and the caller's own commit both go through, and the workspace, the claim and the linked event persist. | `::test_the_commit_guard_is_removed_before_the_caller_commits` |
| Unflushed ORM state at entry is rejected before the mutation runs, so nothing pending is flushed outside the protected SAVEPOINT. | `::test_pending_orm_state_at_entry_is_rejected` |
| A write the caller flushed *before* calling the primitive is outside its SAVEPOINT and cannot be detected — recorded as a limit, with the contract that closes it. | `::test_a_write_flushed_before_the_primitive_is_outside_its_savepoint` |
| A malformed operation or idempotency key — including a trailing newline, which `$` would have accepted — is refused **before** the mutation is invoked, and the check constraints still refuse a writer that bypasses Python. | `::test_a_malformed_operation_is_refused_before_the_mutation`, `::test_a_malformed_idempotency_key_is_refused_before_the_mutation`, `::test_the_database_still_refuses_a_malformed_operation` |
| The primitive persists only a fingerprint and bounded metadata: no value of the request identity reaches a row. Payload- and credential-shaped fields are refused **before** the mutation runs, and reference-shaped names (`input_manifest_id`, `output_object_key`, `artifact_digest`) are accepted. | `::test_only_a_digest_of_the_request_identity_is_persisted`, `::test_payload_shaped_material_is_rejected_before_the_mutation_runs`, `::test_keys_that_name_content_or_a_credential_are_refused`, `::test_reference_shaped_keys_are_accepted` |
| An internal tenant-scoped state change appends an outbox event atomically **without** an idempotency record, two such events do not collide, and a rollback removes the state change and the event together. | `test_outbox_isolation.py::test_an_internal_state_change_can_append_an_event_without_an_idempotency_record`, `::test_two_internal_events_do_not_collide_on_the_null_link`, `::test_a_rolled_back_internal_change_takes_its_event_with_it`, `::test_an_internal_event_is_still_tenant_scoped` |
| Every tenant-scoped table scopes reads **and** writes, asserted on `USING` and `WITH CHECK` independently rather than on whichever one happened to be set. | `test_migrations.py::test_every_tenant_scoped_table_has_an_isolation_policy` |
| The application role holds exactly its allowlist per table; provisioning holds nothing on any of them; neither gained ownership or a privileged attribute. | `test_outbox_isolation.py::test_the_application_role_holds_exactly_its_allowlist`, `::test_the_provisioning_role_holds_only_what_it_must`, `::test_neither_runtime_role_gained_a_privileged_attribute` |

### Not implemented in M2.2 — deliberately

No HTTP endpoints and no `Idempotency-Key` header handling; no SQS publishing and **no
outbox dispatcher**, so events accumulate and nothing reads them; no idempotency-record
expiry or retention (pruning needs a `DELETE` policy these tables deliberately do not
have); no audit events, no tenant-scoped authorization, no secrets model, no lifecycle
state machines, no job/quote/billing tables, no payload plane, no AWS deployment, no Rust
or C++. Those are M2.3, M2.4 and later milestones. v0 is untouched.

(M2.3 has since added audit events, tenant-scoped authorization and the secrets model. The
dispatcher, expiry, lifecycle state machines and everything after them are still not
built.)

### What M2.2 does not claim

**It does not claim exactly-once external message delivery, and nothing in the repository
should be read as claiming it.** The outbox records durable intent. No dispatcher exists;
when one does it will deliver **at least once**, and consumers must be idempotent. What is
proved is one committed database effect and one linked outbox event per
`(tenant, operation, key)`.

**It does not claim that the database guarantees every claim has an event.** The unique
constraint on `(tenant_id, idempotency_record_id)` enforces **at most one** linked event; a
uniqueness constraint bounds duplicates and cannot require existence. The primitive writes
exactly one, atomically with the claim, and that is established by the PostgreSQL tests
rather than by the schema. A deferred constraint trigger could make it a database fact and
was deliberately not built: it would be machinery added to preserve a sentence.

**It does not prove the payload-plane invariant.** M2.2 establishes that *the primitive
persists only a fingerprint and bounded metadata*, and that payload- and credential-shaped
fields are refused before a mutation runs. It does **not** establish that customer payload
bytes never enter the API process or PostgreSQL — target invariant 3 — and three earlier
claims to that effect have been removed as false: the absence of a `bytea` column makes
storing bytes inconvenient rather than impossible, a 256-character string can be content,
and a bounded `jsonb` document is a size limit rather than a semantic filter. `TEXT` and
`JSONB` hold text. The bounds and the denylist are defense in depth. **The data-flow proof
belongs to Milestone 5** and its presigned S3 path.

**It does not sandbox the mutation callback.** The `MutationUnitOfWork` removes the reflex
route out of the transaction, and the scoped `before_commit` guard closes the known escape
through `object_session()` — refusing the commit before it can flush, so no partial state
is created. Neither bounds arbitrary Python: a callback that opens its own engine or
connection, drops to the DBAPI, or issues `COMMIT` as raw SQL is outside this transaction
and outside anything the module can observe. This is the same guardrail-not-boundary
position `AGENTS.md` takes about the policy engine.

**It does not cover business writes made before it is called.** A write the caller already
flushed is not in `session.new`/`dirty`/`deleted`, so the entry check cannot see it, and it
sits outside the primitive's SAVEPOINT — a lost race that discards the mutation would leave
it. The rule is a contract: every business write for the operation goes inside `mutate`,
and the primitive is called before any DML for that operation.

**It does not weaken or replace the M2.1 limitation.** Everything M2.2 established sat
inside the boundary ADR 0004 §8g describes: an attacker who could set `app.tenant_id` could
claim keys in any tenant they could name. (M2.3 closed that boundary. The M2.2 properties
are unchanged and now rest on the authenticated mechanism; the sentence is kept as the
record of what M2.2 itself could claim.)

**It holds only under `READ COMMITTED`, and says so rather than assuming it.** The
primitive refuses anything stricter, because its recovery path re-reads
a row another transaction has just committed. Under `REPEATABLE READ` that read would
return nothing and the caller would be told a taken key is free.

---

## CURRENT — Milestone 2.3 authenticated context, authorization, audit, and secrets

The third slice of Milestone 2, delivered by implementation commit `89fbdd9` and **merged at
`dca2d49` (PR #6)**. It closes the gap M2.1 named and M2.2 left standing: a transaction no
longer chooses its tenant, it presents a credential and is told which tenant it got.

**Implemented and tested.** Not deployed, and **not VERIFIED LIVE**: no evidence artifact
has been captured for this slice.

Everything M2.1 and M2.2 established is preserved — forced row-level security, the pinned
schema, the verified runtime principal, separated credentials, connection and identity-map
hardening, disposable-database safety, idempotent mutations, the transactional outbox, and
the frozen-v0 boundary. What changed is where tenant context comes from, and every M2.1 and
M2.2 test now runs against the new mechanism.

| Component | Behaviour |
| --- | --- |
| `control_plane/db/migrations/versions/0003_auth_context_and_audit.py` | Hand-written, `down_revision = 0002`, reversible. Adds the protected credential registry, the audit trail, one composite type, eighteen functions, and **replaces every policy on every tenant-owned table**. Drops `firmbatch.app_current_tenant_id()`: a function that looks like the mechanism and is not one is worse than no function. Role-agnostic (`TO PUBLIC`); grants stay in `db/roles.py`. |
| `firmbatch.auth_bindings` | The credential registry. Fingerprint (hex SHA-256, globally unique), tenant, principal, `text[]` scopes bounded by a check constraint against the closed catalogue, optional expiry, revocation timestamp, composite `(id, tenant_id)` key. **Protected rather than policed**: `REVOKE ALL ... FROM PUBLIC` and no grant to any runtime role, so no policy is needed and none exists. |
| `firmbatch.bind_authenticated_context(text)` | The one way in. Hashes the presented credential *in the database*, looks the digest up, and refuses an unknown, revoked or expired binding with a **single indistinguishable error**. Takes no tenant, no principal, no binding id, no scope. |
| `firmbatch.auth_context_begin(...)` | Writes the transaction-local context. **Executable by nobody** — a role that could call it could name any tenant and any scope set. Reached only from inside other definer functions. |
| The transaction-scoped context | One row in `firmbatch.auth_transaction_context`, an **unlogged, protected** table in the pinned schema keyed by the backend pid and carrying the `xid8` of the transaction that wrote it. No role but the owner holds any privilege on it. Read back only when `xact_id = pg_current_xact_id_if_assigned()`, so an uncommitted row is invisible to every other transaction and a committed one can never match a future transaction's id. **Nothing clears it and nothing can**: there is no clearing function in Python or in the database. One row per pid, replaced in place, so the table is bounded and needs no pruning. |
| `firmbatch.auth_require_read_committed()` | Called first by both entry points. Refuses any isolation level but `READ COMMITTED`, in the database, because the property is about the snapshot the *registry lookup* runs under: a stricter level would read the registry through a snapshot older than the statement and a revocation committed in between would be invisible. Executable by nobody. |
| The ACL sanitiser | The migration ends by stripping every privilege on every relation, function and type in the schema from everybody except its owner, with the grantees enumerated from `pg_catalog`. `REVOKE ... FROM PUBLIC` does not remove what `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>` granted at object-creation time. `db/roles.py` runs the identical block before its grants; a test asserts the two copies are the same text. |
| `firmbatch.begin_tenant_provisioning()` | The one context that cannot come from a credential, because a tenant has no credential until it exists. Takes **no arguments** and generates the tenant id itself, so provisioning cannot be pointed at an existing tenant. Granted to the provisioning role alone. |
| `firmbatch.register_auth_binding` / `revoke_auth_binding` | The minimal protected persistence foundation M3's credential lifecycle builds on. Neither takes a tenant: both derive it from the current context, so no caller can mint a capability into a tenant it does not already hold. Both require `credential:manage`. **Registration takes no credential either** — it generates one from two `gen_random_uuid()` values (**244 bits**: 122 each) and returns it once, so a caller cannot submit a candidate and learn from the outcome whether it already exists in another tenant. |
| The accessors | `auth_tenant_id`, `auth_principal_id`, `auth_binding_id`, `auth_actor_kind`, `auth_scopes`, `auth_has_scope`. Thin `STABLE` SQL functions over `auth_context()`. `auth_has_scope` coalesces, so an unbound transaction gets `false` rather than NULL. |
| Every policy | One per command, rather than one `FOR ALL`. `USING`/`WITH CHECK` are `tenant matches the authenticated context AND the context holds the required scope`. A command with no policy reaches no row for any role, the owner included, because row security is `FORCE`d. |
| `control_plane/security/authorization.py` | The closed permission catalogue: seven scopes, one `ResourceRule` per tenant-owned table with its read rule, write rule, kind and the reason for it. No scope names an operator, supplier, provider, routing, settlement, certification or internal-control capability, and `RESERVED_NON_CUSTOMER_DOMAINS` plus a test keeps it that way. |
| `firmbatch.audit_events` | Tenant-scoped and append-only. `tenant_id`, `actor_kind`, `actor_principal_id` and `actor_binding_id` come from the authenticated context by column default **and** are re-checked by the insert policy; `occurred_at` is written by a `BEFORE INSERT` trigger from `clock_timestamp()`, which overwrites whatever arrives — so a caller can neither supply a time nor keep its transaction's start time by opening the transaction early. Composite foreign key to `auth_bindings (id, tenant_id)`. Closed `outcome` enum including `attempted` and `denied`. No `UPDATE` or `DELETE` policy and no such grant. |
| `control_plane/db/audit.py` | `append_audit_event(session, AuditEventSpec)` — validates action, resource type, outcome and bounded details, requires an authenticated context, and appends inside the caller's transaction without committing. It calls `firmbatch.append_audit_event(...)`, because **no runtime role holds `INSERT` on the trail**: the same rules are applied again inside the database, on the values about to be written. The function has no parameter for any derived column and returns the id as its result rather than through `RETURNING`, which would require `audit:read` to append. |
| `control_plane/db/auth.py` | The Python side: `AuthenticatedContext`, `bind_authenticated_context`, `begin_tenant_provisioning`, `authenticated_transaction`, `provisioning_transaction`, `register_auth_binding`, `revoke_auth_binding`. Thin by design — every decision it makes is made again in PostgreSQL by a function the caller cannot reach around. |
| `control_plane/db/engine.py` | `tenant_transaction(engine, tenant_id)` and `set_tenant_context` are **gone**, and so is any way to clear a context. `transaction()` opens by *asserting* it starts unauthenticated rather than by making that true. The identity-map and savepoint guards are unchanged and now fire on a change of authenticated context. |
| `control_plane/db/principal.py` | Gains two disqualifying conditions. **Any role membership at all**, enumerated with `pg_has_role(..., 'MEMBER')` so the whole transitive chain is reported; and **any privilege on a protected relation, or `EXECUTE` on an internal function, held by any reachable role** rather than only by the connecting identity. The second is the correction: `has_table_privilege` follows *inherited* privilege, so `GRANT other TO app WITH INHERIT FALSE, SET TRUE` answered "no" while one `SET ROLE` reached everything `other` held. |
| `control_plane/security/secrets.py` | The four secret classes as types: `Secret` (nothing renders it, not even its length; pickle, copy and hashing are closed), `SecretReference`, `EncryptedValue` + `KeyReference`, and the migration credential, which deliberately has no type here. Production resolvers and encryptors **raise**; the test doubles refuse to exist outside `FIRMBATCH_ENV=test`. `looks_like_secret()` names a shape and never a value, and every reference field runs it **before** format validation; all three types define `__repr__` explicitly rather than taking the dataclass default. |
| `control_plane/db/metadata.py` | The bounded-metadata policy, extracted from `db/idempotency.py` so the audit trail holds itself to the same rule; every public name is re-exported from where it was. Two rules added: **keys as well as values** are refused for carrying a recognisable secret shape, checked *before* the format test; and **no refusal quotes what it refused** — an error names the rule and the position (`entry 3`, `entry 3, item 5`) and never the key, the value, or its length. |
| `control_plane/db/repositories.py` | Neither repository takes a `tenant_id` any more. `TenantRepository.create` uses the id the provisioning context generated; `WorkspaceRepository.create` uses the authenticated one. |
| `control_plane/db/roles.py` | **Revision-aware.** Each supported schema revision has an explicit `RevisionPlan` naming its tables, its functions and its per-role grant set; an unknown, mixed or unsupported revision is refused rather than guessed at, and at head every declared object is required to exist. The application role gains `EXECUTE` on the twelve runtime auth functions and `SELECT` — **not `INSERT`** — on `audit_events`; provisioning gains those plus `begin_tenant_provisioning`, and nothing at all on the trail. Neither gains anything on `auth_bindings` or `auth_transaction_context`, and neither may execute any internal function. |
| `control_plane/tests/` | **1315 pytest checks (1,314 passed, 1 skipped locally)**, up from 512: five new modules — `test_authenticated_context.py`, `test_authorization.py`, `test_protected_auth_state.py`, `test_audit_events.py`, `test_secrets_model.py` — plus every existing module moved onto the authenticated mechanism. The last 380 of those come from the third and fourth correction passes below. |

Design decisions are recorded in
`docs/adr/0006-authenticated-authorization-audit-and-secrets.md`.

### What M2.3 proves

| Property | Where |
| --- | --- |
| `set_config('app.tenant_id', <victim uuid>, true)` grants nothing — no row, no context, on any tenant-scoped table. Completion-gate case 1. | `test_authenticated_context.py::test_setting_the_old_tenant_guc_grants_nothing`, `::test_a_session_level_setting_survives_the_pool_and_still_grants_nothing` |
| No fabricated custom setting grants anything, including plausible new names. | `::test_no_fabricated_setting_grants_anything` |
| An attacker holding the full runtime credential reaches no other tenant: every command against the registry is refused, and the only input that produces a context is a credential. Completion-gate cases 2 and 3. | `test_protected_auth_state.py::test_the_application_role_is_refused_every_command_on_protected_state`, `test_authenticated_context.py::test_a_fabricated_tenant_id_is_not_something_bind_will_take` |
| A fabricated tenant id, binding id, fingerprint, actor or scope buys nothing; the function that writes a context is executable by nobody. Completion-gate case 4. | `test_authenticated_context.py::test_a_fabricated_binding_id_grants_nothing`, `::test_the_context_writer_is_executable_by_nobody`, `::test_a_fabricated_fingerprint_cannot_be_registered`, `::test_a_fabricated_actor_cannot_be_asserted`, `::test_a_scope_outside_the_catalogue_cannot_be_stored` |
| No runtime role can read, insert into, update, delete from or truncate the transaction-context relation, and neither can the provisioning role. A grant on it -- direct, inherited, or reachable by `SET ROLE` -- is refused at connect and again at pool checkout. | `test_protected_auth_state.py::test_the_application_role_is_refused_every_command_on_protected_state`, `::test_the_provisioning_role_is_refused_protected_state_too`, `::test_a_direct_grant_on_the_transaction_context_is_disqualifying`, `::test_a_reachable_role_holding_protected_state_is_reported` |
| A **column-level** grant on protected state disqualifies too, checked independently of the table privilege: the reported `SELECT (backend_pid), UPDATE (tenant_id)` exploit, every one of PostgreSQL's four column privileges, both protected relations, direct grants, `PUBLIC`, `SET ROLE`-reachable and transitively reachable holders, and one added after wiring which fails the next pool checkout. Both ACL sanitisers strip column-only grants, and a control asserts the ordinary principal holds none. | `test_protected_auth_state.py::test_the_reported_column_grant_exploit_is_refused_at_connect`, `::test_a_table_privilege_is_not_what_reports_a_column_privilege`, `::test_any_column_privilege_on_protected_state_disqualifies`, `::test_every_column_privilege_postgresql_has_is_covered`, `::test_a_column_grant_on_a_reachable_role_is_reported`, `::test_a_column_grant_reached_through_a_membership_chain_is_reported`, `::test_a_column_grant_to_public_is_reported`, `::test_a_column_grant_after_provisioning_fails_the_next_checkout`, `::test_both_sanitisers_remove_a_column_only_acl`, `::test_a_failing_column_probe_leaves_no_grant_and_no_role_behind`, `::test_the_ordinary_application_principal_reaches_no_column_either` |
| Unknown, malformed, revoked and expired credentials all fail closed, with one indistinguishable message so the failure is not an oracle. | `::test_an_unknown_credential_fails_closed`, `::test_a_malformed_credential_fails_closed`, `::test_a_revoked_credential_fails_closed`, `::test_an_expired_credential_fails_closed`, `::test_every_credential_failure_reports_the_same_thing` |
| A malformed credential is refused before it reaches the database, so a typo cannot reach a statement log. | `::test_a_malformed_credential_fails_closed`, `::test_a_malformed_credential_sent_straight_to_the_database_also_fails` |
| Binding twice, or switching identity, inside one transaction is refused — and the refusal leaves neither identity in force. | `::test_binding_twice_is_refused`, `::test_switching_identity_inside_one_transaction_is_refused`, `::test_a_refused_second_bind_does_not_change_the_standing_context` |
| Context does not survive a commit, a rollback, a failed statement, pool reuse, or ORM `Session` reuse; a Connection-bound `Session` is refused outright. | `::test_a_context_does_not_survive_a_commit`, `::test_a_context_does_not_survive_a_rollback`, `::test_a_context_does_not_survive_a_failed_statement`, `::test_a_context_does_not_survive_pool_reuse`, `::test_a_context_does_not_survive_orm_session_reuse`, `::test_a_connection_bound_session_is_refused_rather_than_half_defended` |
| Acquiring a context inside a savepoint is refused, and there is no raw route to change one there either. | `test_isolation_hardening.py::test_acquiring_a_context_inside_a_savepoint_is_refused`, `::test_there_is_no_raw_route_to_change_the_context_inside_a_savepoint` |
| A valid credential reaches its own tenant and no other; two credentials in one tenant see one tenant. | `test_authenticated_context.py::test_a_valid_credential_reaches_its_own_tenant_and_no_other`, `::test_two_credentials_in_one_tenant_reach_the_same_rows` |
| The credential is never stored: the row holds SHA-256 of it and nothing else, checked from the owner connection which is subject to no policy on that table. | `::test_the_credential_is_never_stored_and_never_returned` |
| Deny by default: a credential with no scopes is authenticated and reaches nothing, anywhere. | `test_authorization.py::test_a_credential_with_no_scopes_reaches_nothing` |
| Read and write scopes are distinguished on the customer resource: a read-only credential lists workspaces and cannot create, rename or remove one. | `::test_a_read_only_credential_can_read_and_cannot_write`, `::test_a_write_credential_can_amend_and_remove` |
| The framework tables take `mutation:execute` and nothing else; the audit trail takes `audit:read` to read and no scope to append. | `::test_the_framework_tables_take_the_minimal_framework_capability`, `::test_reading_the_audit_trail_takes_audit_read`, `::test_appending_to_the_audit_trail_needs_no_scope` |
| The catalogue, the database check constraint and the models agree about the scope vocabulary, and no scope names a supplier, operator or internal capability. | `::test_the_database_and_the_catalogue_agree_on_the_scope_vocabulary`, `::test_no_scope_names_a_non_customer_capability`, `::test_every_tenant_owned_table_has_exactly_one_rule` |
| A credential cannot be minted into another tenant, and a scope held in one tenant means nothing in another. | `::test_a_credential_cannot_be_minted_into_another_tenant`, `::test_a_scope_held_in_one_tenant_means_nothing_in_another`, `::test_holding_every_scope_still_reaches_only_one_tenant` |
| Provisioning cannot be pointed at an existing tenant, cannot read tenant data, and cannot reach an existing tenant's row. | `test_role_privileges.py::test_provisioning_cannot_be_pointed_at_an_existing_tenant`, `::test_provisioning_role_cannot_read_tenant_data`, `::test_provisioning_cannot_reach_an_existing_tenants_row` |
| Every `SECURITY DEFINER` function is owned by the schema owner, pins a safe `search_path`, grants `EXECUTE` to no `PUBLIC`, is granted to exactly the roles that need it, contains no dynamic SQL, and resolves no relation but the one fixed context relation. | `test_protected_auth_state.py::test_every_function_is_owned_by_the_schema_owner`, `::test_every_function_pins_a_safe_search_path`, `::test_public_holds_execute_on_nothing`, `::test_the_runtime_functions_are_granted_to_exactly_the_runtime_roles`, `::test_provisioning_only_functions_are_not_granted_to_the_application_role`, `::test_no_function_builds_a_statement_or_looks_an_object_up_by_a_caller_name`, `::test_every_reference_in_every_body_is_schema_qualified` |
| The context writer and its ownership check are executable by nobody, and the security type of every function is the one that was decided. | `::test_the_context_writer_and_its_guard_are_granted_to_nobody`, `::test_the_security_type_of_every_function_is_what_was_decided` |
| The registry has no grants and no policy, the owner can read it (so the refusals mean something), and a runtime role cannot even ask whether a fingerprint exists. | `::test_no_role_holds_any_privilege_on_protected_state`, `::test_the_registry_carries_no_row_level_security_and_says_why`, `::test_the_owner_can_read_the_registry_so_the_refusals_mean_something`, `::test_a_runtime_role_cannot_discover_whether_a_fingerprint_exists` |
| An audit event records tenant, actor kind, principal, binding, action, outcome, resource, correlation and a server timestamp — and a caller cannot supply any of the derived ones. | `test_audit_events.py::test_an_event_records_the_whole_question_it_exists_to_answer`, `::test_the_function_has_no_parameter_for_any_derived_column`, `::test_not_even_the_owner_can_attribute_an_action_to_somebody_else`, `::test_a_supplied_timestamp_is_discarded_rather_than_stored`, `::test_an_event_cannot_be_dated_from_the_transactions_start`, `::test_the_primitive_offers_no_way_to_name_an_actor` |
| Cross-tenant audit reads and writes fail closed, and the actor reference is composite so it cannot point across tenants. | `::test_one_tenant_cannot_read_anothers_trail`, `::test_the_actor_reference_is_composite_and_therefore_tenant_consistent` |
| A committed audit event is immutable: the application role is refused, and even the owner's `UPDATE`/`DELETE` matches zero rows. | `::test_a_committed_event_cannot_be_changed_by_the_application_role`, `::test_even_the_owner_reaches_no_row_to_change` |
| Audit insertion participates in the caller's transaction: a rollback takes the record with the action, and nothing is durable before the caller commits. | `::test_a_rolled_back_action_takes_its_audit_record_with_it`, `::test_the_record_commits_with_the_action_and_not_before`, `::test_appending_does_not_commit_the_callers_transaction` |
| Audit details are bounded metadata; payload- and credential-shaped material is refused before the row, and the refusal never echoes the value. | `::test_details_are_bounded_metadata`, `::test_details_may_not_name_content_or_a_credential`, `::test_a_secret_shaped_value_is_refused_before_the_row`, `::test_a_secret_object_cannot_be_smuggled_into_details`, `::test_a_secret_never_renders_itself_in_an_audit_failure` |
| Audit and outbox events remain distinct: one carries an actor, the other does not, and an internal transition writes an outbox event and no audit record. There is no hash chain column and no delivery-state column. | `::test_audit_events_and_outbox_events_are_different_records`, `::test_an_internal_transition_appends_an_outbox_event_and_no_audit_record`, `::test_there_is_no_hash_chain_column` |
| An unexpected database error on a credential-bearing statement is re-raised with the credential scrubbed out, and with nothing attached to it that renders the failing statement's parameters. | `test_authenticated_context.py::test_an_unexpected_database_error_does_not_carry_the_credential_with_it` |
| A `Secret` renders nothing of itself by any route — `repr`, `str`, `format`, `.format`, inside a list, inside a dict, inside an exception — and does not leak its length; it cannot be pickled, copied or hashed. | `test_secrets_model.py::test_a_secret_renders_nothing_of_itself_by_any_route`, `::test_a_secret_does_not_leak_its_length`, `::test_a_secret_cannot_be_serialized_or_copied`, `::test_a_secret_is_not_hashable` |
| Production resolution and encryption raise rather than falling back; the test doubles refuse to exist outside `test`; and there is no configuration that substitutes one. | `::test_the_production_resolver_raises_rather_than_falling_back`, `::test_the_production_encryptor_raises_rather_than_storing_plaintext`, `::test_the_test_environment_gets_the_same_unimplemented_adapters`, `::test_a_test_double_refuses_to_exist_in_production` |
| An envelope carries a version and an opaque key reference and never renders its ciphertext; the model names four classes and a boundary for each; this module imports no AWS SDK and no cryptography. | `::test_an_envelope_carries_a_version_and_a_key_reference_and_no_plaintext`, `::test_an_envelope_renders_its_version_and_key_and_never_its_ciphertext`, `::test_the_model_names_four_classes_and_a_boundary_for_each`, `::test_this_module_reaches_no_aws_sdk_and_no_cryptography` |
| No policy anywhere reads a caller-settable value, and the Milestone 2.1 helper is gone. | `test_migrations.py::test_no_policy_anywhere_reads_a_caller_settable_value`, `::test_the_milestone_21_helper_is_gone` |
| The migration reverses to the Milestone 2.2 shape exactly — the old helper and the old policies restored — and back up again; the grants still apply after a round trip; there is one head; and every revision id fits `alembic_version.version_num`. | `::test_the_authentication_migration_reverses_to_the_milestone_22_shape`, `::test_the_grants_still_apply_after_a_round_trip`, `::test_there_is_exactly_one_head`, `::test_every_revision_fits_the_version_column` |
| A runtime principal that can `SET ROLE` to any other role is refused — bare memberships, `INHERIT FALSE` and `INHERIT TRUE`, transitive chains, and a membership granted after wiring, which fails the next pool checkout. A control asserts the ordinary principal reaches nothing, so the refusals are not vacuous. | `test_protected_auth_state.py::test_a_bare_role_membership_is_disqualifying`, `::test_a_reachable_role_holding_protected_state_is_reported`, `::test_a_membership_chain_is_followed_all_the_way`, `::test_reaching_the_migration_owner_is_disqualifying`, `::test_reachable_ownership_of_a_schema_object_is_disqualifying`, `::test_a_membership_granted_after_wiring_fails_the_next_checkout`, `::test_the_application_connection_is_refused_outright`, `::test_the_ordinary_application_principal_reaches_nothing` |
| A credential may issue only a delegable subset of what it holds: management-only cannot mint a permission, `credential:manage` is delegable, `tenant:provision` is delegable by nobody, and duplicates and cross-surface names are refused without being echoed. | `test_authorization.py::test_an_exact_subset_is_delegable`, `::test_the_whole_scope_set_is_delegable`, `::test_credential_manage_may_be_delegated`, `::test_a_management_only_credential_cannot_mint_a_permission`, `::test_an_attempted_superset_is_refused_scope_by_scope`, `::test_an_empty_scope_set_is_permitted`, `::test_duplicate_scopes_are_refused_by_the_database`, `::test_tenant_provision_cannot_be_delegated_by_anybody`, `::test_a_cross_surface_scope_is_impossible_and_is_not_echoed`, `::test_the_provisioning_actor_may_grant_what_it_does_not_hold` |
| No runtime role can write the audit trail except through the hardened function, and the whole metadata policy holds under raw SQL — checked with a corpus both implementations walk, and with the two shape recognisers compared answer for answer. | `test_audit_events.py::test_no_runtime_role_can_write_the_trail_except_through_the_function`, `::test_python_and_postgresql_both_accept_the_accepted_corpus`, `::test_python_and_postgresql_both_reject_the_rejected_corpus`, `::test_the_databases_refusal_never_quotes_the_document`, `::test_the_shape_recogniser_agrees_in_both_languages`, `::test_the_corpus_covers_every_rule_the_policy_states` |
| Whitespace means the same thing in both implementations: an explicitly enumerated code-point set -- checked against Python's own `\s` -- folded to ASCII before any pattern runs, on keys and on string values alike. Both halves are compared across the **whole** declared set in six separator-sensitive shapes, the reported U+00A0 bypasses are refused by the database itself, ordinary Unicode letters stay valid, and no refusal echoes the value or attaches a chain. | `test_audit_events.py::test_the_declared_whitespace_set_is_exactly_what_python_treats_as_whitespace`, `::test_python_and_postgresql_agree_on_every_declared_whitespace_code_point`, `::test_an_ordinary_note_separated_by_any_declared_whitespace_stays_valid`, `::test_ordinary_unicode_is_not_whitespace_and_stays_valid`, `::test_the_reported_bypasses_are_refused_by_the_database_itself`, `::test_the_python_refusal_of_a_folded_bypass_carries_no_cause_and_no_value`, `test_secrets_model.py::test_the_whitespace_enumeration_is_exactly_pythons_own`, `::test_the_enumeration_contains_every_code_point_the_review_named`, `::test_every_declared_whitespace_folds_to_an_ascii_space`, `::test_a_secret_shape_separated_by_any_declared_whitespace_is_recognised`, `::test_ordinary_unicode_is_left_alone_by_the_fold`, `::test_the_assignment_shape_is_case_insensitive_over_ascii`, `::test_a_shape_refusal_still_names_only_the_shape` |
| An authenticated transaction refuses to run read-only, and the standby predicate is consulted first. Asserted on a primary; **no live standby was tested and none is claimed**. | `test_authenticated_context.py::test_a_read_only_transaction_is_refused_deliberately`, `::test_provisioning_is_refused_on_a_read_only_transaction_too`, `::test_a_read_only_default_is_caught_as_well`, `::test_the_standby_predicate_is_tested_before_the_read_only_one`, `::test_the_guard_runs_before_the_context_write` |
| The writable-primary check is reached **before** anything references the unlogged context relation: a preflight that names nothing in the schema, recovery consulted before read-only, on `transaction()` and on both binding entry points, for a Session bound to an Engine and for one a caller built; a Connection-bound Session is refused before any statement. A mocked recovery answer selects the standby diagnostic; no context helper runs after a failed preflight; the refusal carries no credential, URL or DBAPI material. The database functions' first executed statement is the same guard, asserted from `pg_proc.prosrc`. | `test_authenticated_context.py::test_the_preflight_references_no_relation_at_all`, `::test_a_recovering_server_selects_the_standby_diagnostic`, `::test_a_mocked_standby_refuses_before_it_asks_anything_else`, `::test_a_mocked_primary_is_allowed_through`, `::test_transaction_runs_the_preflight_before_the_inherited_context_assertion`, `::test_the_application_entry_path_preflights_before_anything_else`, `::test_the_provisioning_entry_path_preflights_before_anything_else`, `::test_a_session_bound_to_the_engine_preflights_on_the_bind_itself`, `::test_a_session_bound_to_a_hardened_connection_never_reaches_the_context_either`, `::test_a_read_only_transaction_refuses_before_the_context_relation_is_touched`, `::test_the_preflight_refusal_carries_no_credential_and_no_connection_material`, `::test_the_database_functions_guard_before_anything_else_they_do` |
| Role provisioning works at every supported revision and refuses every other: upgrade → provision → downgrade to `0002` → provision → re-upgrade → provision restores the exact grant set, and unknown, mixed, missing and stamp-disagrees-with-schema revisions are named errors. | `test_migrations.py::test_role_provisioning_survives_a_rollback_to_0002_and_back`, `::test_an_unsupported_revision_is_refused_rather_than_guessed_at`, `::test_a_mixed_or_missing_revision_is_refused`, `::test_a_stamped_revision_whose_objects_are_missing_is_refused`, `::test_the_plans_name_only_objects_their_revision_has` |
| A missing ciphertext leaves no trace of itself in any reachable exception representation, and no lookup in the secrets module subscripts a dictionary whose key it would not print. | `test_secrets_model.py::test_a_missing_ciphertext_leaves_no_trace_of_itself`, `::test_a_real_ciphertext_is_not_echoed_by_a_key_mismatch`, `::test_an_unregistered_reference_leaves_no_trace_of_the_value`, `::test_no_read_in_this_module_subscripts_a_dict_it_would_not_print` |
| The two credential generators carry 256 and 244 bits respectively, the arithmetic is asserted rather than described, and no file calls the 43-character rendering an entropy. | `test_secrets_model.py::test_the_python_generator_is_exactly_thirty_two_random_bytes`, `::test_the_database_generator_is_exactly_two_uuid4_values`, `::test_the_database_generator_really_is_the_source_and_the_shape_matches`, `::test_no_source_file_calls_the_credential_length_its_entropy` |
| Every M2.1 and M2.2 property still holds, on the new mechanism. | The whole of `test_tenant_isolation.py`, `test_isolation_hardening.py`, `test_bind_forms.py`, `test_idempotency.py`, `test_idempotency_concurrency.py`, `test_outbox_isolation.py`, `test_role_privileges.py`, `test_ownership_boundary.py` |

### The M2.3 security correction pass — seven findings, all closed

An independent review of the first M2.3 implementation found seven issues: three P1 and
four P2. Every one was **confirmed against a real server before being fixed**, and two of
the confirmations changed what the fix had to be. One of them changed the architecture.

| # | Finding | What was demonstrated | Closed by |
| --- | --- | --- | --- |
| 1 (P1) | Protected ACLs only revoked `PUBLIC` | `ALTER DEFAULT PRIVILEGES FOR ROLE <owner> IN SCHEMA firmbatch GRANT ... TO <app role>` is applied by the creator at the instant each object is created, so the grant is on `auth_bindings` and on `auth_context_begin` before the migration's next statement — and revoking from `PUBLIC` never touches it. The runtime role would have held the credential registry and the context writer. | The migration ends by sanitising **every** relation, function and type in the schema, enumerating grantees from `pg_catalog`; `db/roles.py` runs the identical block before its grants; and `db/principal.py` refuses a connection holding any privilege on protected state or `EXECUTE` on an internal function |
| 2 (P1) | Revocation and expiry evaluated against a stale snapshot | Under `REPEATABLE READ` the registry lookup reads the snapshot the transaction opened with, so a revocation committed afterwards is invisible and a revoked credential still authenticates. `now()` is transaction-start time, so a long transaction extended a credential's life by its own duration. | `auth_require_read_committed()`, called by both entry points and executable by nobody, refuses anything but `READ COMMITTED` **in the database**; expiry is compared against `clock_timestamp()`. The linearisation point is stated: the bind observes every revocation committed before the bind statement began |
| 3 (P1) | The first context was not irreversible | **`DISCARD TEMP` drops every temporary table in the session, including one owned by somebody else.** No privilege required, nothing to revoke. The context vanished and `bind_authenticated_context` then accepted a **second** credential, so one transaction could act as two tenants. `firmbatch.auth_context_reset()` did the same thing more politely. | **The temporary table is gone.** The context is now an unlogged protected table keyed by the backend pid and carrying the transaction's `xid8`, read back only when it matches `pg_current_xact_id_if_assigned()`. There is no clearing operation in Python or in the database, and none is needed. See ADR 0006 decision 2 |
| 4 (P2) | Cross-tenant credential-existence probing | `register_auth_binding(credential, ...)` inserted what it was given, so a `credential:manage` holder in tenant A could submit a candidate and learn from the unique violation that it existed in tenant B. Renaming the error would not have helped: success versus failure is the oracle | The credential is **generated inside the function** from two `gen_random_uuid()` values and returned once. There is no parameter to submit a candidate through |
| 5 (P2) | Secret/key references echoed their input | `SecretReference`/`KeyReference` interpolated the rejected value into the error, so a bearer credential pasted into a reference field was quoted by the check that refused it | Secret-shape rejection runs **before** format validation on every reference field; no refusal repeats its input; all three types define `__repr__` explicitly; the transitive `EncryptedValue` case is tested |
| 6 (P2) | Audit time was transaction-start time | `occurred_at` defaulted to `now()` with a policy requiring it to equal `now()` — which refused an explicit wrong value and missed the real case: a caller backdates an event by opening its transaction early, and the policy compares the backdated value against the same backdated clock | A `BEFORE INSERT` trigger overwrites `occurred_at` with `clock_timestamp()` on every row. `WITH CHECK` runs after `BEFORE` triggers, so the policy has nothing left to check |
| 7 (P2) | Metadata errors echoed the key | The format check interpolated the offending key *before* anything asked whether the key was itself a secret, so a credential used as a metadata key was echoed into an exception, a traceback and a retained CI log | Shape checks run first, on keys as well as values; refusals name the rule and the position (`entry 3`, `entry 3, item 5`) and never the content or its length; applied to audit details, request identities, outbox attributes, action names and idempotency keys |

**One thing found by the correction pass itself.** Scrubbing a credential out of an
unexpected `DBAPIError` was not enough while the raise happened inside an `except` block:
Python attaches the exception being handled as `__context__`, and `raise ... from None`
suppresses it in a printed traceback without detaching it. The helper now raises **after**
the handler, so nothing is attached at all — and every non-echo test walks the whole
`__cause__`/`__context__` chain rather than reading `str(exc)`.

**What the correction pass added to the suite.** 89 further checks, including: an
adversarial migration test that sets malicious default privileges for tables *and*
functions, migrates, and proves both the sanitiser and the role wiring (with a control
that shows the rule was still live, so the assertion cannot pass vacuously); the full
enumeration of clearing routes -- `DISCARD TEMP`, `DISCARD TEMPORARY`, `DELETE`,
`TRUNCATE`, `DROP`, `ALTER ... RENAME`, `UPDATE`, relation shadowing, savepoint release and
rollback, direct internal invocation -- each followed by an attempt to bind a second
identity; `REPEATABLE READ` and `SERIALIZABLE` refusals with a staged stale-snapshot
revocation; a `READ COMMITTED` transaction that opens before a separately committed
revocation; clock-based expiry; cross-tenant probing with active, revoked and expired
candidates; and non-echo regressions using bearer values, short passwords, database URLs,
access-key shapes and malformed identifiers.

### The second M2.3 correction pass — ten findings, all closed

A second independent review found ten more issues: four P1 (one of them P1/P2) and six P2.
Every one was **confirmed against a real server before being fixed**, and two of the
confirmations were worse than reported.

| # | Finding | What was demonstrated | Closed by |
| --- | --- | --- | --- |
| 1 (P1) | The principal check missed `SET ROLE` memberships | `GRANT other TO firmbatch_app WITH INHERIT FALSE, SET TRUE` plus `GRANT EXECUTE ON auth_context_begin TO other`. `has_function_privilege(current_user, ...)` answers **no** — it follows *inherited* privilege — and the connection was certified safe, then read `firmbatch.auth_bindings` one statement later after a single `SET ROLE`. Measured. | Every reachable role is enumerated once with `pg_has_role(..., 'MEMBER')`, which is transitive, and every attribute, ownership and object test runs against that set. **Any membership at all** is disqualifying besides: a runtime principal has no documented need for one and the bootstrap grants none. Re-checked at connect and again on every pool checkout |
| 2 (P1) | `auth_transaction_context` was not in the protected inventory | The inventory the principal check walked contained `auth_bindings` and nothing else, so a grant on the relation that *is* the context mechanism — direct, inherited, or `SET ROLE`-reachable — was invisible to it. A role holding `INSERT` there writes itself any tenant, principal and scope set | It is a `ResourceRule` of kind `protected` like `auth_bindings`, so every inventory derives from one catalogue: ACL sanitation, `PUBLIC` revocation, the principal check, the role-grant tests and the schema invariants. The per-command refusal tests walk `PROTECTED_TABLES` and a test asserts the write statements cover every entry |
| 3 (P1) | Credential scope delegation was unconstrained | `register_auth_binding` accepted any scope in the catalogue, so a leaked credential holding **only** `credential:manage` could mint itself a successor holding `workspace:write` and `audit:read` — escalation inside the tenant, through the supported interface | Enforced in the `SECURITY DEFINER` function: every requested scope must be **delegable** (`tenant:provision` is not — it belongs to the bootstrap path), and a *credential* issuer may grant only scopes it holds. `credential:manage` **is** delegable, bounded by the subset rule; there is no wildcard. The *provisioning* actor is the one exemption and cannot reach an existing tenant. Unknown scopes are refused before the check constraint, whose violation would render the rejected value in its `DETAIL`. Mirrored in Python for a named error |
| 4 (P1/P2) | Role provisioning was broken after a rollback | upgrade → provision → downgrade to `0002` → provision again raised `UndefinedTable: relation "firmbatch.auth_bindings" does not exist` on the **first** wiring call. A controlled rollback left an environment whose roles could not be re-provisioned | `db/roles.py` is revision-aware: one explicit `RevisionPlan` per supported revision, an existence check for every object it names, and a refusal for an unknown, mixed or unsupported revision. No undefined-object error is caught and continued past. Application code at head supports schema `0002` **only** for controlled rollback and provisioning, never for runtime operation |
| 5 (P2) | Audit metadata rules were bypassable by raw SQL | The application role held `INSERT` on `audit_events`, and the table's check constraints bound a details document's *size and shape* and nothing about its content — so a bearer credential under an innocuous key was refused by Python and accepted by PostgreSQL | The `INSERT` privilege is gone from both runtime roles. `firmbatch.append_audit_event(...)` is the only way in, and it applies the whole policy inside the database: denied and secret-shaped keys, secret-shaped values, nested objects and arrays, unsupported types, key/length/size bounds. It has no parameter for any derived column. A shared corpus of accepted and rejected documents is walked by **both** implementations |
| 6 (P2) | Standby and read-only execution failed unclearly | The context write is one row per authenticated transaction, so a read-only transaction failed with a bare "cannot execute INSERT in a read-only transaction" raised from inside a definer function — which reads as a Firmbatch bug rather than an unsupported deployment | `auth_require_writable_primary()` runs **before** the write and refuses both, `pg_is_in_recovery()` first so a standby is not misreported as a stray `SET`. Translated to `WritablePrimaryRequiredError` with no SQL parameters and no exception chain. **Authenticated reads are primary-only at this milestone**; read-replica routing is Milestone 8 |
| 7 (P2) | A ciphertext-bearing `KeyError` was retained | `self._vault[bytes(ciphertext)]` builds `KeyError(<the ciphertext>)`, whose `args` render it — and raising the sanitized error inside the `except` attaches that object as `__context__`. `from None` suppresses it in a *printed* traceback and does not detach it | Sentinel `.get` instead of a subscript, and the refusal raised after the lookup. Applied to the resolver's lookup too, and a parse-tree test refuses the next `self._vault[...]` load and any `except KeyError` in the module |
| 8 (P2) | The credential entropy claim was wrong | Two `gen_random_uuid()` values are 122 + 122 = **244** bits. Several places said 256, which is the *Python* generator's 32 random bytes, and one place read the 43-character rendering as though it were the measurement | Both numbers written down as they are, in code and in documentation, with the arithmetic asserted. The format is unchanged: the roadmap asks for high entropy and 244 bits is high entropy |
| 9 (P2) | Invalid scope and outcome values were echoed | `scope_values` and the audit outcome check interpolated the rejected value, so a credential passed where a scope belongs was quoted by the check that refused it | Shape check first, then parse, and neither echoes. The refusal names the field, the rule and the **position**. Tested with bearer values, database URLs, access-key shapes, short secrets and ordinary invalid strings, walking the whole `__cause__`/`__context__` graph |
| 10 (P2) | Documentation still described the rejected design | `docs/tasks/current.md` presented the `pg_temp` context, `ON COMMIT DELETE ROWS` and `firmbatch.auth_context_relation()` as current, and `docs/STATE.md` cited two tests that had been removed with them | Both documents describe only the permanent unlogged `xid8`/backend-pid mechanism. ADR 0006 keeps the temporary design under rejected alternatives, where it belongs |

**Two confirmations were worse than reported.** Finding 1's `SET ROLE` reach was not
theoretical — the application connection opened successfully with the membership in place
and then queried the credential registry. Finding 4 failed *earlier* than the review
suggested: not on the function grants but on `REVOKE ALL ON TABLE firmbatch.auth_bindings
FROM PUBLIC`, before any grant had run.

**One thing found by this pass itself, in its own tests.** The first version of the
migration-owner membership test asserted that PostgreSQL refuses the grant as a membership
loop, and did not revoke it. On the full-suite run the grant *succeeded* — the role graph
differs by then — and the application role was left a member of the schema owner, failing
every tenant-isolation test that ran afterwards. It now accepts either outcome, asserts the
principal check refuses where the grant is possible, and revokes in `finally` regardless.
The leak these tests exist to detect arrived from a test.

**What this pass added to the suite.** 129 further checks: `SET ROLE` reachability with
`INHERIT FALSE` and `INHERIT TRUE`, transitive chains, direct grants, reachable ownership,
a membership granted *after* wiring failing the next pool checkout, and a control asserting
the ordinary principal reaches nothing; delegation across exact subsets, whole sets,
attempted supersets, management-only issuers, self-delegation, empty sets, duplicates and
six cross-surface names, in Python and again in raw SQL; a full
upgrade → provision → downgrade → provision → re-upgrade → provision round trip with the
grant set compared at each revision, plus unsupported, mixed, missing and
stamp-disagrees-with-schema refusals; a metadata corpus of 8 accepted and 20 rejected
documents walked by both implementations, with a coverage assertion over the corpus itself
and a shape-recogniser agreement test across two regular-expression dialects; read-only and
`default_transaction_read_only` refusals with the standby predicate's ordering asserted
from the catalogue **and no claim that a live standby was tested**; ciphertext, plaintext
and key-reference absence from every reachable exception representation; and the entropy
arithmetic.

### The third M2.3 correction pass — three findings, all closed

A third independent review found three more: one P1, two P2. Each was **confirmed against a
real server before being fixed**, and each new test was run against the pre-fix code and
seen to fail for the intended reason. Two of the three confirmations changed the diagnosis.

| # | Finding | What was demonstrated | Closed by |
| --- | --- | --- | --- |
| 1 (P1) | Column-level ACLs bypassed the protected-state boundary | As the migration owner, `GRANT SELECT (backend_pid), UPDATE (tenant_id) ON firmbatch.auth_transaction_context TO <application role>` — and the hardened checkout **accepted the connection**. Measured. The application could then authenticate as tenant A, rewrite the context row's `tenant_id` to tenant B, and read tenant B's rows: the whole isolation boundary, from a grant conferring no table privilege at all | Column ACLs are part of the central protected-resource boundary. `db/principal.py` reads `pg_attribute.attacl` directly for every non-dropped user column of every protected relation, against PUBLIC and every `MEMBER`-reachable role, and reports it in a field **separate** from table privileges — not `has_column_privilege`, which answers "table *or* column" and would conflate the two. Both ACL sanitisers gained a column pass, kept identical by the existing equality test. All four column privileges disqualify, on either protected relation |
| 2 (P2) | Python `\s` and PostgreSQL `[[:space:]]` are different sets | A U+00A0 before `Bearer example`, and `token` U+00A0 `=example`, were refused by `validated_metadata` and **accepted by the database** — the half that holds when a runtime role calls `append_audit_event` itself. Confirmed on this server, and wider than reported: U+0085, U+00A0, U+2007, U+202F **and** the four ASCII information separators U+001C–U+001F all diverge | Whitespace is enumerated as data — every code point Python's `\s` matches, asserted against `\s` itself — and folded to a plain ASCII space by both implementations before any pattern runs, on keys and on string values alike. The patterns then say `[ ]`/`[^ ]` in both languages. PostgreSQL's `translate()` consults no locale. Ordinary Unicode letters are untouched and stay valid; no refusal echoes the value or attaches a chain |
| 3 (P2) | The standby diagnostic was unreachable on a standby | `auth_transaction_context` is `UNLOGGED`, and PostgreSQL refuses to *plan* a query against an unlogged relation during recovery. Every authenticated entry path began by reading the current context, so on a replica that read failed first with PostgreSQL's own message and the deliberate `auth_require_writable_primary()` diagnostic was never reached | A preflight naming **nothing** in the schema runs first — `pg_is_in_recovery()` before `transaction_read_only` — at the top of `transaction()` and of both binding entry points, covering a Session bound to an Engine and one a caller built. The error moved to `db/engine.py` (which the preflight must live in) and is re-exported from `db/auth.py`. The database guard is kept as defense in depth and is now the **first executed statement** of both entry functions, so raw-SQL callers fail safely too |

**Two diagnoses changed under measurement.** Finding 1 was reported as `REVOKE ALL ON TABLE`
failing to remove column grants. It does remove them — measured. The actual defect was the
*enumeration*: a role holding only column privileges never appears in `pg_class.relacl`, so
the sanitiser's grantee loop never named it and the revoke was never issued. The fix is a
second enumeration over `pg_attribute.attacl`, not a wider `REVOKE`. Finding 2 was reported
as two code points and is four, plus four ASCII separators nobody had listed.

**What this pass added to the suite.** 188 further checks, and no existing test was weakened
to accommodate any of them. 20 for column ACLs: the exact reported exploit refused at
connect, all four column privileges, both protected relations, a direct grant, a grant to
PUBLIC, `INHERIT FALSE` and `INHERIT TRUE` reachable holders, a transitive chain, a grant
added after wiring failing the next pool checkout, both sanitisers exercised on their own
disposable database, and two controls asserting the ordinary principal holds no column
privilege and the probes leave nothing behind. 155 for whitespace: the declared set checked
against Python's own `\s` and against the migration's duplicate of it, both implementations
compared across all 29 code points in six separator-sensitive shapes, the reported bypasses
refused by the database itself, ordinary Unicode in five scripts still accepted, and
non-echo assertions over the whole `__cause__`/`__context__` graph. 13 for the preflight: that it names no relation, its
predicate ordering, a mocked recovery answer selecting the standby diagnostic, no context
helper invoked after a failed preflight on any entry path, and the SQL functions' first
statement asserted from `pg_proc.prosrc`.

**Still no live standby, and still no claim of one.** The recovery branch is exercised by
handing the pure classifier the answer a replica would give. Live-standby qualification is
Milestone 8.

**A fourth finding came out of this pass's own corpus, and is also closed.** Fixing
whitespace left the identical bug one clause over, in case folding — see the fourth
correction pass below.

### The fourth M2.3 correction pass — the case-fold half of finding 2, closed

The third pass fixed whitespace and left the same defect one clause over. It is a confirmed
security defect in M2.3, not a design question, and it is fixed rather than deferred.

| # | Finding | What was demonstrated | Closed by |
| --- | --- | --- | --- |
| 1 (P1) | `re.IGNORECASE` and `~*` are different case folds | Python's is Unicode, PostgreSQL's is locale. Measured on this server with the whitespace fix already in: U+017F + `ecret=x` (LATIN SMALL LETTER LONG S) and `api` + U+212A + `ey=x` (KELVIN SIGN) were **refused by `db/metadata.py` and accepted by `firmbatch.secret_shape`** — the half with no Python in front of it, reachable by any role that can call `append_audit_event` | One explicit pipeline in both: 29 enumerated whitespace code points to ASCII space, then `A`–`Z` to `a`–`z`, then **case-sensitive** lowercase patterns. No `str.lower()`, `str.casefold()`, `lower()`, `upper()`, `~*` or `(?i)` anywhere — `translate()` and `str.translate` map code point to code point and ask no locale |
| 2 (P1) | `\b` and `\y` were the same bug waiting | `\b` follows Python's Unicode `\w`; `\y` follows PostgreSQL's locale `[[:alnum:]]`. They happened to agree on the corpus, which is not a property | An ASCII word boundary written `(?<![0-9a-z_])`, evaluated identically by both engines. Consequence, stated: a non-ASCII letter is now a boundary, so `ıtoken=x` is recognised where both used to say nothing — stricter, and said together |
| 3 (P2) | The two pattern lists were two dialects of one intent | `\b` against `\y`, `(?i)` against `~*`, `\s` against `[[:space:]]` — all three pairings turned out to mean something different, and a reader comparing them could not see it | With every locale- and Unicode-dependent construct gone, the migration carries a **character-for-character copy** of the pattern text, and a test compares the text rather than comparing answers on chosen samples |

**What this pass added to the suite.** 192 further checks, and nothing was weakened: every
prior check still passes unchanged. The ASCII fold asserted as exactly 26 pairs with every
other code point below U+0080 untouched; seven characters that `str.lower`/`upper`/`casefold`
change and this fold must not; a parse-tree test refusing `.lower()`, `.casefold()`,
`.upper()` and `re.IGNORECASE` anywhere in `security/secrets.py`; a per-pattern test refusing
`\s`, `\b`, `\w`, `\d`, `\y`, `(?i)`, `[[:` and any uppercase letter; character-for-character
pattern equality against the migration; all four ASCII case variants of six markers in two
separators and of both authorization schemes; an 86-entry cross-language corpus compared for
the shape *name*, not merely the verdict; case variation combined with each of the 29
whitespace code points; case-varied markers refused through raw `append_audit_event` as both
keys and values; and non-echo assertions over the whole `__cause__`/`__context__` graph.

**The limitation this buys, stated plainly.** A Unicode **homoglyph** of a marker is now
recognised by *neither* implementation — U+017F + `ecret=x` passes both, where before it was
caught by one. That is the honest cost of an ASCII fold and the right trade: a Unicode fold
cannot be reproduced by `translate()`, so keeping it means the layer a caller can walk around
is stricter than the layer that actually holds, which reads as protection and is not. The
denylist is **defense in depth against the obvious mistake** — a credential pasted where a
reference belongs. It does not claim to detect a semantic secret and does not claim to
survive a homoglyph attack; the data-flow proof is Milestone 5's. Both homoglyphs sit in the
**accepted** corpus, so the limitation is a test somebody has to change on purpose rather
than a sentence somebody can forget.

### Not implemented in M2.3 — deliberately

No signup, login, customer accounts, memberships, invitations or portal UI; no product API
credential CRUD and no browser sessions; no HTTP endpoints and no API framework; no jobs,
quotes, billing, lifecycle state machines or S3; no outbox dispatcher, SQS, AWS
infrastructure, Secrets Manager or KMS adapters; no provider credentials or provider
execution; no operator-agent code; no Rust or C++. Those are M2.4, M3 and later
milestones. v0 is untouched.

(M2.4 has since added the lifecycle state machines. Everything else in that list is still
not built.)

### What M2.3 does not claim

**It does not protect against a compromised migration-owner credential.** That role owns
the functions and the policies and can redefine both. `db/principal.py` refuses to let a
runtime connection be, or reach, that role, and `test_ownership_boundary.py` asserts it
across the database, the schema, every relation, every function and every type — which is
the boundary, not an absence of one.

**Authenticated work — including every authenticated *read* — is writable-primary-only, and
that is a real limitation rather than an oversight.** Acquiring a context writes one row of
protected transaction state, so an authenticated transaction cannot run on a standby or
inside a read-only transaction — not even a purely read-only one. Every entry path refuses
before it touches the context relation, through a preflight that names nothing in the
schema; the database's own guard is the first statement of both entry functions, for
callers who write the SQL themselves; both produce `WritablePrimaryRequiredError`, naming
which of the two situations it was. **Read-replica routing is Milestone 8 work.** The
refusals are tested on a primary, and the recovery branch by handing the classifier a
replica's answer. **No live standby has been tested and none is claimed.**

**It does not claim a credential cannot leak in transit.** The raw credential travels as a
bound parameter and is hashed in the database; psycopg sends parameters out of line, so it
does not appear in the query text or in `pg_stat_activity`. A server configured to log
parameters would log it, exactly as it would a password. That is a deployment property and
Milestone 8 owns it.

**It does not implement credential lifecycle.** `register_auth_binding` and
`revoke_auth_binding` are the minimal protected persistence foundation M3 builds on. No
listing, no last-use tracking, no rotation workflow, no endpoints, no memberships, no
sessions, no account model.

**It does not audit authentication.** A failed bind has no tenant to scope a row to and
aborts the transaction that would have written one; a successful bind happens per request,
and recording it would make the trail an access log with the write volume of the traffic.
Credential registration and revocation are audited. Authentication failure belongs in the
application log, which is Milestone 8's.

**It does not establish target invariant 3.** Payload bytes not entering the API process or
PostgreSQL is still Milestone 5's presigned S3 path. The metadata bounds and the
secret-shape rules are defense in depth and prove nothing semantic.

**It closes the database and GUC half of `AUTH-BOUND-TENANT-CONTEXT` and not the identity
half.** Arbitrary runtime SQL can no longer select a tenant without possessing a valid
tenant-bound credential; completion cases 1 to 4 are met and tested adversarially. The
fifth — an authenticated user with no membership in a workspace — is a different question
with no users and no memberships to ask it of, and is tracked separately as
`AUTH-MEMBERSHIP-BOUND-IDENTITY`. **Customer-facing deployment remains blocked** until
Milestone 3 supplies identity, membership and credential lifecycle.

**It is not VERIFIED LIVE.** Implemented and tested on a locally provisioned PostgreSQL 16
server, in a database created and destroyed by the run. No artifact under `docs/evidence/`
captures it, nothing is deployed, and the test count is not deployment proof.

---

## CURRENT — Milestone 2.4 persisted, race-safe lifecycle state machines — **merged at `4511f7d` (PR #7)**

The fourth and last declared slice of Milestone 2, implementation commit `d91e4f2`, status
commit `290f715`, **merged to `main` at `4511f7d` through PR #7** after three independent
review passes whose six, five and two findings are all corrected. Implemented and tested.
Not deployed, and **not VERIFIED LIVE** — no evidence artifact has been captured for this
slice; merging is not evidence.

Everything M2.1, M2.2 and M2.3 established is preserved and re-run unchanged: forced
row-level security, the pinned schema, the verified runtime principal, separated credentials,
connection and identity-map hardening, disposable-database safety, idempotent mutations, the
transactional outbox, the authenticated context, the closed permission catalogue, the audit
trail, the secrets model, and the frozen-v0 boundary. One Milestone 2.2 primitive was
**narrowed** — a latent redirection defect in its generated method forwarders, found while
correcting this milestone's review findings — and the three framework tables gained a derived
lifecycle tag and a reserved operation namespace, neither of which changes anything about a
non-lifecycle row. Both are recorded below.

What this adds is a **lifecycle kernel**: the smallest thing that can say *this row is in
this state, it got there by a declared move, and two callers cannot both move it*. It carries
no domain — there is no job here, no window offer, no attempt and no lease — and it registers
**no machine**.

| Component | Behaviour |
| --- | --- |
| `control_plane/db/migrations/versions/0004_lifecycle_state_machines.py` | Hand-written, `down_revision = 0003`, reversible. Six tables, twenty-three functions, sixteen triggers and five policies; plus two derived columns on each of the **three** framework tables (`idempotency_records`, `outbox_events`, `audit_events`), a reserved-namespace check constraint on two of them, one composite unique key on `outbox_events`, and all three `SELECT` policies dropped and rewritten (dropped rather than added beside, because two policies for one command combine with `OR` and the weaker one would still have decided). Role-agnostic (`TO PUBLIC`); grants stay in `db/roles.py`. Registers **no machine**: the job lifecycle (target architecture §5.1) and the window-offer machine (§12.1) are Milestone 5 and 6 definitions and land with the domain tables they describe. The revision id is 29 characters because `alembic_version.version_num` is `varchar(32)` — the intended `0004_lifecycle_state_machine_foundation` is 39 and failed **after** applying its DDL. |
| `firmbatch.lifecycle_machines` / `lifecycle_states` / `lifecycle_transition_edges` | One immutable graph per `(machine_key, version)`. **Global** rather than tenant-owned — a machine version is one graph for every tenant, in the sense target architecture §3.1 uses for the certification registry — and **protected**: no runtime or provisioning role holds any privilege. **Draft, then published**: `published_at` is NULL until `firmbatch.publish_lifecycle_machine()` sets it as the last statement of registration, and *every* consumer requires it — so a partial graph has no scope, no initial state and no edges as far as anything that uses one is concerned. Once published the definition is sealed in every direction: no state or edge may be inserted, none may be updated or deleted, no machine row may be deleted, and a machine row's only legal update is the one publication it already had. Exactly one initial state is bounded above by a partial unique index and required below at publication; no outgoing edge from a terminal state is a `BEFORE INSERT` trigger *and* a whole-graph check at publication; every endpoint is a composite foreign key. |
| `firmbatch.lifecycle_instances` | Tenant-owned, one pinned machine version, one current state, one monotonic revision starting at zero. A `BEFORE INSERT` trigger writes the initial state, revision zero and both timestamps; a `BEFORE UPDATE` trigger requires `(old, new)` to be a declared edge, the source not to be terminal, the revision to advance by exactly one, and the id, tenant, machine and creation time not to change. Composite foreign key to the declared state set. `SELECT` for the application role and nothing else. |
| `firmbatch.lifecycle_transitions` | Append-only history: `SELECT` and `INSERT` policies and no others, so `UPDATE` and `DELETE` reach no row for any role including the owner under `FORCE`. Composite foreign key to `(id, tenant_id, machine_key, machine_version)` of the instance, so neither a cross-tenant nor a cross-machine reference is expressible; and a composite foreign key to the **edge** table, so a move the machine does not declare cannot be recorded as having been taken. `UNIQUE (tenant_id, lifecycle_instance_id, to_revision)`. Actor from the authenticated context, `occurred_at` from a `BEFORE INSERT` trigger. |
| `firmbatch.transition_lifecycle_instance(...)` | The one move, and **every artifact it owes**. Requires `mutation:execute` and the machine's transition capability, both derived and checked inside the database. Resolves the instance **inside the authenticated tenant**, compares **both** the expected state and the expected revision before asking the graph anything, confirms the edge, performs **one conditional `UPDATE`** whose predicate carries tenant, instance, machine version, expected state and expected revision, then writes exactly one history row, one audit event, the idempotency claim when the caller asked for one, and one outbox intent linked to it. No tenant, actor, principal, binding, timestamp, scope or claim-identifier parameter exists. |
| `firmbatch.create_lifecycle_instance(...)` | Takes a machine key and version and nothing else, and only of a **published** machine. The tenant is the authenticated one; the starting state is the machine's. Requires `mutation:execute` as well as the machine's create capability, and writes one audit event **and one outbox intent** (`<machine>.created`), so "no lifecycle state change without every artifact" has no exception. Returns the id, the initial state and the event id, because a caller holding only the create capability cannot read any of them back. |
| The publication boundary (`lifecycle_machines_before_insert` / `_before_update`) | **Every publication rule, on the one place a row's publication column can change.** A machine is born a draft — an `INSERT` carrying `published_at` is refused, because the validation is attached to the update that publishes and a row that arrived published would never have met it. The `BEFORE UPDATE` trigger then normalises the instant to the server's clock, locks the machine row, requires the machine, every state and every edge to carry **this transaction's** `xmin`, and checks exactly one initial state, declared endpoints, no edge out of a terminal state, and eligible scopes. So a hand-written `UPDATE` runs exactly what `firmbatch.publish_lifecycle_machine()` runs — that function is now a lock, two better error messages and the statement. |
| The publication lock | One lockable object: the machine row. Publication takes `FOR UPDATE` on it before inspecting any child; every state and edge insert takes the same lock and *then* re-reads the publication column from the row the lock hands back. Reading that column without the lock was the defect: an edge could commit between a publication's read and its decision, leaving a published machine carrying an edge nothing validated. An edge locks the **machine**, not the states it names, because publication takes no lock on a state row. `UPDATE` and `DELETE` on a state or an edge are refused unconditionally, so neither can race at all — which is why "lock both parents when a row moves between them" has nothing to implement here. |
| `firmbatch.lifecycle_required_scope(...)` | The `SECURITY DEFINER` reader every policy on both tenant-owned tables calls. The required capability is a property of the **machine version**, stored where the runtime cannot write it; a caller never states one. Granted to the application role because a policy is evaluated with the querying role's privileges. |
| `control_plane/db/lifecycle.py` | The Python side, and it **appends nothing and decides nothing about a claim**. `LifecycleDefinition` + `validated_lifecycle_definition` + `register_lifecycle_definition` (owner-run, takes a `Connection`, refuses an AUTOCOMMIT connection, publishes as its last statement, outside Alembic like `db/roles.py`); `create_lifecycle_instance`; `transition_lifecycle_instance` (the internal form, one **unlinked** event); `execute_idempotent_lifecycle_transition` (the API form — one idempotency key, and no operation name and no fingerprint, because both are derived inside the database); `lifecycle_instance` / `lifecycle_history` reads. Every refusal names the field, the rule and the position and never the value. |
| `firmbatch.lifecycle_request_fingerprint(...)` | **The canonical request descriptor, and PostgreSQL is where it is canonical.** SHA-256 over a `jsonb` object of the authenticated tenant, the derived operation, the instance, the machine version it pins, the expected state and revision, the target state, and the validated reason and details. `jsonb` normalises object key order, collapses duplicates and renders NULL as `null`, so two spellings of one request hash alike. Python computes no lifecycle fingerprint at all, so there is no parity to prove and no second copy to drift. Executable by nobody. |
| `firmbatch.lifecycle_replay_claim(...)` | The replay, and what it rests on. Resolves the claim through `lifecycle_claim_provenance` and insists the whole chain agrees: the claim's tag, the provenance, the transition, the instance's revision, the linked event, and the stored result's own description of what happened. A claim with no verifiable transition behind it is **refused, never replayed**. Reads the framework tables as the caller sees them — row security still decides — and is executable by nobody. |
| `firmbatch.lifecycle_claim_provenance` | **What makes a replay a replay of something.** One row per claim, every column a composite foreign key into a row the transition wrote: the transition, the instance, the machine version, the from/to revisions and the outbox event. Protected the way the definition tables are — no runtime role holds any privilege on it; the lifecycle writer holds `SELECT` and column-level `INSERT` — written only by the transition entry point **executing as the lifecycle writer**, refused to every other identity **including the schema owner** by a guard that compares `current_user` with the catalogue-derived writer, and refused every `UPDATE` and `DELETE`, because a link that could be re-pointed afterwards would prove nothing. The guard additionally requires the claim it names to be a tagged lifecycle claim of the same tenant and machine, so provenance can only ever describe a lifecycle claim. Unique per transition and per event, so "this move was claimed once" is a schema property. |
| The lifecycle writer and `firmbatch.lifecycle_writer_role()` | **A fourth role, and the identity every lifecycle-derived write is checked against.** `NOLOGIN`, no credential, `NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS NOINHERIT`, a member of nothing, reachable by nobody through `SET ROLE` — not the application role, not provisioning, not the schema owner. It owns exactly the two `SECURITY DEFINER` entry points, which therefore *execute as it*, and nothing else; it holds `USAGE` on the schema, `EXECUTE` on the seventeen helpers the two bodies, their triggers and the policies they meet call, `SELECT` on the five tables the replay reads, and column-level `INSERT`/`UPDATE` on exactly the columns the bodies write. `firmbatch.lifecycle_writer_role()` reads **who the writer is** from `pg_catalog` — the owner of both entry points, provided both are definer functions, that owner is not the schema owner, and it holds none of `LOGIN`, `SUPERUSER`, `BYPASSRLS`, `CREATEROLE`, `CREATEDB`, `REPLICATION` — and answers NULL otherwise, on which every guard fails closed. No GUC, transaction variable, temporary object, token, query text or trigger depth is consulted. |
| `firmbatch.outbox_events_link_is_authorized()` | **A generic outbox writer proves its claim link before any constraint sees it.** A `BEFORE INSERT` row trigger, `SECURITY INVOKER`, so it runs before the unique index, the `ON CONFLICT` arbiter and the `AFTER`-trigger foreign key, and looks the claim up under the inserting role's own `FORCE`d row-security view. The lifecycle writer passes. Anybody else must name a claim this authenticated context may read, in the row's own tenant, untagged and outside the reserved namespace; an absent claim, a hidden one, another tenant's, one the context is not entitled to and a lifecycle claim the context *can* read are all refused with one message from one raise site (SQLSTATE `FB006`, translated to `OutboxLinkRefused`). An authorized generic claim links as before, and one that already carries its event still meets the one-event-per-claim index by name. |
| The lifecycle tag on the three framework tables | `idempotency_records`, `outbox_events` and `audit_events` carry `lifecycle_machine_key` / `lifecycle_machine_version`, written **only** by the lifecycle entry points — which execute as the dedicated lifecycle writer role that owns them — refused to every other writer, **the schema owner included**, by a trigger that compares `current_user` with `firmbatch.lifecycle_writer_role()`, unwritable by the application role at column level, with a composite foreign key to the machine and an all-or-neither check constraint. A tagged row's `SELECT` policy additionally requires the machine's declared **read** scope, so neither `mutation:execute` nor `audit:read` alone reads a machine's instance ids, states, revisions, transition ids and results out of the framework's own records. Untagged rows behave exactly as they did. |
| The reserved `lifecycle.` namespace | A claim's `operation` and an audit row's `action` start with `lifecycle.` **exactly when** the row carries a machine tag — a check constraint in both directions. Since only the lifecycle writer may write the tag, a generic Milestone 2.2 writer cannot create a row in the namespace at all: untagged it fails the constraint, tagged it fails the privilege check. That is what separates the two uniqueness domains, so a generic claim can neither collide with a lifecycle claim nor use the claim index to ask whether one exists. And because the lifecycle operation is `lifecycle.transition.<machine_key>.v<version>`, two machines never share a domain either — a key taken for a machine this context cannot read is in a namespace it never reaches. |
| `control_plane/security/authorization.py` | Two new rule kinds' worth of vocabulary: `scope_source` on `ResourceRule` (`catalogue` / `definition` / `none`), five new rules, and `LIFECYCLE_ELIGIBLE_SCOPES` — every known scope except `tenant:provision`, which cannot be placed on a credential so a machine gated on it would be unreachable rather than protected. **M2.4 adds no scope**, and there is deliberately no `lifecycle:*` wildcard. |
| `control_plane/db/roles.py` | A third `RevisionPlan`, and six new fields. `application_functions`: `lifecycle_required_scope` and `lifecycle_writer_role` are granted to the **application role only** — provisioning receives no lifecycle authority of any kind, the first asymmetry between the two runtime roles in this schema. `lifecycle_writer_functions`, `lifecycle_writer_helper_functions`, `lifecycle_writer_grants` and `lifecycle_writer_column_grants`: what the fourth role owns and holds at each revision (nothing before `0004`), installed by `install_lifecycle_writer()` — which hands the two entry points to the writer, grants it the minimum, writes the entry points' `EXECUTE` grant to the application role under `SET ROLE` to the writer (the schema owner can neither grant nor revoke on a function it does not own), and proves `lifecycle_writer_role()` answers with it. Installing needs the owner to be able to `SET ROLE` to the writer for that one call; the bootstrap's `temporary_set_membership` grants it `WITH SET TRUE, INHERIT FALSE, ADMIN FALSE` and revokes it after, and `wire_roles()` is the one function every re-wiring goes through. The ACL sanitiser's two function loops now touch only functions the schema owner owns, because the owner cannot revoke on the writer's: `db/roles.py` carries that ownership-aware body as its runtime `DO` block, and `0004` installs the same body as `firmbatch.sanitize_schema_privileges()`, calls it, and drops it on downgrade. Migration `0003` keeps its original text and has no diff against `main`. `application_column_grants`: at `0004` the application role's `INSERT` on `idempotency_records` and `outbox_events` is **column-level**, and the row's identifier is not among the columns. A caller that could name a primary key could submit one it had guessed and learn from the uniqueness conflict whether it exists; a column grant is refused at permission-check time, so an id that exists and one that does not fail identically and neither reaches an index. Each revision's protected-table list is written out rather than derived from head, because deriving it would make the `0003` plan name tables `0003` does not create. |
| `control_plane/db/idempotency.py` | **One narrowly scoped change, and it is a narrowing.** `MutationUnitOfWork` gained an explicit zero-argument `in_transaction()`, and every generated forwarder was rebuilt to close over its target name. The generated forwarders had bound that name as a *default parameter*, which made `_name` a keyword the caller could supply: `unit_of_work.add(row, _name="connection")` returned the raw `Connection` the class exists to withhold, and the same redirection reached `rollback`, `close`, `get_transaction` and every name in `_REFUSED_OPERATIONS`. That was a latent M2.2 defect rather than an M2.4 one. `_REFUSED_OPERATIONS` itself is unchanged. |
| `control_plane/db/principal.py` | Walks the same two catalogues, which now include four more protected relations and eighteen more internal functions. No special case was added: the writer is a role no runtime connection can reach, which the existing membership rule already refuses. |
| `control_plane/testing/bootstrap.py` | Creates the **fourth** per-run role (`firmbatch_test_lcw_<hex>`, `NOLOGIN`, no password) alongside the three login roles, recorded and cleaned up identically; wires roles through `wire_roles()`, which installs the writer under a temporary `SET`-only membership the administrator grants and revokes; and verifies on a fresh connection that no membership carrying `SET` or `INHERIT` survived. A failure at any step, the writer's installation included, unwinds every object. |
| `control_plane/tests/` | **1,746 pytest checks (1,745 passed, 1 skipped locally)**, up from 1,315: eight new modules — `test_lifecycle_definitions.py` (59), `test_lifecycle_persistence.py` (30), `test_lifecycle_transitions.py` (59), `test_lifecycle_concurrency.py` (27), `test_lifecycle_idempotency.py` (48), `test_lifecycle_security.py` (62), `test_outbox_linkage.py` (9) and `test_lifecycle_writer.py` (15) — plus new migration, rollback, 0003-boundary, catalogue, append-only, column-privilege, role-count and unit-of-work assertions in the existing modules. |

Design decisions are recorded in
`docs/adr/0007-persisted-race-safe-lifecycle-transitions.md`.

### What M2.4 proves

| Property | Where |
| --- | --- |
| A definition is refused unless its states are known, its initial state is one of them, its edges are unique and no edge leaves a terminal state — in Python, and again in the schema by foreign keys, a partial unique index, primary keys and a trigger. | `test_lifecycle_definitions.py::test_an_initial_state_outside_the_state_set_is_refused`, `::test_a_duplicate_edge_is_refused`, `::test_an_edge_out_of_a_terminal_state_is_refused`, `::test_the_database_refuses_a_second_initial_state`, `::test_the_database_refuses_an_edge_from_an_unknown_state`, `::test_the_database_refuses_an_edge_out_of_a_terminal_state`, `::test_the_database_refuses_a_duplicate_edge` |
| A registered version is immutable — for the schema owner too, by a row trigger — and re-registering one is refused rather than merged. | `::test_not_even_the_owner_can_revise_a_definition`, `::test_a_registered_version_cannot_be_registered_again`, `::test_a_registered_version_cannot_be_registered_again_with_a_different_graph` |
| Two versions of one machine coexist with different graphs, and an instance pinned to version 1 is unaffected by version 2. | `::test_two_versions_of_one_machine_coexist_with_different_graphs`, `test_lifecycle_persistence.py::test_two_versions_of_one_machine_start_in_their_own_graphs` |
| Cycles and self-edges are permitted; unreachable states are permitted. Stated as tests so that adding a rule is deliberate. | `::test_a_cycle_and_a_self_edge_are_both_permitted`, `::test_an_unreachable_state_is_permitted_and_says_so`, `test_lifecycle_transitions.py::test_a_self_edge_advances_only_the_revision`, `::test_a_cycle_can_be_traversed_repeatedly_with_monotonic_revisions` |
| Migration `0004` seeds **no machine**, on a fresh disposable database; the suite's own definitions are all named `test_*`. | `test_lifecycle_definitions.py::test_a_fresh_database_carries_no_lifecycle_definition`, `::test_the_suite_registered_exactly_the_test_only_machines` |
| An instance starts at revision zero in its machine's initial state, with a database-generated id and server timestamps; a direct writer cannot start one elsewhere or supply a revision. | `test_lifecycle_persistence.py::test_an_instance_starts_at_revision_zero_in_the_initial_state`, `::test_the_instance_id_is_generated_by_the_database`, `::test_an_instance_cannot_be_created_in_a_state_that_is_not_the_initial_one`, `::test_a_supplied_revision_and_timestamp_are_discarded_at_creation` |
| An instance's id, tenant, machine and version are immutable, and a revision may not skip or repeat — enforced by a trigger, so it binds the owner. | `::test_the_tenant_machine_and_identity_of_an_instance_cannot_change`, `::test_a_revision_may_not_skip_or_repeat` |
| Cross-tenant reads and writes fail closed, and moving another tenant's instance produces the **same** error an invented id does. | `::test_one_tenant_cannot_see_anothers_instance_or_history`, `::test_one_tenant_cannot_move_anothers_instance` |
| Missing context fails closed, in Python and again in the database. | `::test_without_a_context_neither_lifecycle_table_is_readable`, `::test_without_a_context_an_instance_cannot_be_created`, `::test_without_a_context_the_database_refuses_the_creation_function_too` |
| The required capability comes from the machine definition: a credential holding every workspace capability reaches none of a machine that requires another one, and a policy produces nothing rather than an error. | `::test_a_credential_without_the_machines_create_scope_cannot_create_an_instance`, `::test_a_credential_without_the_machines_read_scope_sees_no_instance`, `test_lifecycle_transitions.py::test_a_credential_without_the_machines_transition_scope_is_refused` |
| No runtime role may write either tenant-owned table directly; the history is append-only and even the owner reaches no row to change. | `test_lifecycle_persistence.py::test_the_application_role_cannot_write_either_table_directly`, `::test_the_application_role_cannot_insert_an_instance_directly`, `::test_the_history_carries_no_update_or_delete_policy_at_all`, `::test_even_the_owner_reaches_no_history_row_to_change`, plus the whole of `test_outbox_isolation.py`, which walks `APPEND_ONLY_TABLES` |
| Composite foreign keys reject a cross-tenant reference, a cross-machine reference, an undeclared edge and a duplicate revision — attempted as the owner, under a valid context, so the refusal is the constraint's rather than the policy's. | `::test_a_history_row_cannot_point_at_another_tenants_instance`, `::test_a_history_row_cannot_claim_a_different_machine_than_its_instance`, `::test_a_history_row_cannot_record_an_edge_the_machine_does_not_have`, `::test_two_history_rows_cannot_claim_the_same_revision`, `::test_a_history_rows_revision_pair_must_advance_by_one`, `::test_a_history_row_cannot_be_attributed_to_another_actor` |
| Every declared edge of the test machine can be taken, enumerated rather than sampled. | `test_lifecycle_transitions.py::test_every_declared_edge_can_be_taken` |
| One transition writes exactly one revision, one history row, one audit event and one outbox intent — counted from committed rows. | `::test_one_transition_writes_exactly_one_of_each_record` |
| An undeclared edge, an unknown state, a terminal source, a stale expected state, a stale expected revision and a future revision each change nothing. | `::test_an_undeclared_edge_changes_nothing`, `::test_a_state_the_machine_does_not_have_is_refused`, `::test_a_terminal_state_cannot_be_left`, `::test_a_stale_expected_state_changes_nothing`, `::test_a_stale_expected_revision_changes_nothing`, `::test_a_future_revision_is_refused_too` |
| A stale state, a stale revision and an unknown instance report the **same message**, so the refusal is not an existence oracle. | `::test_every_conflict_reports_the_same_thing` |
| A refused transition leaves no history row, no audit event, no outbox intent and no revision; a caller that fails afterwards loses all of them. | `::test_a_refused_transition_leaves_no_record_of_any_kind`, `::test_a_rollback_after_a_successful_transition_removes_every_effect` |
| The history records the authenticated actor and tenant, distinguishes two credentials in one tenant, and the function has no parameter for any derived column. | `::test_the_history_records_the_authenticated_actor_and_tenant`, `::test_two_credentials_in_one_tenant_are_distinguishable_in_the_history`, `::test_the_transition_function_has_no_parameter_for_any_derived_column` |
| Transition times are the server's `clock_timestamp()`, and four moves in one transaction do not share an instant. | `::test_the_transition_time_is_the_servers`, `::test_an_instances_updated_at_moves_with_it`, `::test_an_audit_event_cannot_be_dated_from_the_transactions_start` |
| Reasons and details are bounded metadata; an over-long reason, a secret-shaped reason, a `Secret` object and a denied or credential-shaped details document are all refused before the move, without repeating what was refused — and the database applies the same policy under raw SQL. | `::test_an_over_long_reason_is_refused_without_its_length`, `::test_a_secret_shaped_reason_is_refused_before_the_row`, `::test_a_secret_object_cannot_be_smuggled_into_a_reason`, `::test_unacceptable_details_are_refused_before_the_move`, `::test_the_database_applies_the_same_metadata_policy`, `::test_a_malformed_state_name_is_refused_without_being_repeated` |
| Two callers racing from one revision with **different idempotency keys** produce one move: contention is observed on `pg_stat_activity` and the test fails if it is never seen; the loser gets a conflict rather than a deadlock; the final state is the winner's; exactly one history row, audit event and outbox intent exist. | `test_lifecycle_concurrency.py::test_two_callers_from_one_revision_produce_one_move`, `::test_the_loser_gets_a_conflict_and_not_a_deadlock`, `::test_a_field_of_callers_still_produces_one_move`, `::test_the_unlinked_form_races_the_same_way` |
| The race result is stable across repeats, and nothing in `db/lifecycle.py` retries a conflict — asserted from the source. | `::test_the_race_result_is_stable_across_repeats` (×5), `::test_nothing_in_the_module_retries_a_conflict` |
| Different instances and different tenants do not contend. | `::test_concurrent_moves_of_different_instances_do_not_collide`, `::test_concurrent_callers_in_different_tenants_do_not_collide` |
| An identical retry returns the stored result and the instance does **not** move again — including once the instance has moved on, because the retry never reaches the database function. A replay appends no history, audit or outbox row. | `test_lifecycle_idempotency.py::test_an_identical_retry_returns_the_stored_result_and_moves_nothing`, `::test_a_replay_appends_no_history_audit_or_outbox_row`, `::test_a_replay_works_even_once_the_instance_has_moved_on` |
| Reusing a key for a different move, a different instance or a different revision is rejected; the same key is independent between tenants. | `::test_reusing_a_key_for_a_different_move_is_rejected`, `::test_reusing_a_key_for_a_different_instance_is_rejected`, `::test_reusing_a_key_from_a_different_revision_is_rejected`, `::test_the_same_key_is_independent_between_tenants` |
| A refused or conflicting transition leaves no claim blocking the retry, and a failure after the primitive returns rolls back all seven effects. | `::test_a_refused_transition_leaves_no_claim_blocking_the_retry`, `::test_a_conflicting_transition_leaves_no_claim`, `::test_a_failure_after_the_primitive_returns_rolls_the_whole_thing_back`, `::test_the_claim_and_the_move_commit_together` |
| Every lifecycle function is owned by the schema owner, pins a safe `search_path`, grants `EXECUTE` to no `PUBLIC`, contains no dynamic SQL, resolves nothing by a caller-supplied name, qualifies every reference, and has the security type that was decided. | `test_lifecycle_security.py::test_every_lifecycle_function_exists_and_is_owned_by_the_schema_owner`, `::test_every_lifecycle_function_pins_a_safe_search_path`, `::test_public_holds_execute_on_no_lifecycle_function`, `::test_no_lifecycle_function_builds_a_statement_or_resolves_an_object_by_name`, `::test_every_lifecycle_reference_in_every_body_is_schema_qualified`, `::test_the_security_type_of_every_lifecycle_function_is_what_was_decided` |
| The definition readers and the trigger functions are executable by **nobody**; the entry points are granted to the application role and **not** to provisioning. | `::test_the_definition_readers_and_triggers_are_executable_by_nobody`, `::test_the_lifecycle_entry_points_are_granted_to_the_application_role_only`, `::test_the_application_role_cannot_call_the_internal_readers`, `::test_the_application_role_cannot_call_the_trigger_functions`, `test_lifecycle_transitions.py::test_the_provisioning_role_holds_no_lifecycle_authority` |
| Arbitrary runtime SQL cannot enumerate machines, register one, add an edge, unmark a terminal state, name a tenant, or manufacture a capability by setting a value. | `test_lifecycle_security.py::test_a_runtime_role_cannot_discover_which_machines_exist`, `::test_a_runtime_role_cannot_register_a_machine_of_its_own`, `::test_a_runtime_role_cannot_add_an_edge_to_an_existing_machine`, `::test_a_runtime_role_cannot_unmark_a_terminal_state`, `::test_the_transition_function_cannot_be_pointed_at_another_tenant`, `::test_the_create_function_cannot_be_pointed_at_another_tenant`, `::test_setting_a_setting_named_after_a_scope_grants_nothing` |
| Knowing the required scope grants nothing, and the reader answers `NULL` — which coalesces to a refusal — for an unknown machine, version or capability. | `::test_the_required_scope_reader_answers_and_confers_nothing`, `::test_knowing_the_required_scope_does_not_grant_it` |
| A grant on a definition table, or a **column** grant on one, refuses the runtime connection at connect time; a control asserts the ordinary principal reaches neither. | `::test_the_protected_lifecycle_tables_disqualify_a_privileged_runtime_connection`, `::test_a_column_grant_on_a_definition_table_disqualifies_too`, `::test_the_ordinary_application_principal_reaches_no_lifecycle_definition` |
| Pooled connections and reused `Session` objects leak no lifecycle state, and a read-only transaction gets the deliberate writable-primary error first. | `::test_a_lifecycle_leaves_nothing_on_a_pooled_connection`, `::test_a_reused_session_does_not_serve_the_previous_tenants_instance`, `::test_an_unauthenticated_transaction_reaches_no_lifecycle_row`, `::test_a_read_only_transaction_is_refused_before_anything_lifecycle_happens` |
| No refusal carries a credential, a reason, a details document or connection material, walked over the whole `__cause__`/`__context__` graph. | `::test_a_transition_refusal_carries_no_credential_or_connection_material`, `::test_an_unexpected_database_error_does_not_repeat_the_details_document` |
| There is one Alembic head; `0004` upgrades from `0003`, downgrades to it, and re-upgrades, with role wiring valid and **exact** at each revision; unknown, missing and mixed revisions are refused. | `test_migrations.py::test_there_is_exactly_one_head`, `::test_role_provisioning_survives_a_rollback_to_0003_and_back`, `::test_role_provisioning_survives_a_rollback_to_0002_and_back`, `::test_an_unsupported_revision_is_refused_rather_than_guessed_at`, `::test_a_mixed_or_missing_revision_is_refused`, `::test_a_stamped_revision_whose_objects_are_missing_is_refused`, `::test_the_plans_name_only_objects_their_revision_has`, `::test_the_head_plan_names_exactly_the_protected_tables_the_catalogue_does` |
| The migration's duplicated constants, SQLSTATEs and conflict message match the application's; the ownership-aware ACL sanitiser is one body in `db/roles.py`, in the `0004` source and in the function the database holds, executable by nobody; and `0003`'s historical block equals that body with the ownership predicate removed and nothing else. | `::test_the_fourth_migration_mirrors_the_model_and_catalogue_constants`, `test_protected_auth_state.py::test_the_sanitiser_is_the_same_statement_everywhere`, `::test_both_sanitisers_remove_a_column_only_acl` |
| A database taken from head down to `0003` is catalogue-for-catalogue identical to one migrated freshly from `base` to `0003` — columns, constraints, indexes, row security, relation and column ACLs, functions with their bodies, owners and ACLs, policies, triggers, types, the schema ACL — with no sanitiser object, no writer-owned function and no writer grant; `0003`'s own sanitiser block and the runtime one strip the same state; and the direct `0003 -> 0004` upgrade, re-wired, reproduces the bootstrap's writer inventory. | `test_migrations.py::test_the_0003_boundary_matches_a_fresh_0003_installation` |
| A replay is backed by a verifiable transition: a fabricated generic claim carrying a plausible lifecycle result replays nothing, and neither does a tagged claim with missing or mismatched provenance. Provenance cannot be written by the application role, cannot be revised or deleted even by the owner, and cannot describe two claims for one transition. | `test_lifecycle_idempotency.py::test_a_fabricated_generic_claim_and_event_never_replay_as_a_transition`, `::test_a_fabricated_generic_claim_cannot_stop_a_real_move_either`, `::test_a_replay_requires_its_provenance_and_refuses_without_it`, `::test_a_replay_refuses_provenance_that_points_at_another_instances_transition`, `::test_two_claims_cannot_stand_for_one_transition`, `::test_provenance_cannot_be_written_or_revised_even_by_the_owner`, `::test_the_application_role_cannot_insert_provenance_at_all`, `::test_one_claimed_transition_writes_exactly_one_provenance_row` |
| The operation name and the request fingerprint are the database's: raw SQL cannot bind a claim to a request it did not make, the function takes no fingerprint argument at all, the digest is stable across equivalent metadata and changes with every part of the request, and Python computes none. | `::test_raw_sql_cannot_bind_a_claim_to_a_request_it_did_not_make`, `::test_the_raw_sql_call_takes_no_fingerprint_argument_at_all`, `::test_the_fingerprint_is_stable_across_equivalent_metadata` (×5: key order, whitespace, duplicate keys, number spelling, Unicode escapes), `::test_every_part_of_the_request_changes_the_fingerprint` (×11), `::test_a_null_reason_is_a_value_and_not_an_omission`, `::test_python_computes_no_lifecycle_fingerprint`, `::test_the_idempotent_form_takes_no_operation_or_fingerprint_argument` |
| `audit:read` alone reveals no lifecycle audit row, no resource identifier and no details — enforced by the policy rather than by the reader; generic audit reading is unchanged; a `lifecycle.` action cannot be written through the generic append; and there is exactly one `SELECT` policy on the table. | `test_lifecycle_security.py::test_a_credential_without_the_machines_read_scope_sees_no_lifecycle_audit_row`, `::test_the_audit_row_is_hidden_by_the_policy_and_not_by_the_reader`, `::test_generic_audit_reading_is_exactly_what_it_was`, `::test_the_generic_append_cannot_write_an_untagged_lifecycle_action`, `::test_the_audit_read_policy_was_replaced_and_not_added_beside`, `::test_no_runtime_role_can_execute_the_lifecycle_audit_append` |
| Publication is a boundary: a pre-published `INSERT` is refused, a direct `UPDATE` runs the same whole-graph validation the function runs, the instant is the server's, and a graph assembled across transactions cannot be published by either path. | `test_lifecycle_definitions.py::test_a_machine_cannot_be_inserted_already_published`, `::test_a_direct_update_is_refused_by_the_same_whole_graph_check_the_function_uses`, `::test_a_direct_update_publishes_a_complete_graph_assembled_in_one_transaction`, `::test_a_direct_update_cannot_publish_a_graph_assembled_across_transactions`, `::test_the_publication_instant_is_the_servers_and_not_the_callers` |
| Publication and every child mutation serialise on the machine row: a state and an edge insert each block on the lock a publication holds, a publication waits for an in-flight child and then refuses it, a child that waited on a published machine is refused, five children and a publication together do not deadlock, and state/edge `UPDATE` and `DELETE` cannot race because they are refused outright. | `test_lifecycle_concurrency.py::test_a_child_insert_blocks_on_the_lock_a_publication_holds` (×2), `::test_a_publication_waits_for_an_in_flight_child_insert`, `::test_a_child_that_waited_on_a_published_machine_is_refused`, `::test_a_publication_and_a_child_insert_have_no_reachable_interleaving`, `::test_concurrent_child_inserts_and_a_publication_attempt_do_not_deadlock`, `test_lifecycle_definitions.py::test_a_definition_row_can_never_be_updated_or_deleted_so_it_cannot_race`, `::test_publication_takes_the_machine_row_lock_before_it_looks_at_the_graph`, `::test_an_edge_insert_fires_the_publication_trigger_before_the_terminal_check` |
| A chosen framework identifier is refused identically whether the row exists or not; the ordinary identifier-free insert still works; the `lifecycle.` namespace is closed to generic writers; a generic and a lifecycle claim may share one textual key; a key hidden behind a machine this context cannot read does not collide; and a key reused within an authorized machine still conflicts. | `test_lifecycle_security.py::test_an_existing_and_an_absent_chosen_identifier_fail_identically` (×2), `::test_the_ordinary_insert_without_an_identifier_still_works` (×2), `::test_a_key_hidden_behind_another_machine_does_not_collide_at_all`, `::test_a_key_taken_within_one_authorized_machine_still_conflicts`, `test_lifecycle_idempotency.py::test_a_generic_writer_cannot_create_a_claim_in_the_reserved_namespace`, `::test_a_generic_claim_and_a_lifecycle_claim_may_share_a_textual_key`, `test_outbox_isolation.py::test_the_application_role_may_write_exactly_the_columns_it_needs` |
| A generic outbox link to a hidden lifecycle claim and to an absent UUID are refused **identically**, before the foreign key and the one-event-per-claim index, in the plain and the `ON CONFLICT` forms and through the Python primitive; an authorized generic claim links; one already linked meets the established conflict by name; a lifecycle claim the caller can read is still refused, identically to an absent one; cross-tenant and wrong-identity links fail like absent claims; and the lifecycle boundary still links its own event atomically. The guard is a `BEFORE INSERT` row trigger run as the invoker. | `test_outbox_linkage.py::test_a_hidden_lifecycle_claim_and_an_absent_uuid_are_refused_identically`, `::test_the_on_conflict_form_is_refused_identically_too`, `::test_an_authorized_generic_claim_can_be_linked`, `::test_an_authorized_generic_claim_already_linked_conflicts_as_before`, `::test_a_generic_writer_cannot_link_a_lifecycle_claim_even_one_it_can_read`, `::test_cross_tenant_and_wrong_identity_links_fail_like_absent_claims`, `::test_a_lifecycle_transition_still_links_its_event_atomically`, `::test_the_link_guard_is_a_before_insert_row_trigger_run_as_the_invoker`, `::test_an_absent_link_never_reaches_the_foreign_key`; and the two rewritten constraint assertions `test_outbox_isolation.py::test_an_event_cannot_be_attached_to_another_tenants_claim`, `::test_tenant_a_cannot_append_into_tenant_b` |
| A fully valid provenance row is refused to the schema owner on identity and accepted from the lifecycle writer; the two runtime roles are refused by the privilege system; an unrelated owner-owned `SECURITY DEFINER` function is refused, called by the owner and by the application; no role can `SET ROLE` to the writer and no membership path reaches it; the writer is `NOLOGIN`, `NOBYPASSRLS` and carries no privileged attribute; the application role moves an instance through the genuine entry point and replays through the writer's provenance; a genuine transition writes exactly one claim, one event, one audit row, one history row and one provenance row; direct owner-tagged claim, event and audit construction is refused and a writer-constructed tagged claim without provenance never replays; downgrade leaves the writer owning and holding nothing (no `pg_shdepend` row), reconciliation at `0003` is a verified no-op, re-upgrade restores the identical inventory, and `DROP ROLE` succeeds; a failed installation leaks no role; the writer's ownership and grant matrix equals the plan exactly; the generic writer holds none of the writer's helpers; and replacing one entry point with an owner-owned stub makes the identity NULL and closes every guard. | `test_lifecycle_writer.py::test_a_valid_provenance_row_is_refused_to_the_schema_owner`, `::test_the_runtime_roles_are_refused_provenance_by_the_privilege_system` (×2), `::test_an_unrelated_owner_definer_function_is_refused_too`, `::test_no_role_can_set_role_to_the_writer`, `::test_no_membership_path_reaches_the_writer`, `::test_the_writer_is_nologin_nobypassrls_and_carries_no_privileged_attribute`, `::test_the_application_role_moves_an_instance_through_the_genuine_entry_point`, `::test_a_genuine_transition_writes_exactly_one_claim_event_audit_history_and_provenance_row`, `::test_direct_owner_tagged_construction_is_refused_and_cannot_become_replayable`, `::test_downgrade_reconciliation_and_reupgrade_leave_no_role_or_ownership_leak`, `::test_a_failure_while_installing_the_writer_leaks_no_role`, `::test_the_writer_holds_exactly_the_planned_authority_and_nothing_else`, `::test_the_generic_writer_cannot_acquire_the_writers_authority_indirectly`, `::test_the_identity_function_fails_closed_when_an_entry_point_is_not_the_writers`; plus the rewritten `test_lifecycle_idempotency.py::test_a_replay_requires_its_provenance_and_refuses_without_it`, `::test_a_replay_refuses_provenance_that_points_at_another_instances_transition`, `::test_two_claims_cannot_stand_for_one_transition`, and the ownership, grantee, column-ACL and role-profile assertions in `test_lifecycle_security.py`, `test_protected_auth_state.py`, `test_admin_escalation.py`, `test_destructive_safety.py`, `test_bootstrap_safety.py` and `test_bootstrap_lifecycle.py` |
| Every M2.1, M2.2 and M2.3 property still holds, unchanged — with two constraint-shaped outbox assertions rewritten to the earlier refusal, and the role-count assertions raised from three to four. | The whole of the other twenty-six test modules, all with the M2.4 schema and the fourth role in place |

### Three defects this milestone's own tests found

Each was reproduced against a real server, and each changed the implementation rather than
the assertion.

| Finding | What was demonstrated | Closed by |
| --- | --- | --- |
| An ambiguous column in the transition function | `RETURNS TABLE (machine_key text, ...)` declares an `OUT` parameter, which is an ordinary plpgsql variable — so every reference to the `lifecycle_instances` column of that name was ambiguous. SQLSTATE `42702`, raised at **runtime** from inside the `UPDATE`, where it read as an unexplained database failure rather than as a naming collision | The output columns carry an `o_` prefix and are aliased back in the one statement that calls the function |
| Two conflict branches were distinguishable | "not found" and "zero rows updated" raised the same message from different lines, and psycopg renders a plpgsql exception's `CONTEXT` — which names the line number. A line number is a branch identifier, so a caller could tell "this instance is not visible to me" from "this instance is stale" | One raise site: the not-found branch sets a counter and falls through. The Python translation additionally drops the database's text for this one error and uses its own constant |
| The graph was checked before the expectation | A caller that lost a race and re-read **after** the winner committed asked "is my target an edge from the state the winner left?" — for `draft -> active` raced against itself, the answer was "no". An ordinary lost race reported an *invalid transition*, and whether it did depended on whether the loser's read landed before or after the commit | The expectation is compared to the persisted row first, and a mismatch falls through to the conflict. After that check the persisted state and the expected state are the same value, so the graph question is asked of the persisted state either way |

A fourth was caught by an existing M2.3 test rather than a new one, and is worth recording
because of *when* it failed: the intended revision id
`0004_lifecycle_state_machine_foundation` is 39 characters and
`alembic_version.version_num` is `varchar(32)`, so the migration applied its whole schema and
**then** failed at the stamp. `test_every_revision_fits_the_version_column` exists for
exactly that and now covers the fourth revision too.

### The M2.4 review correction pass — six findings, all closed

An independent review of the first M2.4 implementation found six issues. Each was
**reproduced against a real server before being fixed**, each was fixed at the root rather
than asserted away, and two of the reproductions changed what the fix had to be.

| # | Finding | What was demonstrated | Closed by |
| --- | --- | --- | --- |
| 1 | A transition could commit without an outbox event | The database function wrote the state change, the history row and the audit event; *Python* appended the outbox intent afterwards. An application role executing arbitrary SQL — which is exactly what the `EXECUTE` grant permits — could call the function and simply not append one, committing a lifecycle move that announced nothing. `mutation:execute` was likewise a Python-side check only | The function writes **all four artifacts, and the idempotency claim**, and neither Python entry point appends anything. `mutation:execute` and the machine's transition scope are both checked inside the function. `create_lifecycle_instance` also writes an outbox intent (`<machine>.created`) and also requires `mutation:execute`, so the rule has no exception. There is no lower-level state-changing function for the application role to reach: every one of the eleven internal functions is executable by nobody. Two regressions cover it — one calling the function over raw SQL, one catching the database's refusal in Python |
| 2 | Replay and framework records bypassed machine-specific authorization | `mutation:execute` alone read a claim's `result` and an outbox event's `attributes` — which carry the instance id, the states and the revisions — for a machine the credential had no capability for. The idempotent replay path re-authorized nothing | `idempotency_records` and `outbox_events` carry `lifecycle_machine_key` / `lifecycle_machine_version`, written **only** by the two owner-run entry points and refused to every other writer by a trigger; the `SELECT` policy on a tagged row additionally requires the machine's declared read scope. Replay therefore reauthorizes **by construction**: the recovery re-reads the claim under the caller's own policies, so a claim it may not read is a claim it cannot be handed. Untagged rows keep M2.2's behaviour exactly. Tested with two credentials in one tenant, plus column-level and reachable-role privilege checks |
| 3 | Concurrent identical requests failed instead of replaying | A retry that arrived while the original was still in flight lost the compare-and-swap and got a `LifecycleConflict`, so a client that had retried on a timeout could not tell "you already did this" from "somebody else moved it" | Both ways of losing — the claim index and the instance row lock — roll a savepoint back and re-read the claim for the exact `(operation, key)`: identical fingerprint replays the winner's result, different fingerprint is the existing conflicting-reuse error, **no readable claim keeps the refusal**. That last branch is what stops a stale, cross-tenant or wrong-identity conflict being laundered into a replay. Four real-concurrency tests, and a source assertion that nothing retries the move |
| 4 | Definitions had no atomic publication or sealing | Registration made the machine, then the states, then the edges visible one statement at a time, so a concurrent reader could resolve a **partial graph** and a registration that failed at its fourth statement had already been readable. Nothing stopped a definition being assembled across transactions, or under `AUTOCOMMIT`, and a published version could still gain rows | `published_at`, set by `publish_lifecycle_machine()` as registration's last statement, and required by *every* consumer — so a draft has no scope, no initial state and no edges. Publication requires every row to carry **this transaction's** `xmin` (which is what refuses `AUTOCOMMIT`, and refuses more besides), then checks exactly one initial state, declared endpoints, no edge out of a terminal state, and eligible scopes. Afterwards the definition is sealed in every direction, including for owner DML: no insert, no update, no delete, no unpublishing, no metadata change. `0004` still seeds no machine |
| 5 | Graph diagnostics ran before the revision was validated | Comparing only the **state** first left a caller holding a stale *revision* — whose state had come back around a cycle — being told its instance was terminal or its edge invalid: a diagnosis about the current row, given to a caller whose request was merely out of date | **Both** the expected state and the expected revision are compared against the tenant-visible row before any graph question. A missing, cross-tenant, wrong-state or wrong-revision request all receive the same non-oracular conflict, and the conditional `UPDATE` remains the concurrency winner check |
| 6 | `MutationUnitOfWork.in_transaction` exposed caller-selected `Session` operations | The generated forwarders bound their target name as a **default parameter**, so `_name` was a keyword the caller could supply: `unit_of_work.add(row, _name="connection")` returned the raw `Connection` the class exists to withhold, and the same redirection reached `rollback`, `close`, `get_transaction` and every name in `_REFUSED_OPERATIONS`. A latent M2.2 defect, not an M2.4 one | An explicit zero-argument `in_transaction()` returning `bool(...)`, and every remaining forwarder rebuilt to **close over** its name, so `_name`, a positional argument, or any other keyword is a `TypeError`. Audited: no public surface returns a `Session` or `Connection`, and none invokes `commit`, `rollback`, `close`, `execute` or an arbitrary method. Regressions for `_name="connection"`, `_name="get_transaction"`, `_name="rollback"` and their positional equivalents |

**Two things the corrections themselves established, both recorded rather than papered over.**
Moving an instance now requires the machine's **read** capability as well as its transition
capability — the function resolves the instance through the same policy a reader uses, so a
transition-only credential cannot move what it cannot see. That is the correct reading of the
capability model rather than a regression, and it is asserted by name. And a caller that
catches the database's refusal in Python does **not** get to keep a partial transaction: the
`RAISE` aborts everything back to the last savepoint, so the artifact count is all-or-nothing
and the revision is unchanged — which is what the F1 regression measures.

**What the correction pass added to the suite.** 128 further checks, taking `control_plane/`
from 1,512 collected to 1,640: publication, sealing, `AUTOCOMMIT` and cross-transaction
`xmin` refusals and a permanently unpublished machine; raw-SQL and caught-exception
all-or-nothing regressions; two-credential framework-record authorization with column-ACL and
reachable-role checks; four real-PostgreSQL identical-request concurrency cases; the
revision-before-graph ordering; the forwarder redirection grid; and a migration ladder that
round-trips the rewritten framework read policies from `0001` through `0004` and back.

### The second M2.4 review correction pass — five findings, all closed

A second independent review of the corrected implementation found five more, and four of the
five were **defects introduced or left standing by the first correction pass** rather than by
the original milestone. Each was reproduced against a real server before being fixed.

| # | Finding | What was demonstrated | Closed by |
| --- | --- | --- | --- |
| 1 | A generic Milestone 2.2 record could forge a lifecycle replay | The machine tag added by the first pass decides *who may read* a framework row. It says nothing about *what the row stands for* — so a claim carrying a plausible lifecycle `result` would have replayed as a transition that may never have happened, and an untagged generic claim under the same key was in the same uniqueness domain to begin with | A protected provenance relation, `firmbatch.lifecycle_claim_provenance`: one row per claim, every column a composite foreign key into a row the transition wrote — the transition, the instance, the machine version, the from/to revisions, the outbox event. No role holds any privilege on it; it is written only by the transition entry point; a trigger refuses every `UPDATE` and `DELETE` including the owner's. A replay resolves the **whole chain** and additionally requires that the instance reached the revision the transition produced and that the stored result describes that transition. A claim without that chain is refused, never replayed. Regressions: the reviewer's fabricated generic claim-and-event, a tagged claim with no provenance, provenance pointing at another instance's transition, two claims for one transition, and direct-SQL provenance insertion from the application role and from the owner |
| 2 | Caller-controlled fingerprints could bind a claim to the wrong request | The fingerprint was computed in Python and passed into the database, so it was a caller-chosen value in the one place a caller must not choose one: move instance A while storing the fingerprint of a request about B, and the next genuine request for B replays A's result | Both the operation name and the fingerprint are **derived inside the database**. The operation is `lifecycle.transition.<machine_key>.v<version>`, from the machine the *instance* pins; the fingerprint is SHA-256 over a `jsonb` descriptor of the tenant, that operation, the instance, the machine version, the expectation, the target and the validated reason and details. PostgreSQL is the only implementation — Python computes no lifecycle fingerprint at all — so there is no parity to prove. The whole of lifecycle idempotency moved inside the entry point with them: the replay lookup, and the lost-race recovery, which is now a plpgsql subtransaction rather than a Python savepoint. The A/B scenario is a regression, alongside determinism tests over key order, whitespace, duplicate keys, number spelling, Unicode escapes and NULL |
| 3 | Lifecycle audit events bypassed machine read authorization | An audit row for a lifecycle action carries the instance id in `resource_id` and the machine, the states, the revisions and the transition id in `details`. `audit:read` alone read the whole trajectory of a machine the credential holds no capability for — the same defect the first pass fixed on the two other framework tables, one table short | `audit_events` gained the same derived tag and the same replaced `SELECT` policy: `audit:read` **and** the machine's declared read scope. The `lifecycle.` action namespace is reserved, so the generic `append_audit_event` cannot write an untagged row that looks like a lifecycle one; the lifecycle kernel has its own internal append, executable by nobody, which is the only writer permitted to tag. Regressions: the two-credential pair in one tenant (row and identifiers invisible), the same question asked over raw SQL, authorized reading, unchanged generic reading, exactly one `SELECT` policy on the table, and the reachable-role and function-grant checks |
| 4 | Publication validation and sealing were bypassable and racy | Two separate holes. The rules lived inside `publish_lifecycle_machine()`, and a function is a path rather than a boundary: a plain owner `UPDATE` published an arbitrary graph, and an `INSERT` carrying `published_at` produced a published machine that no validation had ever seen. And the child trigger read the publication column **without a lock**, so an edge could commit between a publication's read and its decision | Every rule moved into the `BEFORE UPDATE` trigger, plus a `BEFORE INSERT` trigger that refuses a pre-published row and a normalisation of the instant to the server's clock. One lockable object — the machine row — taken `FOR UPDATE` by publication before it inspects any child and by every state and edge insert before it reads the publication column, which it then re-reads from the row the lock returns. An edge locks the machine rather than the states it names. `UPDATE` and `DELETE` on a state or an edge are refused unconditionally, so neither can race at all. Six real-PostgreSQL race tests, every one of which fails if the block is never observed on `pg_stat_activity` |
| 5 | Hidden framework records were still write-side existence oracles | Two of them. A caller could submit a **chosen** primary key and learn from the uniqueness conflict whether a row the read policies hide really exists. And one operation name for every machine put a tenant's machines in one key space, so presenting a key already taken by a machine you cannot read failed — success versus failure was the oracle, and renaming the error would not have helped | Identifiers: the application role's `INSERT` on the two framework tables is **column-level** and the identifier is not among the columns, so naming an id that exists and naming one that does not are refused identically at permission-check time, before any index sees either. Namespaces: `lifecycle.` is reserved in the database by a check constraint tied to the owner-only tag, so a generic claim can neither collide with a lifecycle one nor probe for it; and the machine-derived operation gives each machine its own domain. Authorization on the actual requested machine happens **before** any claim is looked up. Regressions: `INSERT ... ON CONFLICT` with an existing hidden id and with an absent chosen one, asserted to produce the *same* message; a generic claim in the reserved namespace; one textual key shared by a generic and a lifecycle claim; used versus unused keys against a machine the caller cannot read; and same-machine replay and conflicting-reuse behaviour, which had to keep working |

**What the corrections themselves established.** The bad publication interleaving turns out to
be **unreachable** rather than merely refused, while the one-transaction rule stands: a machine
created in an uncommitted transaction is invisible to any other connection, so a concurrent
child cannot name it; and a machine that *is* committed cannot be published, because its rows
carry another transaction's id. The lock is what makes that true for the window where the two
rules hand over, and the tests say which is doing what rather than claiming the lock alone.

**And one property was strengthened rather than preserved.** The first pass turned "a key
claimed by a machine you cannot read" into an authorization refusal that disclosed nothing.
The second removes the situation: the key is not in a namespace that context can reach, so the
request simply succeeds — which is what "a hidden claim must not produce *already claimed*
while an unused key succeeds" asks for. The test that asserted the old refusal was replaced by
one asserting the used key and an unused key behave identically.

**What the correction pass added to the suite.** 81 further checks, taking `control_plane/`
from 1,640 collected to 1,721.

### The third M2.4 review correction pass — two findings, all closed

A third independent review of the twice-corrected implementation found the two findings
below. Both were **reproduced against a real server before being fixed** (the ownership
semantics the second one rests on were measured on a disposable database first: hand-over
needs a `SET` membership plus `CREATE` on the schema; the schema owner may drop but not
revoke on a function another role owns), both are corrected at the root, and neither
correction changed any generic Milestone 2.2 behaviour except the two constraint-shaped
refusals named in the table.

| # | Finding | What was demonstrated | Closed by |
| --- | --- | --- | --- |
| 1 | Hidden lifecycle claims were discoverable through outbox linkage | `idempotency_record_id` is a column the application role may name, and a link was left to the constraints: a hidden lifecycle claim's id produced a uniqueness violation on the one-event-per-claim index, an absent id a foreign-key violation, and with `INSERT ... ON CONFLICT DO NOTHING` the hidden id simply *succeeded* — for rows the read policies hide, because the foreign key is checked with row security bypassed | `firmbatch.outbox_events_link_is_authorized()`, a `BEFORE INSERT` row trigger, `SECURITY INVOKER`, that runs before the unique index, the `ON CONFLICT` arbiter and the `AFTER`-trigger foreign key. For anybody but the lifecycle writer it requires the claim to be visible under the inserting role's own row-security view, in the row's and the context's tenant, untagged and outside the reserved namespace — and refuses everything else with one message from one raise site (SQLSTATE `FB006`, `OutboxLinkRefused` in Python). Untagged stands in for unprovenanced because the provenance guard refuses a row for an untagged claim. No error is rewritten; the check is an authorization decision made before either constraint. Nine regressions: hidden versus absent identically, the same through `ON CONFLICT` and through the Python primitive, authorized linkage, the established conflict for an already-linked claim, a readable lifecycle claim still refused, cross-tenant and wrong-identity links failing like absent claims, the boundary linking atomically, and the trigger's shape from the catalogue |
| 2 | Schema-owner identity did not prove lifecycle provenance origin | The tag guard and the provenance guard checked `current_user = schema owner`, which the definer entry points satisfied — and so did the schema owner's own `INSERT` and any other definer function the owner owned. Direct owner SQL inserted a tagged claim, a tagged event and a provenance row matching an earlier transition, and the replay accepted the forged association | A **fourth role, the lifecycle writer**: `NOLOGIN`, no credential, `NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS NOINHERIT`, a member of nothing, reachable by nobody. It owns exactly the two `SECURITY DEFINER` entry points, so they execute as it, and holds the minimum their bodies need. `firmbatch.lifecycle_writer_role()` reads who the writer is from the catalogue — the owner of both entry points, provided it is not the schema owner and cannot log in — and every lifecycle-derived guard (the three tag guards, the provenance guard, the outbox-link guard) requires `current_user` to be it; NULL before the wiring has run or if anything about that ownership is disturbed, on which every guard fails closed. The provenance guard also requires the claim it names to be a tagged lifecycle claim. Installation is a two-party act: the administrator grants the owner a `SET`-only membership for one call and revokes it after, the owner hands the functions over and grants the writer, and the entry points' `EXECUTE` grant is written under `SET ROLE` to the writer. Downgrade reads the writer from the catalogue first and leaves it owning and holding nothing; re-upgrade and re-wiring restore the identical inventory. Fifteen regressions, listed in the property table, including the reviewer's attack from the owner and from an unrelated owner-owned definer function, the `SET ROLE` and membership walks, the exact grant matrix, the failed-install cleanup, and the fail-closed stub |

**What the corrections themselves established.** The ACL sanitiser could not stay as it was:
PostgreSQL lets only an object's owner or a grant-option holder revoke on it, so the schema
owner running `REVOKE ALL ON FUNCTION ... FROM PUBLIC` against a writer-owned entry point is
refused — measured. The sanitiser's two function loops now touch only functions the schema
owner owns, with the writer-owned entry points sanitised by the writer itself during its
installation. That ownership-aware body lives in two places: `db/roles.py` runs it as the
runtime `DO` block, and `0004` installs it as `firmbatch.sanitize_schema_privileges()`, calls
it, and drops it again on downgrade after every writer-owned function and writer grant is
gone. **Migration `0003` is untouched history** — no diff against `main` — and a test asserts
that its block equals the current body with that one predicate removed, and that a database
taken from head down to `0003` is catalogue-for-catalogue identical to one migrated freshly
to `0003`. And the caveat the previous pass recorded — that an event linked to a claim whose
UUID a caller already knew could be probed through the one-event-per-claim constraint — is
gone rather than narrowed.

**What the correction pass added to the suite.** 25 further checks, taking `control_plane/`
from 1,721 collected to 1,746: two new modules, three tests rewritten to construct their
rows as the writer, and the ownership, grantee, column-ACL and role-count assertions raised
across seven existing modules.

### Not implemented in M2.4 — deliberately

No job, quote, window-offer, attempt, shard, lease, provider or billing record, and **no
registered machine of any kind**. No accounts, memberships, sessions or portal UI; no HTTP
endpoints and no API framework; no S3 payload path; no outbox dispatcher, SQS or AWS
infrastructure; no operator-agent code; no Rust, Go or C++. No retention or deletion
operation for instances or history. Those are M3 and later milestones. v0 is untouched.

### What M2.4 does not claim

**It does not model any product lifecycle.** No machine is registered. The job lifecycle
(§5.1) and the window-offer machine (§12.1) are Milestone 5 and 6 definitions and land with
the domain tables they describe; seeding a partial graph here would put a contract nobody had
reviewed into every production database, and a registered version is immutable.

**It does not establish target invariants 4 to 10.** Fenced attempts, stale-worker refusal,
canonical results, immutable accepted quotes, spend envelopes, separate ledgers and
evidence-based cancellation are all Milestone 5 and 6 work. This kernel is the mechanism
those milestones will express *part of* their invariants with; it establishes none of them.

**It does not claim exactly-once external delivery**, unchanged from M2.2. The outbox records
durable intent, no dispatcher exists, and when one does it will deliver at least once.

**It does not claim that a trigger binds a superuser, or the schema owner's DDL.** Sealing
a published definition, the lifecycle tags, the provenance relation and the outbox link are
all enforced by row triggers, so they bind ordinary DML including the schema owner's — since
the third correction pass the owner's own `INSERT` and its own `SECURITY DEFINER` functions
are refused every lifecycle-derived write, because the guards ask for the lifecycle writer.
They do not bind a superuser, and they do not bind an owner who first runs
`ALTER TABLE ... DISABLE TRIGGER`, redefines a guard, sets
`session_replication_role = replica`, or drops a writer-owned function inside its schema
(which makes the writer unrecognised and closes every guard). Those are deliberate,
DDL-shaped acts by a role this design already trusts with the definitions themselves, and
the trusted-administrator limitation is retained on purpose. What the triggers buy is that
no accident, no ordinary statement and no ordinarily-owned function reaches either.

**It does not claim that moving an instance is possible without reading it.** The transition
function resolves the instance through the same policy a reader uses, so a credential holding
the machine's transition scope but not its read scope is refused. That is deliberate and
asserted by name; a machine that wants a write-only mover would need a different resolve, and
no milestone has asked for one.

**It does not bound what a definition means.** The kernel enforces that a graph is
well-formed. Whether `admitted -> cancelled` belongs in the job machine is a commercial
question, and registering a wrong edge would produce a perfectly valid state machine with the
wrong contract in it.

**It does not claim the request fingerprint survives a change of PostgreSQL's `jsonb` text
form.** The descriptor is canonical *within* a database — `jsonb` normalises key order and
collapses duplicates, so two spellings of one request hash alike, which is the property a
replay needs. It is not a stable identifier across implementations, and nothing compares one
across databases or persists one as an external contract. If a future PostgreSQL changed how
a `jsonb` value renders, stored claims would stop matching new requests and those retries
would be refused as conflicting reuses rather than replayed: a visible, bounded failure
rather than a wrong replay, and one worth stating before somebody finds it.

**The "no chosen identifier" caveat is closed, not narrowed.** The previous pass recorded that
an event linked to a claim whose random UUID a caller already knew could be probed through the
one-event-per-claim constraint. A generic link to a claim this context may not read — hidden,
absent, another tenant's, or a lifecycle claim's — is now refused before the foreign key and
the unique index are evaluated, with one message, including through `INSERT ... ON CONFLICT`.
No constraint on the framework tables answers a generic writer's question about a row the read
policies hide.

**One wording imprecision is known and recorded.** The bounded-metadata policy is shared
rather than copied: the transition function calls
`firmbatch.audit_require_acceptable_details`, so a raw-SQL caller whose details are refused
sees a message that says "audit details". The rule is the same rule and the supported Python
path names it correctly; only the noun is wrong, in a backstop.

**It does not protect against a compromised migration-owner credential's DDL**, unchanged
from M2.3 in kind and narrowed in reach. That role owns the trigger functions, the tables and
the definitions and can redefine all three; what it can no longer do is write a
lifecycle-derived row with ordinary SQL, because the guards ask for an identity it does not
hold and cannot become.

**It is not VERIFIED LIVE.** Implemented and tested on a locally provisioned PostgreSQL 16
server, in a database created and destroyed by the run. No artifact under `docs/evidence/`
captures it, nothing is deployed, nothing is committed, and the test count is not deployment
proof.

---

## CURRENT — Milestone 3.0 revision D.1 documentation adoption — **merged at `116b5ee` (PR #8)**

Documentation only, on `docs/rev-d-phase-0-roadmap` from `main` at `4511f7d`. It changes
no product behavior, no migration, no test, no dependency and no evidence, and it touches
no protected agent, policy, workflow or verification file. The branch first adopted
revision D; revision D.1 superseded D the same day, before anything was committed, and the
staged documentation was corrected in place to D.1. Reviewed on 2026-09-07; one
clarification was applied after review — the `AUTH-MEMBERSHIP-BOUND-IDENTITY` completion
gate's non-member and session-versus-API-credential cases in `docs/firmbatch-v1-roadmap.md`
and `docs/tasks/current.md`, with the M3.1 deliverable text aligned — and nothing else
changed.

| Document | What changed |
| --- | --- |
| `docs/firmbatch-v1-roadmap.md` | Revised M3–M8 sequence under revision D.1; Phase 0 / P / B and endpoint triggers; Milestone 2 recorded complete at `4511f7d`; the stale active `AUTH-BOUND-TENANT-CONTEXT` "raw GUC" blocker prose replaced by `AUTH-MEMBERSHIP-BOUND-IDENTITY`, with the M2.3 closure linked and its adversarial tests retained; M3.0 adoption, M3.1 identity and issuance, M3.2 customer application and M3.3 protected AWS staging (planned, not authorized); each later slice names the D.1 rule it implements; a "Remaining decisions" table with owners |
| `docs/architecture/v1-target-architecture.md` | Revision D.1 integrated under the existing section numbers; §17 invariants 1–11 byte-identical to `main`, 12 (purchase only against an admitted job, inside a bridge envelope enforced as gross accrued spend, frozen `purchase_rate` and `supplier_account`, no recomputed cost) and 13 (`provider_policy` governs execution placement only, not the payload plane, and never weakens invariant 11) appended; `[D.1]` markers where D.1 states a rule precisely; new §5.5 qualification tier; no open-rule markers; §18 revision record for rev C → D → D.1 |
| `docs/architecture/rev-d-decision-register.md` | Converted from an open-items list into the D-review/D.1-resolution register: each of D1–D10 with the review finding, the D.1 resolution, the source authority by section, and the genuinely remaining implementation choice if any; the qualification tier; the remaining-decisions table with owners |
| `docs/architecture/sources/` | The supplied rev D.1 Markdown verbatim (`architecture-v1-rev-d-1.md`, SHA-256 `44e29e07…853f3`, the current source), the rev D Markdown kept as the historical reviewed input (`architecture-v1-rev-d.md`, SHA-256 `ea09cb2e…a2a2c`), and a manifest with the hashes of both PDFs and of every companion authority reviewed (settlement canon, plan v3.4, roadmap r2_4, price register, customer brief, definitions, demand map, operator equation, both RFQs), each marked stored or hash-referenced; the snapshots' "PLANNED — nothing here is implemented" banner is the source's disclaimer about itself, explained in the manifest |
| `docs/adr/0008-phase-0-purchased-capacity-and-staged-delivery.md` | New: Phase 0 purchased capacity at revision D.1, Milestone 2 preserved, staged delivery with the M3.3 preview, the qualification tier and gross-accrual bridge accounting with the configured caps left to a human, Phase P / endpoint / Phase B deferrals, the review items resolved and the remaining choices named |
| `docs/STATE.md`, `docs/tasks/current.md`, `README.md` | Status: Milestone 2 merged; revision D.1 PLANNED; M3.1 next; one README status line |

**What this adoption does not do.** It implements nothing from revision D or D.1. It does
not verify any price, SKU, quota, throughput or cost figure in the sources or the
companions; those are the documents' figures at their capture dates. It does not fix the
bridge caps (plan v3.4's $3–5k a month and $10k total are a planning range; the configured
caps are a human's spend decision), the per-evaluation token and spend caps, the quote
expiry or any other value the authorities leave to configuration, contract or measurement.
It creates no cloud resource and authorizes no deployment, purchase, supplier contact or
customer invitation. It reclassifies no evidence: Milestone 2 stays implemented and tested,
not VERIFIED LIVE.

---

## CURRENT — Milestone 3.1 membership-bound identity, sessions and credential issuance — **implemented, tested and independently reviewed at `f92ecb9`; merged at `87159d5` (PR #9)**

Implemented on the branch from `main` at `116b5ee` (Milestone 3.0, PR #8), committed at
**`f92ecb9`** and merged to `main` at **`87159d5`** (PR #9, status commit `c841f77`); **not
deployed, and not VERIFIED LIVE**. ADR 0009 records the
design. Nothing in Milestone 2 is reopened: migrations `0001`–`0004` are unchanged —
migration `0005` is where the whole M3.1 implementation lives, merged since at `87159d5` —
`bind_authenticated_context` is unchanged, and every existing test passes unchanged except
the three named below.

**What it is.** Forward migration `0005_identity_and_membership` adds nine **protected**
tables — `accounts`, `account_passwords`, `account_tokens`, `memberships`,
`workspace_directory`, `browser_sessions`, `workspace_invitations`,
`account_idempotency_records` and the unlogged `identity_transaction_context` — with no
grant, no policy and no column privilege for any runtime role, reached only through
fifty owner-owned `SECURITY DEFINER` functions (twenty-seven application entry points,
five granted to the authenticator role alone — the trusted-issuer boundary added by the
security correction pass below — and eighteen internal helpers executable by nobody). A
browser session is a third actor kind (`session`: principal = the account, no binding) that
acquires an ordinary Milestone 2.3 tenant context through the owner-only `auth_context_begin`,
with the membership **re-derived at every bind** and revoked **structurally** by a
`BEFORE UPDATE OR DELETE` trigger on `memberships` that revokes every credential the
membership issued and unbinds every session bound through it. A workspace is a tenant at
this milestone; `create_workspace` provisions both plus the owner membership in one
function. Roles are closed (`viewer`, `member`, `admin`, `owner`); `credential:issue`,
`membership:read` and `membership:manage` are session-only permissions outside the
Milestone 2.3 catalogue; no role grants `credential:manage`, so the M2.3 minter refuses every
session. `issue_api_credential` re-reads the membership, bounds the scopes by the catalogue,
the issuable subset and the member's own permissions, and mints a fresh `fbk_` secret;
rotation is an atomic locked cutover; only the issuing member rotates, a manager revokes.
Five secret kinds (`fbs_`, `fbc_`, `fbv_`, `fbr_`, `fbi_`) share the bearer credential's
244-bit construction, are returned once, and are stored only as SHA-256 fingerprints;
`secret_shape` gains one seventh pattern and is restored to `0003`'s exact text on
downgrade. Passwords are Argon2id through `argon2-cffi`, verified in the application process
(the harvestable-hash limitation is stated in ADR 0009 decision 6). `FB010` is the one neutral
refusal, raised from one site per function. The native HTTP boundary is a Starlette
application (`control_plane/api/`) with a host-only `HttpOnly`/`Secure`/`SameSite=Strict`
cookie, `X-CSRF-Token` plus an `Origin` allow-list on every cookie mutation, credentialed CORS
from the same explicit allow-list and never a wildcard, a separate bearer boundary that
refuses cookies as the cookie boundary refuses bearer tokens, 16 KiB bounded bodies, neutral
one-field error bodies, metadata-only logging, an email-delivery interface with a test-only
capture adapter and a production adapter that raises, and no HTML.

| Path | What |
| --- | --- |
| `control_plane/db/migrations/versions/0005_identity_and_membership.py` | New forward migration after `0004`: the nine tables, two composite types, the widened actor constraints, six columns and two constraints on `auth_bindings`, the seven-shape `secret_shape`, fifty-one functions (twenty-five for the application role, eight for the authenticator, eighteen internal), four triggers, and the revised `bind_authenticated_context`; a downgrade that restores the `0004` catalogue exactly |
| `control_plane/db/models.py`, `security/authorization.py`, `db/roles.py` | Models and constants for the nine tables; nine protected resource rules; the `0005` revision plan (`M3_1_REVISION`) with the identity function inventories |
| `control_plane/db/accounts.py`, `membership.py`, `credentials.py` | The Python wrappers: signup, verification, recovery, login, sessions; workspaces, binding, memberships, invitations; issuance, rotation, revocation, listing, last use |
| `control_plane/security/passwords.py`, `permissions.py`, `secrets.py` | Argon2id policy; the closed role model and the issuable subset; the five identity secret prefixes and the appended shape |
| `control_plane/api/` | `app.py` (the boundary and thirty-two routes), `settings.py` (`FIRMBATCH_API_ALLOWED_ORIGINS`, `FIRMBATCH_API_COOKIE_SECURE`, `FIRMBATCH_API_SESSION_TTL_SECONDS`), `email.py`, `__main__.py` (loopback uvicorn, application settings only) |
| `control_plane/tests/` | Nine new modules (`test_identity_accounts`, `_membership`, `_issuance`, `_protection`, `_migration`, `_permissions`, `_concurrency`, `test_api_http`, and `_security_corrections` from the Codex pass) and `identity_helpers.py`; `test_migrations.py`, `test_audit_events.py` and `test_protected_auth_state.py` extended for the new head, the appended shape and the nine tables, and `conftest.py`, `test_configuration.py`, `test_admin_escalation.py`, `test_bootstrap_safety.py` and `test_bootstrap_lifecycle.py` extended for the authenticator role |
| `requirements-v1.txt`, `requirements-v1-dev.txt`, both lock files | `argon2-cffi==25.1.0`, `starlette==1.6.0`, `uvicorn==0.52.4` (runtime); `httpx==0.28.1` (dev); locks regenerated with `pip-compile --generate-hashes --strip-extras --no-header` in a throwaway environment |
| `docs/adr/0009-…`, `.env.example`, `README.md` | The decision record; the three API variables; one status line |

### What M3.1 proves

Against PostgreSQL 16, every check as the restricted application role and failing closed:
two unrelated tenants cannot observe or affect one another through any identity function; a
non-member's account session binds nothing and issues nothing; a revoked membership is
unbound, its credentials revoked, a stale pointer on the session row not honoured, and the
row not reinstatable even by the schema owner; an invitation for one tenant grants nothing in
another, and the wrong recipient, an expired, revoked, reused, forged or bearer-shaped
invitation are one refusal; a session secret at the credential boundary and a credential at
the session boundary are refused, the latter before the database is consulted; a credential
context reaches no identity function; the M2.3 minter and revoker refuse every session; raw
SQL as the owner's own workspace session cannot insert, update, delete or read a binding,
membership, session or context, cannot call any internal function, and cannot widen or
re-point a context; issuance is bounded by the membership as re-read, the catalogue and the
issuable subset, with the membership permissions refused as non-catalogue values; rotation
is atomic and the old secret stops in the same transaction; duplicate keyed requests produce
one workspace, one membership, one binding, one claim and one linked event, with the contention
observed on `pg_stat_activity`; concurrent owner removals leave exactly one owner and
concurrent rotations exactly one successor; membership, credential and invitation identifiers
are not oracles across tenants; no secret reaches any row, audit detail, outbox attribute,
exception chain, HTTP response, log line or error body, and every secret is present only as
its digest; the address normaliser, the role table and the password policy agree between
Python and SQL; every identity function is owner-owned, path-pinned, `PUBLIC`-revoked, of the
decided security type, free of dynamic SQL and schema-qualified, granted to exactly the
application role or to nobody; the four triggers are installed and enabled; the ACL sanitiser
strips a stray grant on the identity plane; and `0005` upgrades, downgrades to a catalogue
equal to an independent downgrade, and re-upgrades, with role wiring at every revision.

**The `AUTH-MEMBERSHIP-BOUND-IDENTITY` cases, each a named test:**

| Gate case | Test |
| --- | --- |
| 1. A verified non-member keeps its account session, can create its first workspace, and cannot bind the unauthorized workspace or obtain a credential scoped to it by any route | `test_identity_membership.py::test_gate_case_1_a_non_member_keeps_its_account_session_and_cannot_bind_the_workspace` |
| 2. Revoking a membership stops the identity acting in the workspace on the credential path's linearisation terms | `test_identity_membership.py::test_gate_case_2_revoking_a_membership_stops_the_identity_acting_in_the_workspace` |
| 3. An invitation accepted for one tenant grants nothing in another | `test_identity_membership.py::test_gate_case_3_an_invitation_accepted_for_one_tenant_grants_nothing_in_another` |
| 4. Sessions and API credentials are distinct types, never accepted at each other's boundary, never converted; issuance is an audited operation after membership and scopes are rechecked | `test_identity_issuance.py::test_gate_case_4_a_session_issues_a_credential_that_authenticates_as_its_membership_and_nothing_else` |

**Verification at implementation commit `f92ecb9`, 2026-09-09, against the attested local
PostgreSQL 16.15 cluster:** the PostgreSQL foundation suite **2,038 collected — 2,037 passed,
1 skipped** (the one skip is the pre-existing, environment-dependent REPLICATION skip) — the
latest full-suite result, a net increase of 76 over the first pass's 1,962 that is the second
pass's regression and concurrency coverage; `./scripts/verify-repository.sh` reports
**14 gates passed, 0 failed**, with **119** required files in the layout gate; `git diff
--check` is clean; the cluster carries no leaked `firmbatch_test_*` database, role or session
afterwards. **No evidence artifact was captured**; these are HISTORICAL observations at that
commit, not VERIFIED LIVE. (The figures recorded for 2026-09-07 were 1,962 collected —
1,961 passed, 1 skipped, and they are HISTORICAL to that state.)

**Three existing tests changed, each because the head moved:** `test_migrations.py` (the head
is `0005`, the ladder starts there, the protected-table chain gains a link, and the unmodelled
`identity_transaction_context` joins its sibling), `test_audit_events.py` (`0003`'s six shapes
are asserted as a strict prefix of the now-seven, with six corpus samples for the seventh),
`test_protected_auth_state.py` (the nine tables join the parametrised protected-write
refusals). No assertion was weakened.

### The M3.1 Codex security correction pass — ten findings and two gaps, all closed

A Codex security diff scan of the uncommitted M3.1 working tree raised ten findings (five
medium, five low) and two review gaps. All are corrected on the branch, with regression
tests. ADR 0009's "Security corrections" section records the changes that alter the design;
the summary here is what the code now does.

**The trusted-issuer boundary is a distinct database principal.** The pre-authentication
functions are granted to a new restricted login role, the **authenticator**, and to the
ordinary application role not at all. This pass moved five — `login_lookup`,
`open_browser_session`, `request_account_recovery`, `account_recovery_token_valid`,
`complete_account_recovery`; the second review pass below moved the three
mailbox-verification ones, so the current inventory is **eight**. Raw SQL as the application
role can no longer harvest a stored password hash, mint a session for a victim account
(findings 1/5 in the report), or request and consume a recovery secret to reset a victim's
password (finding 2). The API's signup, verification, login, recovery-request and
recovery-completion routes run on a separate authenticator engine; every other route stays
on the application engine. Password verification still runs in the process (PostgreSQL has
no Argon2), so a compromised authenticator could still skip it — that trust is now confined
to a narrow principal, and separating the process that holds its credential is M3.3's.

**The authenticator's grant is the least that reaches those eight.** `USAGE` on the schema,
`EXECUTE` on the eight pre-authentication functions, and `EXECUTE` on exactly two read-side
accessors — `auth_tenant_id`, which `db/engine.transaction()` calls to assert a transaction
inherited no context, and `auth_context`, which that invoker-rights accessor calls as the
caller. Ten functions; no table privilege and no column privilege anywhere; a member of no
role, so nothing is reachable through `SET ROLE`. It is deliberately **not** granted the
common runtime set the application and provisioning roles hold, which also carries
`bind_authenticated_context`, `register_auth_binding`, `revoke_auth_binding` and
`append_audit_event` — none of which any authenticator call path reaches.
`test_identity_protection.py` asserts this from the catalogue in four ways: the exhaustive
executable set is exactly those ten **named**, each unreachable function is named
individually, the role holds no relation privilege, and it is a member of nothing — and a
fifth test drives the pre-authentication flows end to end, so a grant narrowed too far fails
as loudly as one
left too wide.

**The canonical address maximum is enforced by the database.** `EMAIL_REGEX` bounds the
local part and each domain label but repeats labels without an upper limit, so a
255-character address matched the grammar while `EMAIL_MAX_LENGTH` is 254. `accounts`
now carries `length(email_normalized) <= 254` as its own CHECK, mirroring the bound both
`identity_normalize_email` and `db/accounts.normalize_email` already applied, so the three
layers agree and a writer reaching the table another way cannot store what the normalisers
would never produce. Proven at the lowest boundary that can answer it: the schema owner —
the one identity that can insert into this protected table — stores a 254-character address
and is refused a 255-character one by `email_normalized_length`, with both addresses
grammar-valid so only the bound separates them.

**Account recovery evicts credentials durably.** `accounts` gains a `security_epoch`;
membership-bound credentials are stamped with it at issue and rotation
(`auth_bindings.principal_epoch`); `complete_account_recovery` advances it and marks the
visible bindings revoked; and `bind_authenticated_context` — the one M2.3 function this
revision now replaces via `CREATE OR REPLACE`, restored byte-for-byte on downgrade — refuses
a membership-bound credential whose stamped epoch is behind the account's, and rechecks that
its membership is still active. A credential issued before a recovery, including one that
raced it, no longer authenticates (findings 6, and defence-in-depth for 3/4 in the report).

**Issuance and rotation share the workspace serializer.** `issue_api_credential` and
`rotate_api_credential` now take the workspace row lock before reading membership and re-read
the membership and role under it, so issuance, rotation, removal and demotion serialize on
one lock in one order; no credential survives a completed removal or demotion (findings
3/4). `change_membership_role`, `remove_membership` and `create_invitation` re-read the
**caller's own** role under the lock, so a concurrently demoted owner cannot act on cached
authority or restore itself (finding 5). (The second review pass below replaced these five
separate re-reads with one shared mechanism and extended it to the six workspace operations
this pass left reading the cached scope set.)

**Unauthenticated work is bounded.** A memory-hard admission gate in `security/passwords.py`
bounds concurrent Argon2 and returns a deterministic 503 under saturation without disclosing
account existence (findings 8/10 in the report); recovery completion rejects malformed and
non-existent tokens before hashing (finding 9); the HTTP boundary enforces its 16 KiB limit
while consuming the ASGI receive stream rather than trusting Content-Length (finding 7); and
`purge_expired_unverified_accounts` is an explicit owner-run expiry control against unbounded
unverified-account growth (finding 10). These are the application-layer floor; ingress rate
and size limits remain additive M3.3/M8 work.

**The two review gaps.** The populated-data downgrade that failed with PostgreSQL error
23514 is fixed: the `0005` downgrade reconciles `audit_events` and `lifecycle_transitions`
session-actor rows (bypassing `FORCE` row security as the owner) before it re-adds the
narrowed actor constraint, and a new test drives the populated downgrade/re-upgrade ladder
end to end. The runtime-import inventory `scripts/check-runtime-imports.py` `RUNTIME_MODULES`
now names every new M3.1 production module (`db/accounts.py`, `db/credentials.py`,
`db/membership.py`, `security/passwords.py`, `security/permissions.py`, and `api/*`), so the
import-closure gate checks that they reach no migration or test tooling and read no
privileged credential.

**Both protected inventories are extended, with the human's approval.**
`scripts/verify-repository.sh` `REQUIRED_FILES` names every new M3.1 production module and
test module — the layout gate reports **119** required files and fails if one is deleted —
and `scripts/check-runtime-imports.py` `RUNTIME_MODULES` names every new production module.
The paragraph that stood here said the layout gate had not been extended; that was true when
this pass closed and stopped being true when the human approved the change, and it is
corrected rather than left standing (second review pass, 2026-09-09).

**A note on the append-only tokens trigger.** To let the owner-run purge cascade-delete an
expired unverified account's tokens, `account_tokens_append_only` is now `BEFORE UPDATE`
rather than `BEFORE UPDATE OR DELETE`; deletion of a token remains impossible for every
runtime role by the absent grant, so no boundary is weakened.

### The second M3.1 review correction pass — six findings, all closed

A GPT-5.6 Sol review of the same uncommitted branch raised six findings. All are corrected
with regression tests; ADR 0009's "Second review correction pass" section records the four
that change the recorded design. Migrations `0001`–`0004` are untouched; `0005` was then unmerged
and was corrected in place (merged since at `87159d5`). The theme is one the first pass began and did not finish: **a
decision made once is not a decision that still holds.**

**1. A login challenge is bound to the password version it was answered against.** Argon2
verification runs in the process and takes hundreds of milliseconds; a recovery can commit in
that window, after which the old password verifies against a hash the account no longer has
and the session opens *after* `complete_account_recovery` revoked every session it could see.
`login_lookup` now reads the stored hash and `accounts.security_epoch` in one statement and
records both on the challenge; `open_browser_session` takes `SELECT … FOR UPDATE` on the
account row — which conflicts with the recovery's own `UPDATE accounts` — re-reads the epoch
under it, refuses a mismatch with the neutral refusal, and holds the lock to commit. Both
transaction orderings are driven in `test_identity_concurrency.py`: with the verification
paused and the recovery committed, the session opening is refused and no session row is left
behind; with the session opening holding the lock, the recovery provably blocks (asserted
through `pg_locks`) and then revokes the session it waited for.

**2. Mailbox verification is a mailbox proof, and its authority moved to the authenticator.**
`signup_account` and `request_email_verification` mint a verification secret and return it in
the result row; `verify_account_email` consumes one and flips the account to `active`. A role
holding all three needs no mailbox: it registers an address it does not control, reads the
secret from its own result, consumes it, and holds a verified account — which satisfies the
verified-account precondition on workspace creation and invitation acceptance. All three are
now the authenticator's and the application role holds none of them (eight pre-authentication
functions, ten with the two read-side accessors, named in the exhaustive privilege test). The
HTTP signup and verification routes run on the trusted engine. Raw SQL under the application
role can neither issue nor consume a verification token, and the supported signup →
captured-delivery → verification flow is driven end to end alongside it; the raw secret
reaches the configured email adapter and nothing else — no response body, log line, audit or
outbox attribute, exception chain, or application-role result.

**3. One membership revalidation, in the database, for every workspace operation.** Six
operations still decided from `auth_has_scope(...)`, which reads the scope set the *bind*
cached: `rename_workspace`, `revoke_invitation`, the manager-only invitation listing,
`revoke_api_credential`, the credential listing (including its manager reach) and the
credential-history route. `firmbatch.workspace_membership_authority(p_scope, p_lock)` is now
the one mechanism, and every workspace-mode function goes through it, as does the HTTP
boundary for the one disclosure it performs itself. It takes the serialisation point, re-reads
tenant, workspace, account, membership identity, both active states and the current role under
it, and requires the permission of *that* role — before any replay lookup, disclosure or
mutation, so a demoted caller cannot replay its way to a result it may no longer ask for. A
mutator locks the workspace row `FOR UPDATE`; a **reader** locks its own membership row `FOR
SHARE`, because `workspaces` is under forced row security whose `UPDATE` policy requires
`workspace:write` and PostgreSQL evaluates `UPDATE` policies for any `SELECT … FOR
SHARE`/`FOR UPDATE` — so locking the workspace would refuse a viewer a listing it is entitled
to — and because a reader's decision depends on its own authority alone. Concurrency tests
bind an admin session, commit a demotion or a removal in another transaction, and assert the
stale transaction is denied the former authority for a mutation, a manager-only listing, the
manager *reach* of the credential listing, and the audit disclosure.

**4. HTTP authentication happens before the body is interpreted.** The bounded stream read
stays first — refusing after buffering would mean the buffer had already happened — and
everything that interprets the bytes (media type, UTF-8, JSON, object shape) moved behind the
credential into `RequestBody.json()`. Absent, malformed, unknown and mixed credentials are one
`401 authentication_required` whatever the body is; previously a malformed body or an
unsupported media type produced `400`/`415` for an unauthenticated caller. The cookie is also
shape-checked before the origin and CSRF preconditions, so the three credential states are
decided at one point.

**5. A wrong CSRF token is not a missing workspace.** `_refused_bind` re-binds in account mode
to tell a refused session from an unbound one, and dropped the CSRF secret when it did — so a
forged mutation came back `412 workspace_required`, telling its sender the cookie was good.
The retry now carries the proof the request carried: an incorrect token is `401`, and a
genuinely unbound session presenting its own token still receives the `412`. `keep_current` on
`POST /v1/account/sessions/revoke-all` is a strict JSON Boolean; strings, numbers, arrays,
objects and `null` are `422 invalid_request` with no session changed, `false` revokes the
current session and clears its cookie, and `true` retains both.

**A seventh thing, found by the leak check rather than by the review.** Confirming that the
suite leaves the cluster clean turned up one or two surviving `firmbatch_test_auth_*` roles
after every full run. Four teardown call sites spell the per-run role list out by hand — in
`test_bootstrap_safety.py` and `test_bootstrap_lifecycle.py`, tests that deliberately break
the bootstrap and then clean up themselves — and each was written before the authenticator
existed, so it dropped four of the five roles. `conftest.drop_handle_objects` and
`bootstrap._cleanup` were already correct; only the hand-written lists were stale. All four
now name the authenticator, and the group they live in leaves no role and no database behind.

**6. Revoked and expired are one credential state.** The credential listing derived "active"
from `revoked_at` alone, so an elapsed credential the bearer boundary already refuses was
shown as usable; and rotation replaced an elapsed inherited expiry with `NULL`, promoting a
dying credential into one that never expires. `workspace_api_credentials()` now returns the
lifecycle state computed by PostgreSQL against the same `clock_timestamp()` the bind compares
against, and rotation refuses an expired predecessor with the neutral refusal a revoked one
gets — the narrowest fail-closed reading of ADR 0009 decision 5, because rotation carries the
predecessor's scopes forward without rebounding them by the member's current role. Rotation
with an explicitly supplied future expiry does not lift that refusal; re-issuance is the way
back. The elapsed-expiry guard is kept as a refusal rather than deleted, so a future edit
cannot silently reintroduce the `NULL`.

### The final independent M3.1 verification — clean, nothing outstanding

A third independent review — GPT-5.6 Sol at xhigh effort, over the implementation at
`f92ecb9` — **verified all six outstanding findings from the second pass as fixed**: the
recovery/login transaction race; the mailbox-verification authority; stale workspace
membership; HTTP authentication and CSRF ordering; strict `keep_current` Boolean parsing; and
credential-expiry consistency. The additional **authenticator-role teardown leak** — the
seventh item above, found by the leak check rather than by a reviewer — is **fixed** with
them: the four hand-written per-run role lists in `test_bootstrap_safety.py` and
`test_bootstrap_lifecycle.py` name the authenticator, so the group leaves no role behind.
The review found **no actionable regression**.

The final focused verification of that state passed **202 tests with no failures**, and
`./scripts/verify-repository.sh` passed **all 14 gates**, the layout gate over **119**
required files. The latest full foundation-suite result stands where the paragraph above
records it — **2,038 collected, 2,037 passed and 1 environment-dependent REPLICATION skip**.
Migrations `0001`–`0004` remain unchanged; migration `0005` contains the M3.1
implementation (unmerged at the time of that review; merged since at `87159d5`). No
disposable database, role or session remained on the cluster after the
run.

**M3.1 was, at that review, implemented, tested, independently reviewed and ready for pull
request and merge; it has since merged at `87159d5` (PR #9).** It remains **not deployed and
not VERIFIED LIVE**: no deployment exists and no evidence artifact has been captured, and
neither a passing suite nor a clean review is evidence under this repository's standard.

### Not implemented in M3.1 — deliberately

The customer application and any HTML (M3.2 — **now built**, see the Milestone 3.2 section
below); password change while signed in (needs M3.2's re-authentication design — **now
built**, ADR 0010 decision 4); deployment, TLS, the separated issuer credential and real secrets
delivery (M3.3); a real email provider, rate limiting, metrics (M8, a subset pulled forward
by M3.3); account deletion and archival (no milestone has taken the retention decision);
account-level events in a tenant audit trail (signup, verification, recovery and session
revocation have no tenant); more than one workspace per tenant.

### What M3.1 does not claim

It is committed at `f92ecb9` and merged at `87159d5` (PR #9), and it is **not deployed and
not VERIFIED LIVE**:
no deployment exists and no evidence artifact has been captured. The gate's "through the
UI" route is M3.2's to build and test; the four cases are met here at the database and HTTP
boundaries. Password verification runs in the application process, so a compromised runtime
can read one Argon2id hash per address it names — a stated limitation, not a solved one, now
confined to the narrow authenticator principal. Starlette 1.6 emits a deprecation warning
preferring `httpx2` for its test client; the pinned `httpx` 0.28.1 works and the warning is
informational.

---

## CURRENT — Milestone 3.2 the customer-only product portal — **implemented, tested and independently reviewed at `ce097cb`; merged at `ae61747` (PR #10)**

Built on `feat/milestone-3-2-customer-portal` from `main` at `87159d5` (Milestone 3.1,
PR #9), committed as **implementation commit `ce097cb`** and merged to `main` at
**`ae61747`** (PR #10, status commit `59d82a7`). **Not deployed, and not VERIFIED LIVE**: no
evidence artifact has been captured. ADR 0010 records the design and its four rounds of
corrections, and every actionable finding is closed — the independent review's eleven
(2026-09-10), the three remaining logout findings and the session-generation race
(2026-09-11), the clean-context review's eight (2026-09-11) and the final review's two P3
findings (2026-09-12); see the correction sections below. Migrations `0001`–`0005` are unchanged history, byte for byte;
`0006_preferences_and_password` is where the whole schema change lives. It replaces the
bodies of three of the identity plane's fifty-one functions with `CREATE OR REPLACE` —
`verify_account_email` and `complete_account_recovery`, brought under the account-plane lock
order, and `workspace_membership_authority`, brought to compare the recorded expected
workspace with the binding — restoring all three verbatim on downgrade;
`bind_authenticated_context`, the other forty-seven and every M3.1 policy are untouched.

**What it is.** The authenticated customer application, `portal/`: TypeScript, Vite and
React, with **React and ReactDOM as its only runtime packages** and a development toolchain
of Vite, TypeScript, Biome, Vitest with jsdom and Testing Library (`portal/package.json` is
the authority for the exact list), served **same-origin with the API** behind a proxy.
Nineteen registered routes across five journeys — signup and email confirmation, sign-in and
recovery, the first workspace, the workspace itself (details, team, stated policy, API
credentials) and the account (identity, password, sessions): six of them public, two for the
first workspace, two account pages in the shell and nine inside a workspace, four of which
(Evaluation, Jobs, Results and Billing) are honest, unfabricated placeholders — and a
twentieth page, not found, as the fallback for every other path. Behind it, migration `0006`
adds two relations (the tenant-plane `workspace_preferences` and the transaction-scoped
`identity_expected_workspace`), one trigger and six functions, replaces the bodies of three
`0005` functions, and the API gains five route registrations on four paths.

| Path | What |
| --- | --- |
| `portal/src/api/client.ts` | The one place the portal talks to the API: `/v1` paths only (a protocol-relative or absolute URL is refused before `fetch`), CSRF on every cookie-authenticated mutation read fresh from the cookie, 16 KiB bodies bounded before they are sent, refusals mapped through a closed table so a server-supplied code is never rendered raw, a deadline helper that aborts a request through its own signal and its operation's and is released on settlement, and no logging anywhere |
| `portal/src/lib/csrf.ts`, `lib/redirect.ts` | Reading the CSRF cookie (prefixed name preferred, so cookie tossing cannot displace it); and the whitelist of destination *shapes* a `next=` parameter may take — applied to the caller's string and again to the destination rebuilt from the parser's result, so a dot-segment climb such as `/..//evil.example`, which the parser normalises to the protocol-relative `//evil.example`, is refused rather than returned |
| `portal/src/auth/session.tsx` | Who is signed in and what the **server** last said they may do. Nothing is persisted; the role is re-read from the bound workspace, not from the membership list. A replacement session is adopted synchronously from the response that opened it, before any read under it, and a refusal of the current session while a replacement is in flight is deferred to that request's outcome; account loads are sequenced and coherent (profile and workspace detail must agree, or the set is re-read once and dropped); a workspace selection publishes the binding the mutation returned at once and reads the rest separately. The one sign-out operation lives here: single-flight across every control, fenced to the session generation it began under, and it forgets the session only after a successful logout, or after one bounded account read following a failed logout confirms the session is gone. Every route's request carries a *lease* and a refusal reaches the session only through `reconcile`, which clears on a safe read's definitive `401`, checks a mutation's `401` with one bounded read, re-reads authority on `403`, and drops an obsolete answer; there is no unfenced `forget` |
| `portal/src/lib/one-time-token.ts` | Verification, recovery and invitation tokens: captured once by the router before any page renders, scrubbed from the URL, held in memory only, submitted at most once at a time, released when used |
| `portal/src/lib/requests.ts` | The page request lifecycle: a ticket per request carrying the load sequence, the session lease and the workspace the page began under, so only the newest load publishes and a completion after the page moved on is inert; and the keyed single flight every page read goes through, so a `StrictMode` replay issues each mount-time read once |
| `portal/src/ui/`, `portal/src/routes/` | The shell, the shared components and the twenty pages, grouped by journey into seven route modules; `App.tsx` holds the route tables and also owns focus after navigation |
| `control_plane/db/migrations/versions/0006_preferences_and_password.py` | `workspace_preferences` (composite FK, `FORCE` RLS, three policies, six check constraints, one trigger kept as defence in depth), the transaction-scoped `identity_expected_workspace` relation, and six functions: `state_workspace_preferences` and `acknowledge_workspace_consent` — the mutation boundary the application role holds — `identity_expect_workspace`, the writer of the expected workspace the boundary records once per workspace mutation, the consent trigger, and the two password-change entry points on the trusted-issuer boundary. It also states the account-plane lock order and replaces `verify_account_email` and `complete_account_recovery` under it, and replaces `workspace_membership_authority` to compare the recorded expectation with the binding under the workspace lock before any workspace mutation writes — restoring `0005`'s text for all three on downgrade |
| `control_plane/db/preferences.py`, `control_plane/api/consent.py` | The Python side of the relation — reads under the `SELECT` policy, writes through the two functions, every write naming the workspace the page loaded for; the versioned consent and subprocessor statement, served by `GET /v1/consent` |
| `control_plane/api/app.py`, `settings.py` | Five new routes; `workspace_id` required on both preference mutations, the `X-Workspace-Id` header required on every workspace mutation (recorded in the transaction once, after the bind and before the handler) and `409 workspace_mismatch` when either is not the bound workspace; `workspace_id` in the envelope of every workspace read; a login whose password moved mid-flight is `401 invalid_credentials`; the readable CSRF cookie set beside the session cookie and cleared with it |
| `control_plane/db/accounts.py`, `roles.py`, `models.py`, `security/authorization.py` | `change_password`; `WorkspaceBindingMismatch` for SQLSTATE `FB014`; the `0006` revision plan — the application role holds `SELECT` alone on the relation, the two mutation functions and the expected-workspace writer, and nothing on `identity_expected_workspace` — with four new function inventories and the protected-table tuple; the relation's model and four closed vocabularies; its `ResourceRule`, and the protected one for `identity_expected_workspace` |
| `scripts/verify-repository.sh`, `.github/workflows/ci.yml` | One new gate and its CI prerequisites — **both protected files, both changed with the human's explicit prior approval** |

### What M3.2 proves

Against PostgreSQL 16, and in the portal's own suite:

**Isolation and authorization.** `workspace_preferences` is on the ordinary M2.3 model, not
the protected plane: `FORCE` row-level security (which binds the schema owner too — an owner
`INSERT` with no context is refused by the policy before a constraint is reached), a `SELECT`
policy requiring `workspace:read`, `INSERT`/`UPDATE` policies requiring `workspace:write`,
and **no `DELETE` policy and no `DELETE` grant**. **The application role holds `SELECT` on
the relation and nothing else**: an `INSERT`, `UPDATE` or `DELETE` it writes itself is refused
at permission-check time even from an owner's CSRF-verified workspace session, before any
policy or trigger is reached. Two tenants cannot see or affect one another, and asking about
the other's workspace by id returns the same shape as "stated nothing" rather than an
existence oracle. A removed member reads nothing. The composite foreign key refuses a row
naming one tenant's workspace while carrying another's tenant id — tested as the owner with
`FORCE` briefly lifted, because a referential check bypasses row security and that is
precisely why the *pair* is referenced.

**The mutation boundary.** Every write goes through `state_workspace_preferences` or
`acknowledge_workspace_consent`, two `SECURITY DEFINER` functions granted to the application
role alone, and a static scan of every function body in the schema proves they are the only
two that write the relation. Each requires a workspace-bound session **with its CSRF secret
verified** (a read-bound, `csrf=False` transaction is refused, in Python and in raw SQL alike),
re-derives the caller's membership and role under the workspace lock (a member demoted after
its session bound is refused; a removal that overlaps a bound session is proven to wait for
it), compares the workspace the page loaded for with the bound one, decides no-op or
transition under the lock, and appends the audit event and writes the row in one call —
proven both ways with an injected failure: a row that cannot be written takes its event down
with it, and an event that cannot be appended leaves the row untouched. One successful
mutation produces exactly one audit event with the session actor, and a repeat produces none.

**The expected workspace.** Both mutations name the workspace the page loaded its form for.
A forged identifier, another workspace of the same account and another tenant's workspace are
one refusal with one message; a form loaded for workspace A whose shared session another tab
re-bound to B is refused, and neither A nor B changes; a save that names the bound workspace
succeeds. A switch that overlaps an in-flight save is proven through `pg_locks` to wait for
it, the save lands on the workspace it named, and the next save from the stale page is
refused. At the HTTP boundary an absent or malformed `workspace_id` is `422`, a mismatch is
`409 workspace_mismatch`, and the two-tab scenario is driven end to end.

**Derived consent.** `acknowledge_workspace_consent` records the server's current version,
the bound account and `clock_timestamp()` — proven with the trigger disabled, so the
derivation does not depend on it; the trigger re-derives the same values behind the function
as defence in depth. Re-acknowledging the version in force is a no-op that appends no audit
row; two simultaneous acknowledgements serialise on the workspace lock and leave one row, one
timestamp and one event; an unpublished version is refused in Python, in the function and by
the check constraint; and an ordinary preference edit never re-dates an acknowledgement. The
history is `audit_events`, which is append-only.

**The password change and the account-plane lock order.** One transaction verifies, replaces
by compare-and-swap against the hash it verified, supersedes every outstanding token, advances
the security epoch, revokes every membership-bound credential and **every** browser session,
and mints the replacement afterwards. A wrong current password changes nothing and leaves the
asking session intact. A foreign, revoked or unknown session is one neutral refusal. Every
account-plane writer now takes the account row `FOR UPDATE` first (then tokens, passwords,
bindings, sessions), which `0006` states once and applies to the change and to the two
replaced `0005` bodies. Under real overlap — one transaction holding the account row, the
others proven through `pg_locks` to be waiting on it with their token rows still unlocked —
two changes leave one winner; a recovery waits and returns `False` with its token superseded
rather than consumed; a login that verified the old password is refused when the epoch moved
under the lock; and a login, a recovery and a second change all waiting at once each lose
cleanly. No `40P01` in any outcome, one epoch increment, one live session, and no transaction
or pooled connection left open. The application role can call neither password function.

**The CSRF cookie.** Set at login and at password change with the session's own lifetime,
`SameSite=Strict`, `Path=/`, no `Domain`, **not** `HttpOnly`, `__Host-` prefixed exactly when
it is `Secure`; cleared with the session cookie at logout. It survives a reload and is shared
by a second tab **without rotating**, which is the gap M3.1 left. The boundary never compares
it with the header: setting cookie and header to the same forged value is still refused,
because the header is verified inside PostgreSQL against the session's stored fingerprint.

**The customer boundary.** The complete route inventory contains no path naming a supplier,
operator, agent, capacity, pool, bridge, budget, settlement, window, offer, certification,
qualification, reconciliation, provider, spend, internal or admin surface, and every path is
under `/v1/account`, `/v1/workspace`, `/v1/api`, `/v1/health` or `/v1/consent`. No issuable
scope reaches a reserved non-customer domain. The portal's own source is scanned for the same
terms. **The operator capacity agent appears nowhere**: not in the navigation, the API
surface, the settings, the user model or the source.

**Secrets.** The portal touches `localStorage`, `sessionStorage` and `indexedDB` **not at
all** — the test setup makes any access throw, and the source is scanned as well. There is no
`console` call, no `innerHTML`, no `dangerouslySetInnerHTML`, no `eval`. A newly issued
credential is shown once, is gone from the DOM when dismissed, and reaches no URL, cookie,
storage or later request; a replay renders "already issued" rather than an empty box. No
Milestone 3.2 response carries anything shaped like a secret.

**Journeys and states.** Signup, verification-resend and recovery-request show the *same*
confirmation for a known and an unknown address, so the portal does not hand back the oracle
the API's neutral `202` withholds. A one-time token is moved out of the URL by the router
before any page renders — captured once, scrubbed with `replaceState`, held in memory only —
and under `StrictMode`, with effects replayed, a verification is submitted exactly once, a
transport failure keeps the token for an explicit retry, a `400` is a spent link, a reload
loses the token and the page says to open the link again, and the token appears in exactly
one request and in no cookie, storage or URL. The invitation page is public: signed out, it
keeps the token and sends the visitor to sign in or sign up with `/accept-invitation` as the
checked continuation, then accepts in the same mounted application; signed in, it accepts
directly; a spent or mis-addressed token is one neutral sentence. An off-site `next=` is not
followed — nor one that is a path by every syntactic rule and protocol-relative once the
parser has normalised its dot segments — and a safe one is. A verified account with no membership keeps its session and is
offered the first-workspace page. A membership revoked underneath an open page leads to the
picker, not to an error. A `403` during an action is believed: the page re-reads its
authority and re-renders as the new role. **A sign-out is a server outcome**: the session is
forgotten locally only after a successful logout, or when one safe account read made after a
failed logout answers `401`. A `401` from the logout itself proves nothing — a wrong CSRF
secret on a live session gets the same neutral one, with no cookie deleted — so after any
failed, timed-out or lost logout the portal reads the account exactly once, never retries the
logout on its own, and keeps the customer signed in, on the same page, told so next to a
button that retries, whenever that read finds the session live or cannot settle it. **And it
is one operation**, owned by the session provider rather than by a button: registered
synchronously by the first call so that the masthead and the security page clicked together
send one logout and show one pending state; fenced to the session generation it began under,
so that a logout or read still pending when a password change adopts a replacement session
is aborted and applies nothing to the new session — no clearing, no navigation, no error;
and bounded, the logout at 15 s and the validity read at 10 s, a read past its deadline
being `unknown` with authentication retained and every control restored. **The same fence
covers every page.** Each request captures a lease when it starts, and its answer counts only
while that lease is current: a safe read's definitive `401` under the current session clears
it and the page is remembered; a mutation's `401` is ambiguous and is checked with one
bounded read before anything is cleared; a `401` that is a verdict on a password touches
nothing; a `403` re-reads authority; and an answer to a request begun under a session that a
login or a password change has since replaced — a late `401`, a late `500`, a late success —
is dropped without a message, a navigation or a clearing.

**Accessibility.** One `main` landmark and a skip link that is the first focusable thing; a
named navigation landmark; every input labelled by a real `<label for>`; an invalid field
carrying `aria-invalid` with its message tied by `aria-describedby`; every disabled
permission control carrying its *reason*, associated with the control; failures announced in
an `alert` region and confirmations in a `status` one; a dialog that is modal, labelled,
takes focus, keeps `Tab` inside itself, closes on `Escape` and returns focus to its opener;
captioned tables with `scope="col"`; forms submittable from the keyboard alone; and **focus
that follows the route**: after every actual route change made from the keyboard, focus
lands on the new page's `h1` — including a page whose heading appears only after its data
loads — and it is left alone on the first render and on a re-render that did not change the
route. Every public page's title is its `h1`; the wordmark is not a heading.

**Verification at implementation commit `ce097cb`, after the review corrections, the
centralised sign-out operation, the session lease on every route, the clean-context
corrections and the final review's two P3 corrections, against the attested local
PostgreSQL 16.15 cluster** — the suite totals observed on 2026-09-12 on the code that became
`ce097cb` (its only later change before the commit was a test docstring), and the canonical
script re-run at `ce097cb` on 2026-09-13 with only this status update in the working tree:
`./scripts/verify-repository.sh` reports **15
gates passed, 0 failed** with **167** required files in the layout gate — fourteen gates and
119 files before this slice; the corrections changed the script in one approved way, a
required-file entry for `portal/src/lib/one-time-token.ts`, and touched no gate. The
PostgreSQL foundation suite is **2,188 passed, 1 skipped** of 2,189 collected (the one skip
is the pre-existing, environment-dependent REPLICATION skip): a net increase of **55** over
the 2,133 reported before the review, all in the four M3.2 modules (the mutation boundary,
the expected workspace on every workspace route, the lock-order overlap tests and the
restore contract), and of **151** over M3.1's 2,037. The portal suite is **392 tests across
10 files** (65 added on 2026-09-12 for the final review's redirect correction — the
dot-segment corpus through every redirect helper, the rebuilt-destination check, the
router's `navigate`, a rendered `Link` and the sign-in journey — after 88 added for
the sign-out operation — its outcomes, single flight, the generation fence, deadlines and
cleanup — the session lease on every route, the replacement barrier, the ordered and coherent
refresh, the binding-first workspace switch, the expected workspace on every page, the page
request lifecycle, mount-time reads under `StrictMode`, one-time tokens under `StrictMode`,
the invitation flow and focus after navigation), run by the new gate together with `biome ci`,
`tsc --noEmit` and a production `vite build`, on Node 24.21.0 LTS. `git diff --check` is
clean; the cluster carries no `firmbatch_test_*` database, role or session afterwards. **No
evidence artifact was captured**; these are reported results at implementation commit
`ce097cb`, not VERIFIED LIVE. The figures reported on 2026-09-09 (2,133 passed; 239 portal tests) are
HISTORICAL to the pre-review tree, and the 327 portal tests reported on 2026-09-11 are
HISTORICAL to the tree before the final review's corrections.

**The new gate is fail-closed, and that was checked rather than assumed.** With
`portal/node_modules` moved aside, the portal gate fails, naming `cd portal && npm ci` as the
fix, and the script exits non-zero. The figure first recorded here, "13 gates passed, 2
FAILED", came from a run in which `FIRMBATCH_TEST_DATABASE_URL` had also been emptied to
shorten the experiment, so its second failure was the foundation-suite gate refusing to skip,
not a second effect of the missing dependencies; the portal gate is the only gate that
consults `portal/node_modules`, so that experiment on its own is one failure of fifteen. An
unrun test suite reports the same green as a passing one, which is why the gate does not
skip.

**Six existing test modules changed, each because a head, an inventory or a contract
moved**, and no assertion was weakened: `test_migrations.py` and `test_identity_migration.py`
(the head is `0006`, and both ladder round-trips gain `0006` as a rung, so they now cover one
more revision in both directions; `test_migrations.py` also asserts that the head plan names
the protected `identity_expected_workspace`); `test_identity_protection.py` (the
authenticator's named inventory grows from ten functions to twelve — the deliberate-edit gate
M3.1 built for exactly this, with the two additions named and justified in place);
`test_protected_auth_state.py` (`identity_expected_workspace` joins the parametrised
protected-write refusals); `test_api_http.py` (its browser carries the `X-Workspace-Id`
header every workspace mutation now requires); and `test_destructive_safety.py` (its two
terminate steps target client backends only — the autovacuum flake noted below).

### The two defects this milestone's own tests found

1. **The client demanded a CSRF token on the pre-authentication routes.** Signup, verification,
   recovery and login are not cookie-authenticated and carry no CSRF secret — there is no
   ambient authority for one to defend and no session secret in existence yet. The first
   signup test failed with "your session has ended", which is exactly what it should have
   said. Corrected with a **closed, auditable list** of the six exempt paths checked in the
   client rather than a flag each call site passes, because a flag can be forgotten at a new
   call site and the failure mode of forgetting it is a cookie-authenticated mutation that
   silently stops proving where it came from.
2. **A failed team action had its explanation erased by the reload that followed it.** The
   page reloads its lists after a failure so the customer sees where things stand, and the
   reload cleared the same error state. Corrected by separating "the thing you asked for did
   not happen" from "these lists could not be fetched", which have different lifetimes.

A third correction was made without a test failing: a consent-service outage used to reject
the whole preferences load, leaving the form rendered with **empty values that were not the
customer's** — the state in which somebody presses Save and overwrites their own settings with
blanks. The two halves now settle independently, and Save is refused outright until the
current settings have actually been read.

### Independent review corrections (2026-09-10)

An independent review of the branch raised eleven findings, all accepted as actionable and
reproduced. Every one is corrected at its root, with a test that fails without the
correction, and migrations `0001`–`0005` are byte-identical to `main` before and after:

1. **Stale workspace form.** Both preference mutations carry the workspace the page loaded
   for; the database compares it with the bound workspace under the workspace lock and
   refuses a mismatch with one neutral code (`FB014` → `409 workspace_mismatch`); the portal
   says nothing was saved and reloads for the current workspace. ADR 0010 decision 7.
2. **Application-role DML.** The application role's `INSERT, UPDATE` on
   `workspace_preferences` are gone; it holds `SELECT`. Direct DML is refused even from an
   owner's CSRF-verified session.
3. **Read-bound contexts.** Both mutation functions require the CSRF-verified workspace
   session first; a `csrf=False` transaction is refused in Python and in raw SQL.
4. **The trigger as boundary.** The two `SECURITY DEFINER` functions are the authorization
   and audit boundary; the trigger is defence in depth, and the functions are proven to
   derive the consent actor and time with it disabled. No unrelated function writes the
   relation.
5. **Password-change/recovery deadlock.** One documented account-plane lock order in
   `0006`; `complete_account_recovery` and `verify_account_email` replaced under it (restored
   verbatim on downgrade); `change_account_password` reordered; real two-connection and
   four-connection overlap tests with `pg_locks` evidence, no `40P01`, neutral mapping, no
   partial state, no leaked transaction or connection. ADR 0010 decision 4.
6. **Logout correctness.** Local state is cleared only after a successful logout, or when
   one safe account read made after a failed logout confirms the session is gone. A logout
   `401`, `5xx`, network failure, timeout or lost response leads to that single read; a live
   or uncheckable session keeps the customer signed in with an actionable message and a
   retry, and nothing retries the logout on its own. Corrected three times: the first
   correction still trusted a logout `401`, and the review's P2 follow-up reproduced a wrong
   CSRF secret on a live session receiving that same `401` with no cookie deleted and the
   account read still succeeding; the third (2026-09-11, the three remaining logout
   findings) moved the sign-out into the session provider as one generation-fenced,
   single-flight operation — an answer pending when a replacement session is adopted is
   aborted and applies nothing, two controls clicked together send one logout, and the
   validity read runs under a real deadline that yields `unknown` with authentication
   retained; and the fourth (2026-09-11, the session-generation race) extended the fence to
   every route — a lease on every request, no unfenced `forget`, a mutation `401` never
   clearing on its own, a safe read's `401` clearing only the matching current session, and
   an answer to a replaced session dropped whatever it says. ADR 0010 decision 9.
7. **StrictMode one-time tokens.** Tokens are captured once by the router, scrubbed, held in
   memory, submitted at most once at a time, retried explicitly, released when used. ADR
   0010 decision 8.
8. **Signed-out invitation flow.** `/accept-invitation` is public, keeps the token, continues
   through sign-in or sign-up with a checked route, and accepts in the same mounted
   application. ADR 0010 decision 8.
9. **Audit atomicity.** Each mutation appends its event and writes its row inside one
   function call; injected failures on either side roll back the other; a repeat appends
   nothing; simultaneous same-version acknowledgements leave one event.
10. **Navigation focus.** Focus moves to the new page heading after every actual route
    transition and never otherwise. ADR 0010 decision 10.
11. **Documentation counts.** ADR 0010, this file, `docs/tasks/current.md` and
    `portal/README.md` name the runtime packages and tool categories rather than counting
    them; `portal/package.json` is the authority.

One further mapping was corrected on the way: a login whose password verified against a hash
a change or recovery replaced while Argon2 ran is `401 invalid_credentials`, not the
boundary's generic `404`.

### Clean-context review corrections (2026-09-11)

A second, clean-context review of the branch raised eight findings, accepted as actionable
and corrected as one design — every answer fenced to what asked for it (ADR 0010 decision
11). Each has a regression test that fails without the correction; migrations `0001`–`0005`
stay byte-identical to `main`.

1. **Session replacement barrier (F1).** The provider adopts a replacement session
   synchronously from the response that opened it (`adoptFrom`, used by sign-in and the
   password change), before any read under it: the generation moves, pending work of the
   former session is disowned and aborted, and a refusal of the current session that arrives
   while the replacing request is in flight is deferred and settled by that request's outcome.
   Both reproduced schedules — the old Security-page `401` after the replacement response and
   before it — end with the replacement held, no detour through sign-in and the page's
   success kept. A replacement whose read fails is a live session with a retry.
2. **Atomic refresh and workspace switching (F2, F3).** Account loads are sequenced and only
   the latest publishes; a load reads again, once, when its profile and its workspace detail
   name different workspaces, and drops the set otherwise, so A's binding with B's role is
   unpublishable. A selection publishes the binding the mutation returned at once and
   navigates; its supplementary read is separate, and its failure is a retryable load problem,
   never "workspace unavailable".
3. **Expected workspace everywhere (F4).** Every workspace mutation carries `X-Workspace-Id`;
   the boundary records it once per transaction through the new `identity_expect_workspace`
   function into the new transaction-scoped `identity_expected_workspace` relation, and
   migration `0006` replaces `workspace_membership_authority`'s body to compare it with the
   binding under the workspace lock before any of the ten workspace mutations writes. A stale
   page, a forged identifier and another tenant's identifier are one neutral `409`, with no
   write and no audit event; a missing header is `422`. Every workspace read names the
   workspace it describes, and a page never renders an answer for another workspace.
4. **Page request lifecycle (F5, F6).** Every page request takes a ticket; only the newest
   load publishes, ends the loading state or reports; an action publishes only while the page,
   session and workspace it began under are current; completions after leaving a page are
   inert, including navigation.
5. **StrictMode and hygiene (F7, F8).** Page reads and the provider's own reads are keyed
   single-flight, so a mount effect replayed under `StrictMode` issues each read once while a
   reload after an action and a return to a route read afresh; the invitation page takes its
   ticket before its request; the account page says a confirmation link is on its way only
   after the server accepted the request; the ineffective dynamic import is gone and the
   production build is warning-free; concurrent validity reads coalesce; `clearWorkspace`,
   which had no production caller, is removed; the source scan is supporting evidence only.

One flake was found on the way and closed: two `tests/test_destructive_safety.py` steps
terminated every backend on the disposable database, and an autovacuum worker there belongs
to the cluster superuser, whose processes a non-superuser may not terminate. Both now
terminate client backends only.

### Final review corrections (2026-09-12)

The final independent review of the corrected tree left two P3 findings, both accepted.

1. **A `next=` destination could normalise to a protocol-relative URL.** `safeDestination`
   checked the caller's string syntactically (one leading `/`, no `\`, no control
   character), resolved it against a throwaway origin, confirmed the origin, and returned the
   destination rebuilt from the parser's parts. The WHATWG parser normalises dot segments,
   so `/..//evil.example`, `/.//evil.example` and `/a/..//evil.example` — paths by every
   syntactic rule, and local by the parser's own account — came back as `//evil.example`,
   which is protocol-relative and which a browser sends off-site. The router's `navigate`
   happened to re-check the string it was handed, so a sign-in redirect through
   `destinationFromSearch` was refused on that second pass (and a direct `navigate` of such a
   value threw a `SecurityError` at `pushState`); a `Link` rendered the value as its `href`,
   and `destinationQuery` encoded it. The rebuilt destination is now checked again, with
   the same syntactic rule and a second parse that must land on the same origin, path, query
   and fragment, and it is returned only if that form passes as well. The three cases, their
   percent-encoded and query-carrying variants, are in the hostile corpus, asserted through
   `safeDestination`, `destinationFromSearch`, `destinationQuery`, the router's `navigate`,
   a rendered `Link` and the sign-in journey; against the previous module, fourteen of the
   fifteen new tests fail (the journey passes either way, for the reason above). The
   consumers' own checks are unchanged.
2. **Factual descriptions reconciled with the implementation.** Every count below was
   re-derived from migration `0006`, the route tables, the staged diff and the verification
   script rather than copied: `0006` adds **two** relations (`workspace_preferences` and
   `identity_expected_workspace`), **one** trigger and **six** functions, replaces **three**
   `0005` bodies, grants **three** functions to the application role, and puts **six** check
   constraints on `workspace_preferences`; the portal registers **nineteen** routes and
   renders **twenty** pages (the not-found fallback is the twentieth) from **seven** route
   modules; the API gains **five** route registrations on four paths; **six** existing
   foundation-suite modules changed, named above; the identity plane `0005` defined has
   **fifty-one** functions (the M3.1 comment in `db/roles.py` said fifty, split
   twenty-seven, five and eighteen; the tuples say twenty-five, eight and eighteen). Corrected
   in `db/roles.py` (the five-function, two-replacement, ten-function and fifty-function
   wording), migration `0006` (comment only: the audience inventory and the sanitiser
   comment), `db/accounts.py` (`FB014` is raised by the two preference mutations *and* by
   the replaced `workspace_membership_authority` on every workspace mutation),
   `api/consent.py` and `portal/tests/storage.test.ts` (each cited a test module that does
   not exist; the assertions live in `test_portal_migration.py` and `test_portal_http.py`),
   `portal/src/lib/requests.ts` (the provider's account loads do not use `SingleFlight`; the
   page reads and the validity read do), `portal/src/api/client.ts` (no `Accept` header is
   sent, and the comment said one was), ADR 0010's consequences, `docs/tasks/current.md`,
   `portal/README.md` and this document. The "13 gates passed, 2 FAILED" fail-closed figure
   is restated above as what it was: one failure from the missing `node_modules`, and one from
   a foundation-suite gate deliberately starved of its database URL in the same experiment.

### Not implemented in M3.2 — deliberately

Jobs, quotes, invoices, evaluation runs, results and billing (M4–M6; the four sections are
navigation and honest unavailability, with no fabricated record of any kind); deployment,
TLS and real secrets delivery (M3.3); a real email provider, rate limiting and metrics (M8,
a subset pulled forward by M3.3); changing an account's email address (no milestone has taken
the identity-change decision); account deletion (no milestone has taken the retention
decision); more than one workspace per tenant; and a **real-browser end-to-end suite** — see
below.

### What M3.2 does not claim

It is committed at `ce097cb` and merged at `ae61747` (PR #10), and it is **not deployed and
not VERIFIED LIVE**: no deployment exists and no evidence artifact has been captured, and
neither a passing suite nor a clean build is evidence under this repository's standard.

**No real browser has run this portal.** The cookie contract is asserted at the header level
against real PostgreSQL, and the client behaviour is asserted in jsdom with a real cookie
jar. What neither covers is the *browser's own* enforcement of the `__Host-` prefix and
`SameSite=Strict` — vendor behaviour rather than this repository's code — nor the visual
result of the stylesheet. A Playwright suite against a deployed environment is the natural
home for both and belongs to M3.3, whose gate is already "the real customer portal can be
opened and reviewed on AWS with verified test identities". Recorded as an open item in
`docs/tasks/current.md`.

**No email is delivered**, so the signup, verification, recovery and invitation journeys
cannot be completed end to end by a human locally without reading the token out of the API
process. The capture adapter is still the only one that exists.

**Nothing here is a quote, an execution or a commercial commitment.** A `workspace_preferences`
row is recorded intent; no admission, routing or pricing path reads it, and M5 owns the
contract fields that make the same ideas binding.

**The M3.1 limitation is unchanged**: password verification runs in the application process,
so a compromised runtime can read one Argon2id hash per address it names. M3.2 adds a second
path that reads one — the signed-in change — and puts it on the same narrow authenticator
principal, which neither worsens nor solves the limitation ADR 0009 decision 6 states.

---

## CURRENT — Milestone 3.3a AWS staging, Cognito and Terraform architecture adoption — **merged through PR #11 at `86d4195`, documentation only**

Documentation only, on `docs/milestone-3-3-aws-terraform-architecture` from `main` at
`ae61747` (Milestone 3.2, PR #10). It changes no product behaviour, no migration, no test,
no dependency, no CI or verification script and no evidence; it creates no AWS resource, no
Terraform and no image; it touches no protected agent, policy, workflow or verification
file; and the two architecture source snapshots under `docs/architecture/sources/` are
byte-identical to `main`. ADR 0011 records the decisions; the topology document draws them.

| Document | What changed |
| --- | --- |
| `docs/adr/0011-aws-staging-cognito-and-terraform-delivery.md` | New, and corrected the same day after an independent review (below). M3.3 split into four slices — a architecture; b Terraform and task scaffolding only, not operational until c passes review; c every program the scaffolding runs — database bootstrap, identity binding, the broker and its Cognito, JWT and KMS clients — with the identity mapping, the cookie and route changes, the reviewed dependencies, lock files and tests; d reviewed plan, cost estimate, explicit authorization, apply and evidence — with Milestone 3 closing only after M3.3d; a dedicated staging account with account-ID enforcement, `eu-central-1` recommended and unconfirmed, synthetic data only, Budgets as alerts not a cap; one customer origin `https://staging.app.firmbatch.com` with ALB routing `/` and `/v1/*` to the web/API service and `/auth/*` to the identity broker, the compiled portal served from the web/API image, CloudFront and static S3 deferred; one Cognito User Pool per environment behind the broker (confidential client, code grant with PKCE, exact URLs, `openid email`, invite-only, email usernames, password plus required TOTP, `PreventUserExistenceErrors`, refresh rotation, five-minute tokens, eight-hour window, Managed Login at a custom domain with its certificate in `us-east-1`), no Identity Pools, no ALB `authenticate-cognito`, no groups for roles, no JWT at the core API, no social providers, no token in the browser; `__Host-fb_session` with `SameSite=Strict` and an opaque `__Host-fb_oidc` handle with `SameSite=Lax` that is not a session; every callback a `303` to a fixed clean URL; `/auth/logout` replacing the browser's `/v1/account/logout` in AWS mode; the `auth_identity(issuer, subject)` mapping bound explicitly by a manually invoked `identity-binding` one-off task and never by email, no legacy-password migration, KMS-encrypted refresh tokens in protected state; the network rules; RDS PostgreSQL 16 with the managed-RDS qualification list, the RDS-managed master secret for the bootstrap task only, database passwords written by a one-off task and never into Terraform state, the Cognito client secret as the acknowledged state exception; the Terraform layout and rules; the OIDC delivery model with two separately protected GitHub environments and saved plans kept as encrypted, short-lived objects that are never GitHub artifacts; metadata-only application logging with ALB access logs off, and AWS-managed records that can hold identity data inventoried at M3.3d; production hostnames left to Milestone 8; the explicit deferrals; the deployment parameters a human confirms at M3.3d; and, from a final correction pass, a dedicated identity-binding database boundary, `main`-only environments with distinct roles and required M3.3b acceptance tests, plan approval independent of plan-produced metadata in an Object-Locked plan bucket separate from state, structural reviewer allow-list validation, and credential-safe browser evidence |
| `docs/architecture/m3-3-aws-staging-topology.md` | New, and corrected with the ADR. The picture, the routing table, the two services and three one-off tasks with their credentials and security groups, network, RDS, the cookie table, the login, callback and logout flows, the identity mapping and the binding task, secrets, state and plans, the Terraform tree with module expectations, the pipeline with its two environments, the application and AWS-managed logging rules, the browser-evidence rules, the M3.3d evidence list, slice gates with the M3.3b acceptance tests and the M3.3c binding-boundary and evidence-tooling tests, deferrals and the parameter table |
| `docs/firmbatch-v1-roadmap.md` | Baseline `ae61747`; M3.0, M3.1 and M3.2 marked merged; production public hostnames marked a Milestone 8 decision, with the portal always same-origin and any separate API hostname for non-browser clients or reviewed edge routing; M3.3 rewritten as M3.3a–d with gates and `staging.api.firmbatch.com` superseded; the Milestone 3 gate closing at M3.3d; the remaining-decisions row narrowed to deployment parameters; the immediate order |
| `docs/architecture/v1-target-architecture.md` | New §14.1 **[M3.3a]** describing the staging subset of §14; a "repository amendments after D.1" note in §18. §17 byte-identical to `main` |
| `docs/architecture/rev-d-decision-register.md` | The AWS staging row in §3 narrowed to the deployment parameters with the architecture recorded as decided; §4 item 2 amended |
| `docs/STATE.md`, `docs/tasks/current.md`, `README.md` | Status: M3.2 merged at `ae61747` (PR #10), not deployed, not VERIFIED LIVE; Milestone 3 active; M3.3a current; the Cognito decision recorded; no AWS deployment or evidence; the stale M3.1 "still not merged" sentence and the task file's stale M3.0 "this branch" wording in its M2.4 section corrected |

**What this adoption does not do.** It deploys nothing and authorizes nothing: no AWS
account, DNS record, certificate, Cognito pool, bucket, database or task exists because of
it. It implements no broker, no bootstrap or identity-binding command, no identity mapping, no
cookie rename, no route change, no Terraform, no image and no pipeline, and it chooses no
JOSE/JWT library, HTTP client or AWS SDK. It fixes no deployment parameter — the account ID,
region, domains, CIDRs including the reviewer allow-list and its address-space allowance, SES
identity, alert recipient, budget threshold, RDS sizing and minor, the saved-plan lifetime and
the two GitHub environments' reviewers, the staging identities to bind, the retention of
AWS-managed identity logs, and the cost estimate are confirmed by a human at M3.3d. It verifies no AWS price or
behaviour. It reclassifies no evidence: M3.1 and M3.2 stay implemented, tested and
reviewed, not VERIFIED LIVE; nothing in M3.3 is VERIFIED LIVE before M3.3d captures it.

**Verification for this slice** is recorded in `docs/tasks/current.md` under M3.3a: `git
diff --check`; the two source snapshots and migrations `0001`–`0006` compared to `main` by
SHA-256; `./scripts/verify-repository.sh` at the working tree. It is a run, not an evidence
artifact. The final correction pass is verified by the same script at the finished, staged
tree, and that result is reported with the change rather than written here, so that the tree
the script verified is the tree recorded.

### M3.3a review corrections (2026-09-13) — four P2 and eleven P3 findings, all applied

An independent review of the M3.3a architecture raised four P2 and eleven P3 findings. All
were accepted and corrected in the same eight documentation files; no code, migration,
lock file, CI, script, source snapshot or §17 text changed. ADR 0011 "Review corrections"
maps each to the decision that now carries it.

- **P2-1 The saved Terraform plan.** It carries prior state and the Cognito client secret, so
  it lives only as an encrypted object under `plans/` in the KMS-encrypted infrastructure
  bucket, with a short lifecycle (proposed 24 hours), a recorded SHA-256, Terraform version,
  provider-lock digest, source commit and state serial and lineage, all verified by an apply
  that never re-plans; expired or mismatched plans are refused and deleted; GitHub shows only
  action counts, policy results, cost summary and checksum; the full plan is reviewed in a
  separately authenticated operator session. State and plans are equally sensitive. The
  M3.3d evidence list now records the sanitized summary, never the plan. *Superseded in part
  by the final correction pass below:* plans now live in a separate, Object-Locked plan
  bucket rather than under a prefix of a shared bucket, apply verifies an approved object
  version independently rather than recorded metadata, and a refused or expired plan is left
  to lifecycle expiry, because a delete in a versioned bucket does not remove every copy.
- **P2-2 The session cookie.** Recorded for M3.3c: `__Host-fb_session` wherever cookies are
  `Secure` (`Secure`, `HttpOnly`, `Path=/`, no `Domain`, `Strict`), unprefixed only as a
  development name, tests and configuration updated, no deployed-cookie migration. The
  topology's claim that host-only stops a sibling host is corrected: the prefix does. The
  `__Host-fb_oidc` handle is specified — `Lax` deliberately, opaque, single-use,
  short-lived, holding no token, code, nonce or verifier.
- **P2-3 Identity binding.** A fifth, one-off `identity-binding` task definition, manually
  invoked, with its credential, Cognito permission, non-secret invocation metadata, audited
  success and refusal, neutral refusals, and no endpoint or service — in the topology, the
  task and credential tables, the Terraform module expectations, M3.3c and M3.3d.
- **P2-4 Slice ownership.** M3.3b is scaffolding only and is not operational until M3.3c's
  programs, dependencies and image pass review; every executable program, client,
  dependency, lock file, entry point and test is M3.3c's; no library is chosen in M3.3a.
- **P3 corrections.** RDS ingress from all five security groups; no WAF added to the
  ALB; the authentication host under the same registrable domain with the `Strict`
  session and `Lax` handle stated; `/v1/account/logout` disabled for the browser in AWS mode
  in favour of `/auth/logout`; two GitHub environments, `staging-plan` and `staging-apply`,
  both human-approved with exact-`sub` OIDC trust; the broker's executable code moved from
  M3.3b to M3.3c; CloudTrail, Cognito logging and export, SES records and the Cognito WAF's
  logs inventoried at M3.3d as possible holders of identity data; port 80 on the same
  allow-list, redirect only; every callback a `303` to a fixed clean URL with the handle
  cleared, `no-store` and `no-referrer`; the unhandled-error logging finding recorded for
  M3.3c, widened after the corrections when the access line was found to fall back to the raw
  path as well; and the stale M3.0 wording and the production-hostname language reconciled.

A security review and an evidence audit run after the corrections raised further questions.
Six were decided in the final correction pass below. The rest remain open, with their owning
slice, under "Open questions carried into Milestone 3" in `docs/tasks/current.md`.

### M3.3a final correction pass (2026-09-13) — six architecture questions decided

Documentation only, in the same eight files; no code, migration, dependency, Terraform,
workflow, verification script, source snapshot or §17 text changed. ADR 0011 "Final correction
pass" maps each decision to where it lives.

- **The identity-binding credential.** The binding task no longer receives the authenticator
  credential. M3.3c adds a dedicated identity-binding login role with no table privilege and
  no role membership, holding `EXECUTE` on one `SECURITY DEFINER` binding function, with a
  separate `NOLOGIN` owner where review needs one. The function binds one explicit
  `(issuer, subject)` to one explicit unused invitation or account, never by email; it is
  idempotent, refuses conflicts, and commits its audit event atomically. The task's command is
  assumed overridable, so the credential is designed to be harmless beyond binding; the
  operator's run permission covers only this task definition and its own roles. The task,
  credential, security-group and RDS-qualification tables are updated. The ordinary
  transaction preamble calls two identity accessors, so the binding command's database path
  must not rely on it.
- **The GitHub environments.** Both `staging-plan` and `staging-apply` allow only `main`,
  require reviewers, prevent self-review where supported and hold no permanent AWS credential.
  The workflows are manually dispatched from the default branch, check `refs/heads/main` and
  the source commit's reachability and approval, are protected by `CODEOWNERS` and branch
  protection, and are disabled for forks and pull requests. OIDC trust names the exact
  repository and environment, the plan and apply roles are distinct, and the apply role has a
  permissions boundary and cannot be assumed through `staging-plan`. Each is a required M3.3b
  acceptance test.
- **Plan approval.** Saved plans move to a dedicated plan bucket, separate from state, with
  content-addressed keys, versioning and Object Lock governance retention. The plan role can
  create objects but cannot overwrite, unlock or apply. The human starts apply with the
  reviewed object's key, version ID and expected SHA-256, visible in the approval request.
  Apply recomputes and checks everything itself and fails closed; plan-produced metadata is no
  authority.
- **Plan retention.** A proposed one-day governance retention tied to the saved-plan lifetime,
  24 hours recommended; lifecycle expiry of current and noncurrent plan versions and delete
  markers; no bypass or historical read by either role (as implemented by M3.3b: no version
  listing, and IAM cannot confine `s3:GetObjectVersion` to one version, so a version ID already
  held stays readable within the retention window — ADR 0012 decision 7); apply refuses a plan past the allowed
  age; state keeps its own retention and never expires with plans. The earlier wording that a
  refused plan is deleted is replaced: a delete in a versioned bucket only adds a marker.
- **The reviewer allow-list.** Fail-closed structural validation by Terraform and an
  independently tested policy check: canonical CIDRs, IPv4 `/24` or narrower, IPv6 `/64` or
  narrower, at most 16 entries proposed, no non-routable, duplicate or overlapping entries, a
  maximum address-space allowance, never empty; human review; no committed CIDRs; the same
  list on ports 80 and 443; the broker's NAT EIP added separately as a `/32` to the Cognito WAF
  only.
- **Browser evidence.** No raw traces, HAR files, videos, storage-state files, console or
  network dumps or failure screenshots from authentication journeys; persistence disabled; an
  allow-listed summary; fixed failure classifications and opaque correlation IDs; sanitized
  callback and logout assertions; separately approved screenshots of clean synthetic routes
  only; a blocking secret scan before commit; raw artifacts never uploaded. M3.3c builds the
  tooling and M3.3d's evidence list asks only for sanitized summaries and approved images.

The deployment-parameter lists are reconciled to the genuine human decisions: account, region,
domains, CIDRs, SES identity, alert recipient, budget, RDS sizing and minor, plan lifetime and
reviewers, identities to bind, AWS-managed log retention, the current cost estimate and the
deployment authorization.

---

## CURRENT — Milestone 3.3b Terraform, container and delivery foundation — **implemented, statically tested and independently reviewed at `cff27c8`; awaiting PR CI and merge; nothing planned, applied, pushed or deployed**

On `feat/milestone-3-3b-terraform-foundation` from `main` at `86d4195` (M3.3a, PR #11), committed at
implementation commit `cff27c8` and awaiting pull-request CI and merge; every actionable finding of its
independent reviews is closed (the correction passes below). ADR 0012
records the implementation decisions and the places they refine ADR 0011. It is **scaffolding
only**: no Terraform plan or apply has run against AWS; no AWS resource, GitHub environment,
branch protection, ruleset, variable, secret, image, deployment or evidence artifact exists
because of it; and no agent made an AWS API call while building it. Milestone 3.3 remains active,
and **M3.3c is next**: the executable identity broker, database bootstrap and identity-binding
programs, their dependencies and the identity-mapping migration, now `0008`. **`0007` is taken** by an
incidental correction on this branch: the password-hash contract (below; ADR 0012 decision 14).

| Area | What exists now |
| --- | --- |
| `infra/terraform/bootstrap/` | Applied first. The state bucket (versioned, customer-managed KMS, public access blocked, TLS only, lockfile backend; current state never expired, superseded versions expired after the configured retention with the thirty newest always kept) and the separate saved-plan bucket (versioned, KMS, Object Lock in GOVERNANCE mode with a configurable retention, lifecycle expiry of current and noncurrent versions and delete markers under `plans/` only, a policy refusing overwrite, retention bypass and history enumeration to the pipeline roles, and every write to any principal but the exact plan role). The state, plan and release keys. The account's one GitHub OIDC provider and **every GitHub delivery identity** — the staging plan and apply roles and the artifact-publish role, their trust and permission policies and boundaries. Applied by a human only (`infra/terraform/runbooks/bootstrap.md`) |
| `infra/terraform/artifacts/` | Applied second. The canonical release registry (ADR 0012 decision 13): a private release repository with `IMMUTABLE` tags and no exclusion filter, KMS encryption under the bootstrap root's release key, scan on push, untagged-only expiry and a repository policy letting only artifact-publish push and nobody delete; the Object-Locked, write-once release-record bucket; no replication. It creates no identity or key, and refuses to plan until every role it names exists. Applied by a human only |
| `infra/terraform/environments/staging/` | The staging composition of the eight modules, its own state key, `allowed_account_ids` and caller-identity and region postconditions, `eu-central-1` default and `us_east_1` aliases, a values-free example |
| `infra/terraform/modules/` | Exactly `network`, `edge`, `compute`, `database`, `identity`, `secrets`, `observability`, `delivery` — the topology of ADR 0011 decisions 3–8; `delivery` now holds only the workload boundary and the operator's identity-binding policy |
| `infra/terraform/policy/` | The repository's independent checks (standard library HCL and YAML readers, the reviewer allow-list validator, an IAM policy evaluator, twenty-three rules) with mutation tests that remove each rule's main properties and expect a refusal — not an exhaustive test of every line each rule reads |
| `infra/terraform/scripts/static-checks.sh` | What the new verification gate runs |
| `infra/delivery/` | `delivery.py`, the workflows' fail-closed checks and their tests — among them the resumable publication state machine, the versioned release-record contract, the frozen approval, the exact publish-attempt check, admission with digest-scoped exceptions and security stops, the deployment-authorization binding, rollback and destination-digest checks, and the ECS delivery contract applied to saved plans; `admission-policy.json`, zero critical and high findings and no exception; `readiness.json`, **every prerequisite false and no deployment authorization** |
| `.github/workflows/artifact-publish.yml`, `staging-plan.yml`, `staging-apply.yml` | Manual dispatch only; a preflight job with no environment and no OIDC token; publication builds once and publishes or resumes one release, plan promotes a verified release by digest, apply re-verifies the authorized release and refuses any other image; every file in a private runner directory removed by an always-run cleanup; **none can run today** |
| `.github/workflows/ci.yml` | Installs the pinned Terraform for the new gate; a `container` job that builds and inspects the image and never logs in or pushes; reusable through `workflow_call` as publication's required verification |
| `.github/CODEOWNERS` | Owners for infrastructure, workflows, scripts, the container files and agent configuration |
| `Dockerfile`, `.dockerignore` | Three stages, digest-pinned bases, locked dependencies, a non-root runtime with no tests, no credential and no environment file |
| `docs/adr/0012-terraform-container-and-delivery-foundation.md` | The decisions |

### What M3.3b establishes — statically, and nowhere else

Asserted by the mocked Terraform tests, the independent policy checks with their negative tests,
and the delivery checks' unit tests. **None of it has run against AWS or GitHub.**

- Every Terraform test is confined to a root's `tests/` directory, mocks every provider
  configuration its root declares, and plans only; the check runs before any `terraform test`,
  which the gate runs with every AWS credential removed and instance metadata disabled.
- Account enforcement on every provider and root; separate roots and state keys; no workspace; one
  pinned Terraform and one pinned provider with committed lock files.
- No provisioner, PostgreSQL provider, secret version, generated password, IAM user or access key,
  Identity Pool, Cognito group or user, ALB authentication, WAF on the ALB, CloudFront, valued
  `tfvars`, state or plan file.
- ECS tasks without public IPs or ECS Exec, with circuit-breaker rollback, one verified release
  reference by digest from the approved repository with tags refused, containers unprivileged, non-root,
  with a read-only root filesystem, every capability dropped and no volume, a separate credential per task — the identity-binding task never holds
  the authenticator credential — and no ECS task definition or service plannable until
  `runtime_contract_reviewed`, a human-set boolean, is true after M3.3c's review (the services'
  precondition is asserted by the policy check, the task definitions' also by a Terraform test).
- RDS PostgreSQL 16: private, encrypted, SSL-enforced, Single-AZ, seven-day backups, deletion
  protection, final snapshot, RDS-managed master secret, an explicit minor.
- Ingress from a CIDR only through the reviewer allow-list on ports 80 (redirect only) and 443; the
  allow-list refused by Terraform and independently by Python when empty, invalid, non-canonical,
  non-routable, duplicated, overlapping, broader than `/24` or `/64`, longer than 16 entries or over
  its address-space allowance.
- An invite-only pool with required TOTP, a confidential code-grant client with exact URLs and
  `openid email`, Managed Login v2 with its certificate in `us-east-1`, a WAF on the pool.
- IAM and bucket policies written with exact OIDC audience and subjects, distinct plan, apply and
  artifact-publish roles — all created, with the OIDC provider, by the human-applied bootstrap root —
  and the authority split of ADR 0012 decision 5 (its privilege and resource ownership matrix is
  there): trust anchors — IAM, KMS, secret containers, the release registry, buckets — are
  human-applied. The apply role's boundary **admits** only the staging service families, exact IAM
  reads and `iam:PassRole` on the ten pre-created workload roles to ECS tasks — no IAM mutation is
  within it — and denies secret values and secret-container writes, key policies, one-off tasks and ECS
  Exec, deregistration, another family on either service, service changes outside the two services,
  image publication and registry changes, release-record writes, data export and log reads, purchases,
  alarm suppression and budget actions. The apply role registers, and never deregisters, revisions of the
  five approved families and rolls out each service only with its own family; only the plan role may
  write a saved plan; and no statement grants either staging role an overwrite of a saved plan, a
  retention bypass or a history listing. Written, checked as text, and evaluated against representative
  requests by the repository's own evaluator and the mocked bootstrap tests — never evaluated by AWS.
- A saved plan checked against the ECS delivery contract at plan and again before apply: the image
  must be the verified release digest, roles the family's pre-created roles, secret references the
  family's approved containers, and containers unprivileged, non-root, read-only, capability-dropped,
  awsvpc, volume-free and without ECS Exec; a change to a trust anchor or a budget action refuses apply.
- Build once, promote by digest (ADR 0012 decisions 13 and 15), as written and unit-tested against
  in-memory fakes of GitHub, ECR and S3: publication after the full CI verification, one build with no
  build argument and its provenance in its labels before any credential, an SBOM and a release draft;
  then a fresh push of one immutable `git-<commit>` tag or the resumption of an earlier attempt's push,
  proven from the registry's own bytes, never an overwrite; a deterministic, versioned, write-once release
  record freezing the approval and naming the original publish attempt, a 412 or lost response accepted only
  for a byte-for-byte and semantically identical object; promotion that validates the frozen approval and
  the exact publish attempt, resolves the digest by digest only, and admits it under the committed policy
  with digest-scoped, expiring exceptions and security stops; apply that re-verifies the exactly authorized
  release immediately before applying, under a deployment authorization bound to one plan and one release;
  rollback to a retained earlier digest and revision; destination-digest equality before any cross-account
  or cross-region deployment. Nothing has been built, pushed or promoted.
- Workflows written to run only on manual dispatch of protected `main` in this repository, to
  reference an environment only after a preflight job checks it exists and is protected, to
  upload no artifact, to keep plan output off the log, never to plan at apply, and to apply only
  a named, retained, unexpired, checksum-verified saved-plan version whose provider lock matches
  the approved commit. The workflow structure is checked statically and the verification
  functions by unit tests; neither workflow has run.

### The correction pass before commit (2026-09-14)

Three corrections before the implementation commit, at the human's instruction:

1. **An incidental reliability and security correction: the password-hash contract, migration
   `0007_password_hash_contract`.** M3.3b's canonical verification failed once in the PostgreSQL suite
   with `PasswordPolicyError` from `hash_password`. M3.1's password-hash validation — in
   `security/passwords.py` and in `signup_account`, `complete_account_recovery` and
   `change_account_password` — applied the generic secret-shape recogniser to the Argon2id PHC hash,
   whose random base64 salt and digest can form an AWS access-key-id shape, so a valid hash was
   refused at random. Python now validates the hash structurally (text, at most 512 characters, the
   exact Argon2id PHC pattern), and the forward migration replaces the three function bodies with
   `CREATE OR REPLACE`, removing only the `secret_shape(<hash>)` term and restoring the earlier bodies
   exactly on downgrade, owner, ACL and hardening unchanged. The recogniser itself is unchanged, and
   migrations `0001`–`0006` are unedited. `control_plane/tests/test_password_hash_contract.py`
   (**110 tests**, passing three consecutive runs locally) uses a valid hash whose salt encodes the
   formerly refused shape, and holds signup, recovery and the signed-in password change to accepting
   it; every malformed, unsupported, oversized or NULL hash to refusal at every boundary; the raw
   access key id to recognition; the downgrade to `0006` to the catalogue a fresh `0006` produces; and
   nothing to logging the password or the hash. **The M3.3c identity mapping moves to `0008`**: ADR
   0011 and the M3.3 topology document carry the new number in place, each with a pointer to ADR 0012,
   and ADR 0009's M3.1 record is not rewritten. Implemented and
   tested, not VERIFIED LIVE.
2. **The authority split** replaces the blanket human-only rule (ADR 0012 decision 5).
3. **Build once, promote by digest** replaces manual image publication (ADR 0012 decision 13).

### The second correction pass: the independent M3.3b review (2026-09-14)

An independent review of the corrected tree raised sixteen findings and asked for a regression sweep;
all are corrected before the implementation commit, at the human's instruction (ADR 0012, whose
decisions are amended in place, with decision 15 new). Implemented and statically tested, not VERIFIED LIVE.

1. **The apply boundary.** The former `DenyEveryIamChange` `NotAction` statement denied everything
   outside a short allow-list — S3, EC2, RDS and ECS included — and is gone, with no broad replacement.
   The boundary's Allow set is its ceiling: the staging service families, exact IAM reads and
   `iam:PassRole` on the ten workload roles to `ecs-tasks.amazonaws.com`; no IAM create, update,
   delete, attach, detach, policy-version, trust or boundary change is within it. The policy check's
   evaluator and the mocked bootstrap test hold representative required requests — state and
   exact-plan access, VPC, RDS, task-definition registration, service changes, observability and
   budget operations — to being allowed, and IAM mutations to being denied. Every `NotAction` and
   `NotResource` statement in the tree is judged by what it denies, so a deny of everything but a
   short allow-list is refused whatever it is called.
2. **Revisions are kept.** Task definitions carry `skip_destroy = true`; the apply boundary denies
   deregistration; a digest rollout registers a new revision and deregisters none.
3. **No bootstrap cycle.** The bootstrap root creates the plan, apply and artifact-publish roles with
   their trusts, policies and boundaries, and the release key; the `artifacts` root reads the roles it
   names and refuses to plan until they exist, and no resource policy names a principal that does not
   exist. Order: bootstrap → artifacts → the human's first staging apply → the pipeline.
4. **Idempotent, recoverable publication.** The image is built and inspected, with its provenance
   (repository, commit, workflow, original run and attempt) in its labels, and its SBOM and release
   draft written, before any credential. `git-<commit>` is pushed once if absent; if present, its
   digest is resolved and its provenance and registry bytes verified. It is never overwritten or
   deleted, and only a missing SBOM or record is written. S3 writes are conditional; a 412 or lost
   response is accepted only for an object identical in full SHA-256 and semantic identity. A
   different digest or incompatible provenance refuses for human recovery. Artifact-publish gains only
   the ECR reads and `s3:GetObject` on release records this needs.
5. **The exact publish attempt** is named in the record and verified at its own attempt endpoint; a
   later failed rerun does not invalidate the release.
6. **Apply re-verifies the release.** Only the plan role may write a saved plan. Apply takes the
   release commit and the record's version and SHA-256, and immediately before applying re-verifies
   the record, digest, repository, commit, publish attempt, a fresh scan, admission and exceptions,
   and that the saved plan names the same digest. The apply role reads ECR by digest and the exact
   record version only.
7. **Historical, non-oracular approval.** Reviews from accounts without write access and reviews
   after `merged_at` are ignored; the approval evidence is frozen into the record and validated at
   promotion and rollback; revoking a release is an explicit security stop.
8. **The checker.** `*.tf.json`, override files and override directories refused; the exact
   credential-job guard; no status function, `continue-on-error` or step-level `if` but the cleanup;
   triggers, permissions and checkout settings read from the parsed file; `pull_request_target` and
   `write-all` refused; each protected environment reserved to its own workflow file; quoted YAML keys
   fail closed. One mutation test per bypass.
9. **ECS conditions.** Service creation and update are confined to the service's own family and to
   `ecs:enable-execute-command = false`, with the cluster and service resources and the saved-plan
   checks kept.
10. **KMS.** No KMS right for ECR; artifact-publish generates data keys and decrypts through S3 only;
    readers decrypt release records through S3 only; no ECR consumer grant.
11. **Scan exceptions** are committed and owner-reviewed, never inputs: an exact digest, exact
    vulnerability IDs, a reason, approver, approval reference, creation time and mandatory expiry.
    Anything expired, malformed, broad or mismatched refuses, at plan and at apply.
12. **Deployment authorization** is read from `readiness.json` on `main`, binds one plan key, version,
    SHA-256, release commit and image, expires within 24 hours, appears in the run name the approver
    sees, and is checked before any credential.
13. **Runner files.** `umask 077`, a private directory, and an always-run cleanup of plans, logs,
    `errored.tfstate` and crash logs that cannot mask the job's own failure; nothing printed or uploaded.
14. **Versioned release-record contracts.** Version 1 freezes its components, lock files, workflow and
    rules; a later component or lock file does not invalidate it; an unknown version refuses; retiring
    one is an explicit decision.
15. **The guard** unwraps `timeout -s/--signal/-k/--kill-after` and `env -C/--chdir`, refuses mutating
    `gh api` spellings, and applies the Terraform and AWS rules to `.exe`, OpenTofu and `aws2` names.
16. **Documents** reconciled; ADR 0011 and the topology document carry pointers to ADR 0012, and the
    migration references in both were renumbered to `0008` in place.

### The third correction pass: the review's verification (2026-09-14)

The same independent reviewer verified the second pass and found nine of its seventeen corrections
incomplete, one at P1. Each is corrected before the implementation commit, at the human's instruction, and
the eight it verified closed are preserved with their regression tests. Implemented and statically tested,
not VERIFIED LIVE.

1. **P1 — apply now reads the live security overlay from `main` (findings 6, 7, 11).** `verify-release`
   read the admission policy from the checkout, which at apply is the plan's older source commit, so a
   security stop or an exception's removal merged after the plan was ignored. It now reads
   `infra/delivery/admission-policy.json` from `origin/main` (`security_overlay_from_main`), at plan and
   at apply; the plan job's checkout fetches main's history. A test drives the `verify-release` command
   path with a checkout that lacks a stop `main` has, and it refuses.
2. **The historical contract and the live overlay are separate (finding 14).** Each release-record
   version's contract now also freezes the gate and publication job names and the approval rules (keys,
   qualifying associations, write permissions); verification uses the record's own contract for those, so a
   renamed CI job or changed rule is a new version beside the earlier one. The attempt's workflow path was
   still the module constant after this pass; the fourth pass reads it from the record's contract too. The
   overlay is in no contract.
3. **No bootstrap cycle (finding 3).** Readiness prerequisites are per workflow (`WORKFLOW_PREREQUISITES`):
   publication no longer requires `human_applied_resources_applied_by_human`, attested only after the
   first staging apply that deploys a published release; `readiness.json` must record exactly the known
   prerequisites. The bootstrap runbook orders publication before that apply, in two attestation PRs.
4. **The canonical artifact registry is declared (finding 3).** The bootstrap root takes
   `artifact_registry_account_id` and `artifact_registry_region` and builds every release ARN and
   release-key condition from them, never from its own account or region; it refuses a registry declared
   elsewhere, because it creates the publisher and the release key beside the registry. `staging-plan`
   checks its Terraform variables' registry declaration against the environment's before its OIDC token,
   and `plan-summary` refuses a plan whose `release_registry_*` inputs name another repository. A registry
   in a dedicated artifact account passes every check when every place declares it.
5. **An image store reporting a manifest digest fails before any credential (finding 4).** The build
   records BuildKit's configuration digest (`--metadata-file`); `release-draft` refuses a manifest
   descriptor or a local image ID that is not that digest, and the SBOM is addressed by the draft's digest,
   never the local image ID.
6. **The publish job checks its own attempt before any credential (finding 5)** — `check-publish-attempt`,
   the gate predicate promotion applies later — so a partial rerun whose gates are listed under an earlier
   attempt stops before the push rather than stranding the commit.
7. **Approval wording and rule (finding 7).** The association GitHub reports on a review is not described
   as proof of write access; the deployment source commit's approval is documented as requiring its
   approver's write permission when the job runs, and a revoked approver's effect on plan, rollback and
   apply is stated with its recovery.
8. **The checker (findings 8 and 17)** refuses an environment named by an expression or in another letter
   case, `dynamic` blocks, provider blocks in modules, module sources that do not resolve to
   `infra/terraform/modules`, `continue-on-error` or conditional jobs and steps in `ci.yml`, and step-level
   `if` in preflight jobs; its evaluator gives every request the keys AWS always attaches, fails closed on a
   condition key it does not model, evaluates the plan role, and reads every policy form a resource can hold,
   refusing any it cannot.
9. **The guard (finding 15)** parses `gh api` short-flag clusters by gh's grammar, routes `find` and `tree`
   write options through the write rules and refuses `find -ok`/`-okdir`, and resolves wrapper long options
   by GNU unique prefix, refusing an ambiguous one.
10. **Documents (finding 16).** ADR 0012 declares its amendments to ADR 0011 — deployment authority,
    migrate before rollout, the third environment, plan-version reads — and ADR 0011's header points to them;
    stale dates, root counts, guard wording, citations and environment counts are corrected; the external
    assumptions are assigned to M3.3d qualification. Boolean counts, maxima and identifiers gain tests.

**Protected files changed in this pass, under the human's instruction for these findings:** the three
delivery workflows, `.agents/policy/guard.py`, `.agents/policy/test_guard.py` and
`.agents/skills/verify/SKILL.md`. `scripts/verify-repository.sh`, `ci.yml`, `CODEOWNERS`, `AGENTS.md`,
`CLAUDE.md` and the hook configuration are unchanged; `REQUIRED_FILES` stays at **257**, since no file was
added.

**Component runs, locally, before the canonical run on the final staged tree** (runs, not artifacts): the
policy check, **23 rules, no findings**; the policy unit tests, **207**; the delivery unit tests, **97**;
`terraform fmt -check -recursive` clean; `terraform test` against mocked providers, **18 passed** for
`bootstrap`, **12** for `artifacts` and **41** for `environments/staging`; the agent policy tests, **460
checks passed**; `ruff check .` clean. The canonical run on the final staged tree is reported with the change
rather than written here.

### The fourth correction pass: findings 14, 16 and 17, and two regression gaps (2026-09-14)

The same reviewer found three findings still incomplete and two regression tests missing under closed findings.
Each is corrected before the implementation commit, at the human's instruction; the behaviour of every finding
already verified closed is unchanged. Implemented and statically tested, not VERIFIED LIVE.

1. **Finding 14 — the versioned workflow identity.** `verify_publish_attempt` compared the attempt's workflow path
   with the module-level `PUBLISH_WORKFLOW`; it now uses the workflow the record's declared contract names. A
   test defines a version-2 contract with a renamed publication workflow — and renames the module constant too —
   and verifies the unchanged version-1 record by its original identity; an attempt of the renamed workflow is
   refused for that record, a record relabelled version 2 is refused, and unknown versions still fail closed.
   The earlier wording that a later contract "strands no" release, written while the workflow path was still the
   module constant, is corrected wherever it appeared.
2. **Finding 17 — every policy a delivery identity can hold.** The checker now walks every IAM policy and
   attachment resource in every root and module against an explicit graph: each delivery identity holds exactly
   one literal inline policy and one boundary in the bootstrap root. Another inline policy, a managed or exclusive
   attachment, `managed_policy_arns` or `inline_policy` on a role, a policy held in a local or built by `for_each`,
   or an attachment to a role not proven to be declared beside it, is refused. Every admitted statement is read in
   full: no delivery policy may grant every action, a secret value, an SSM parameter, or decryption beyond the
   state, plan and release keys. **The plan role gains a permissions boundary**, human-applied in the bootstrap
   root: its ceiling is exactly the plan policy's actions, and its denies refuse secret values and parameters,
   other keys, the release key outside S3, saved-plan reads and state writes. Each boundary is evaluated alone
   against a side-door policy granting every action; a mocked bootstrap test does the same for the plan boundary,
   and confirms state reads, the lockfile, saved-plan writes and refresh still work.
3. **Finding 16 — documents.** The verification script's comment names all three roots; the guard's refusal
   message and `docs/tasks/current.md` say `providers lock`; the roadmap includes the artifacts root; the three
   delivery environments are distinguished; `delivery.py` cites ADR 0012 decision 13 for versioned contracts;
   ADR 0012 cites ADR 0011 §9.3 for build-per-deployment and, with ADR 0011's header, declares the guard,
   cost-summary, rollout and migration-order amendments; the workflow-token assumption is assigned to M3.3d
   everywhere; the guard-count progression runs through 460; 241 and 256 are labelled historical.
4. **Closed finding 4 — a regression test** distinguishes the local image ID, BuildKit's configuration digest and
   the registry manifest digest, shows the draft refuses the mismatch before any credential, shows the post-push
   comparison refuses a forged draft with no record written and no further write, and runs the same code with that
   comparison removed to show it would then produce a record binding the pushed image to a draft that attested
   another digest.
5. **Closed finding 12 — a command-level test** runs `check-deployment-authorization` with a checkout whose
   `readiness.json` authorizes the dispatched tuple and an `origin/main` that does not: it refuses. With exactly
   the tuple on main and an unreadable checkout copy, it passes, proving the checkout is never read.

**Protected files changed in this pass, each with the human's exact approval:** `scripts/verify-repository.sh`
(one comment; no gate or command) and `.agents/policy/guard.py` (one refusal message; no behaviour).
`REQUIRED_FILES` stays at **257** and the gates at **16**; no file was added.

**Component runs, locally, before the canonical run on the final staged tree** (runs, not artifacts): the policy
check, **23 rules, no findings**; the policy unit tests, **213**; the delivery unit tests, **101**; `terraform fmt
-check -recursive` clean; `init -backend=false -lockfile=readonly` and `validate` for all three roots; `terraform
test` against mocked providers, **19 passed** for `bootstrap`, **12** for `artifacts` and **41** for
`environments/staging`; the agent policy tests, **460 checks passed**; `ruff check .` clean. The canonical run on
the final staged tree is reported with the change rather than written here.

### The fifth correction pass: finding 17's delivery-identity adoption, and two policy-checker test gaps (2026-09-14)

The reviewer showed that a role outside the bootstrap root could still become a delivery identity — a staging-root
role imported from `firmbatch-staging-github-plan` and given `AdministratorAccess`, and a compute-module role named
`${var.name_prefix}-github-apply` — and that two policy-checker paths had no direct test. Corrected before the
implementation commit at the human's instruction; the behaviour of every finding already verified closed is unchanged.
Implemented and statically tested, not VERIFIED LIVE.

1. **Only the bootstrap root declares or owns a GitHub delivery identity** — the staging plan, staging apply and
   artifact-publish roles.
2. **Every other root and module declares only its explicitly allow-listed workload roles**: the compute module's
   `execution` and `task`, each with its reviewed name template.
3. **A role is judged by its effective `name` and `name_prefix`**, resolved through locals, interpolation, variables
   and module values, not by its Terraform resource label. An effective name ending in `-github-plan`,
   `-github-apply` or `-artifact-publish`, in any letter case, is refused; a name that cannot be resolved, or
   plan-time text that could complete one, fails closed.
4. **Terraform `import` blocks are refused everywhere under `infra/terraform`.** Adopting an existing AWS identity or
   resource needs a separate, explicitly reviewed human procedure and is never hidden inside an environment's
   ordinary configuration.
5. **An additional, unresolved or indirectly attached policy on a delivery identity fails closed**; outside the
   bootstrap root a policy may attach only, by reference, to an allow-listed workload role declared beside it.

Both reproductions are refused, and each rule has a negative test. The checker gaps are closed by direct tests: the
literal-policy-document check refuses each admitted policy in another form, and the always-refused request set is
shown to catch what the statement scan cannot. The R0 policy-engine row carries the guard-count progression
247 → 315 → 343 → 408 → 460 (finding 16). `REQUIRED_FILES` stays at **257** and the gates at **16**.

**Current final verification, locally** (runs, not artifacts). Component runs on the corrected tree: the policy unit
and mutation tests, **225** on the final tree (**221** at `cff27c8` and the fourth pass's **213** above are historical;
the four added tests guard the numeric `USER 10001:10001` of the PR CI container-build correction); the delivery
unit tests, **101**;
`terraform test` against mocked providers, **19 passed** for `bootstrap`, **12** for `artifacts` and **41** for
`environments/staging`; the agent policy tests, **460 checks passed**. The canonical run on that staged tree
(staged-diff SHA-256 `5f426da6869ce990b401218cd795ab48fa962d4ae1399f491a9a0d96efc66db6`): **16 passed, 0 failed**,
**257** required files. The documentation reconciliation came after that run; **the final local canonical run**, on
its staged tree (staged-diff SHA-256 `e6b90bc5efb35903bae89ef6f35933c9198a5a1ead2ee16788ccc66a1930dd0d`, the tree
committed as `cff27c8`): **16 passed, 0 failed**, **257** required files. None of this is AWS-live: no plan or apply, no image built or pushed, no
deployment and no evidence.

### What M3.3b does not do, and does not claim

- **No cloud plan, no apply, no AWS call, no GitHub change.** The IAM policies, the plan bucket's
  conditional-write condition, the workflows and the preflight's GitHub API reads have never run.
- **The GitHub protections do not exist.** At the pre-flight check — read-only GitHub API calls,
  an unrecorded observation rather than an artifact — `main` had no branch protection, no ruleset
  and no environment; the workflows refuse for exactly that reason, and nothing here
  claims otherwise because a test checks their shape.
- **The image has not been built locally.** Docker is unavailable locally; the first actual container build is
  CI's `container` job, which has not yet run and remains a required condition of the pull request's CI.
- **Not operational.** The broker, bootstrap and identity-binding programs do not exist; the
  existing web/API entry point still requires an authenticator URL the AWS-mode task does not
  receive; today's API does not serve the compiled portal the image carries.
- **Open, recorded in ADR 0012 "Still open":** one-off task execution in the pipeline (an operator runs
  `migrate` before a rollout that needs it, amending ADR 0011); replication, signing and a production
  registry; measured admission thresholds; **the external assumptions assigned to M3.3d qualification** —
  the ECS condition keys, ECR manifest bytes and bucket-policy conditions against AWS; the attempt-jobs names,
  partial-rerun job listing, `author_association` timing and the workflow token's view of environment
  protection against GitHub; the runner's image store and BuildKit metadata digest, and `origin/main` in a
  full-history checkout — each failing closed, and each gating publication failing before any credential and
  so before the push; egress
  narrowing through the NAT; a dual-stack ALB for IPv6 reviewer entries; the plan job's cost summary;
  the IAM action lists against a real plan; who writes the Cognito client secret value (M3.3c); the
  OIDC trust binding the environment rather than the workflow file; the static checks outside
  `AGENTS.md`'s ask-before list; and `npm ci --ignore-scripts`. (The workflow token's view of environment
  protection fields is among the M3.3d qualifications above.)
- Nothing in M3.3 is VERIFIED LIVE.

### Protected files changed, each with the human's explicit approval (2026-09-13)

`scripts/verify-repository.sh` (one new gate and the M3.3b `REQUIRED_FILES`; no gate removed,
reordered or weakened), `.agents/skills/verify/SKILL.md` (the gate documented, and the stale gate
count replaced by a pointer to the script's own summary), `.agents/skills/record-evidence/SKILL.md`
(M3.3 AWS staging evidence unavailable until M3.3d; other evidence unaffected),
`.agents/policy/guard.py` and `.agents/policy/test_guard.py`, `.github/workflows/ci.yml`, the new
`.github/workflows/staging-plan.yml`, `.github/workflows/staging-apply.yml` and
`.github/CODEOWNERS`. The approval's amendments are applied: **no agent-run AWS CLI call except
local commands** (the proposed read-only allow-list was not introduced), and the evidence
restriction confined to `docs/evidence/m3/aws-staging/`. No other protected file changed.

The two correction passes of 2026-09-14 changed further protected files at the human's explicit
direction. The first added `.github/workflows/artifact-publish.yml` and fifteen `REQUIRED_FILES`
entries and changed `ci.yml` and the two staging workflows. The second changed the three delivery
workflows, `.agents/policy/guard.py` and `.agents/policy/test_guard.py`, and — with the human's
separate explicit approval — `scripts/verify-repository.sh`, only to add its new
`infra/terraform/bootstrap/delivery_policies.tf` to `REQUIRED_FILES` (257 entries), with no gate,
command or ordering changed.

### Findings recorded while building it

- ADR 0011 decision 8 says extending the guard "is not this slice's"; M3.3b extended it with
  explicit approval, and ADR 0012 records that the sentence is superseded rather than rewriting it.
- The topology's secrets table has Terraform writing the Cognito client secret; M3.3b creates its
  container and no value, and leaves the writer to M3.3c.
- `control_plane/api/__main__.py` loads the authenticator URL unconditionally and binds loopback by
  default; the image passes `--host 0.0.0.0`, and the AWS-mode entry point is M3.3c's.
- `terraform validate` checks test files by default and fails on the teardown of a module that
  receives its `us-east-1` provider only through `configuration_aliases`; the gate validates with
  `-no-tests`, and `terraform test` validates and runs those files itself.

### Independent review corrections (2026-09-13)

A read-only security review and a read-only evidence audit ran over the finished tree before it
was staged; their findings were applied in the same change.

- **Security — the human-applied set widened** *(superseded on 2026-09-14 by the authority split,
  ADR 0012 decision 5: task definitions, services and ordinary budget changes are the apply role's
  again, inside the ECS delivery contract; kept here as the record of that pass)*. The review found that an apply role able to create
  or re-trust ECS roles, update a secret, register a task definition, share a database snapshot,
  export logs or replace the operator policy could read or replace runtime secrets and data. Every
  IAM resource, KMS key and alias, Secrets Manager container, ECS task definition and service, and
  the budget is now human-applied: the apply boundary denies the calls, the apply workflow refuses a
  plan that changes those types, and the first full staging apply is a human's (ADR 0012 decision
  5). This is wider than the "delivery trust" first approved, and stricter.
- **Security — also corrected:** purchases, alarm and budget tampering, other database classes and
  non-certificate `us-east-1` use denied to the apply role; the workload boundary narrowed to this
  environment's repository, log groups, secrets, keys and pools; the preflight counts only
  approvals from collaborators with write access and reads every page of reviews; apply credentials
  outlast the apply job; inventory and replication denied on the plan bucket; and the guard refuses
  `help` as a trailing operand, unwraps `time` and `exec`, refuses further registry-push spellings, an
  `init` whose last `-backend` is not `false`, `providers` subcommands other than `lock`, and any
  non-reading command naming a path in the M3.3 staging evidence directory.
- **Evidence — corrected:** the verification record and the gate-by-gate status table added to
  `docs/tasks/current.md`; the state bucket's retention described as it is; mutation tests added for
  the identity rule, every apply-workflow verification, the boundary's denies, lifecycle expiry,
  database settings and the container's locks; a check that the apply workflow keeps its checksum
  step; `.tftest.json` tests refused; stale gate and guard counts replaced; runtime wording for
  never-run workflows and policies replaced by "written and statically checked"; point-in-time
  observations labelled as unrecorded.
- **Left open, stated in ADR 0012:** binding the OIDC trust to the workflow file; putting the static
  checks on `AGENTS.md`'s ask-before list; `npm ci --ignore-scripts`; and an apply session's residual
  power over the infrastructure it does apply.

Verification for this slice is recorded in `docs/tasks/current.md` under M3.3b.

---

## CURRENT — v0 prototype

1,437 lines of Python across the product modules (`control/`, `controller.py`, `worker/`,
`providers/`, `fb.py`); 1,153 excluding blank and comment-only lines. Single control plane,
SQLite store, one provider adapter. (The "roughly 900 lines" in `README.md` is not counted
and is wrong.)

| Component | Behaviour |
| --- | --- |
| `control/db.py` | SQLite in WAL. Effective busy timeout is **15s**, set by `sqlite3.connect(timeout=15)` at `db.py:97` — the `PRAGMA busy_timeout=5000` in `SCHEMA` is per-connection and applies only to the connection `init()` opens, which is dropped by refcount when `init()` returns (`with conn() as c` is sqlite3's *transaction* manager, not a closing one). Every call site opens its own connection, so the PRAGMA is dead for all of them. Leases with expiry and reaping; results keyed `(job_id, request_id)` and upserted; ledger rounds worker life **up by a full increment past the floor** (`billed_h = (int(hours*6)+1)/6.0`, `db.py:410`), not to the ceiling. |
| `control/app.py` | FastAPI. Worker API (claim, heartbeat, post results) plus operator API. `GET /agent.py` and `GET /health` take no authorization argument at all. |
| `controller.py` | The deadline loop: measures rate against remaining work and scales workers. Holds the only spend ceiling, `max_workers`, which caps concurrency and not cumulative launches. |
| `providers/local.py` | Subprocess workers, for testing. |
| `providers/verda.py` | Verda adapter; uploads a per-job bootstrap script via `startup_scripts.create` and injects it by ID; the instance fetches `agent.py` from the control plane. The "confirmed against SDK 1.24.1" note is a module docstring, not an observation — see NOT VERIFIED. |
| `worker/agent.py` | Standalone, `requests`-only, disposable. Posts results in chunks of 25 as it goes. |
| `fb.py` | Operator CLI: `serve submit run watch chaos report probe demo`. Also owns deadline parsing (`parse_deadline`) and the chaos kill path. |
| `tests/test_recovery.py` | Fourteen deterministic checks. Thirteen cover the two durability properties below; the fourteenth covers ledger billing rounding. Not pytest — a script. |

Two properties the prototype rests on:

1. Shards are **leased**, never assigned. Two release mechanisms: immediate release when the
   controller notices a missing heartbeat, and lease expiry for when the controller itself died.
2. Results are keyed by `(job_id, request_id)` and **upserted**; a re-claimed shard is
   re-issued only the requests with no result yet.

Both are real and both are tested. Neither is an invariant in the roadmap §5 sense, and the
roadmap's own migration matrix already marks both **Replace** — see the defect register below
for what they do not give you.

### Not implemented in v0

No tenancy, no authentication beyond a shared `FB_TOKEN`, no S3 payload plane, no Postgres,
no quotes or contracts, no validator, no certification, no forecasting, no hedging, no
provider reconciliation beyond direct calls.

**No lease fencing.** There is no lease generation or attempt ID, and no ownership check on
the settle path. Roadmap §5 invariant 4 ("a stale worker cannot heartbeat, publish, validate,
or settle a newer attempt") is absent. See D1 below.

CI exists (`.github/workflows/ci.yml`, added by R0). Push and pull-request runs passed for
PR #2 on 2 September 2026, but no immutable repository evidence artifact captures those runs,
so they are observed external state rather than VERIFIED LIVE under this document's taxonomy.

---

## v0 defect register

Recorded, **not fixed** — these are product defects and Milestone 1 inputs, deliberately out
of scope for the R0 repository pass. Each is established by reading the code; none has a
captured failing run, so none is VERIFIED.

| # | Defect | Where | Consequence |
| --- | --- | --- | --- |
| D1 | `finish_shard` has no ownership check: `UPDATE shards SET state='done' ... WHERE id=?`, with no `AND lease_worker=?` and no state guard. `extend_lease:219` *is* guarded, so the inconsistency is inside one file. `/w/results` (`app.py:98-109`) and `heartbeat` (`db.py:285-295`) re-check nothing either. | `control/db.py:224-230` | A partitioned worker's buffered final post settles a shard another worker now holds. `outstanding()` reaches zero so every worker exits, while `status()["remaining"]` is still > 0 because it is ledger-derived. The stale settle also sets `lease_worker=NULL`, so `worker_has_lease(B)` is False and `controller.py:88-91` sorts lease-less workers to the front of the scale-down list — the controller preferentially kills the worker actually holding the work. The second failure is not independent; the system causes it. `controller.run` has no deadline-triggered break (`controller.py:51`), and the only writer of `status='done'` (`app.py:107-108`) itself requires `remaining == 0`, so the loop is genuinely unbounded — D1 drives D7's churn indefinitely, burning 10-minute increments behind a stuck job. The steady-state rate is `min_workers` relaunched per `FB_WORKER_STALE` cycle (~75-90s), **not** `LAUNCH_PER_TICK` per tick: once `rate_per_s` decays to 0, `controller.py:60` is False and `want = max(min_workers, n_live)`, so no launch happens until the last worker is reaped. `LAUNCH_PER_TICK` per tick is a transient, reachable only while the 120s rate window is still non-zero. The compound failure is conditional, not automatic: `put_results` has no ownership check either, so if no scale-down tick fires, B simply finishes and nothing goes wrong. The settle destroys the safety net; the controller's scale-down ordering is the most likely thing to spring it. Roadmap Milestone 1 hypotheses 1 and 4. |
| D2 | Billing rounds up by a full increment past the floor rather than to the ceiling: a worker alive exactly 10.0 minutes is billed 20. | `control/db.py:410` | Inflates `cost_per_1m_accepted`, which `fb.py:158` calls "the only number that goes in a quote". |
| D3 | The live `FB_TOKEN` is interpolated into the provider bootstrap body and uploaded via `startup_scripts.create`. | `providers/verda.py:30,60,106,112` | The control-plane bearer token is readable from the provider's control plane and the instance's own logs. |
| D4 | `fb serve` prints the live `FB_TOKEN` on startup. | `fb.py:46` | Any captured `serve` output leaks the token into a transcript or an artifact. |
| D5 | `GET /agent.py` and `GET /health` are unauthenticated. | `control/app.py:164-177` | The worker agent source is served to anyone who can reach the port. Compounded by `fb serve` defaulting to `0.0.0.0`. |
| D6 | `cmd_chaos` builds a fresh `LocalProvider` with an empty `procs` map, so `kill` falls through to `os.kill(int(instance_id))` on a PID read from the database. | `fb.py:130`, `providers/local.py:47-57` | If that worker already exited and the PID was recycled, an unrelated process is SIGKILLed — in the chaos flow, the sibling `fb serve` is a candidate. **Suspected, not observed.** |
| D7 | `max_workers` caps concurrency, not cumulative launches, and `LAUNCH_PER_TICK=2` runs every tick. | `controller.py:66-83` | A churn loop can bill many pre-paid 10-minute increments under a constant ceiling. |
| D8 | `/tmp/fb_demo.jsonl` is hard-coded. | `fb.py:183,185` | Two concurrent demo or chaos runs clobber each other's input. |
| D9 | Firmbatch records a worker dead on *requesting* a stop, never on confirming one. `db.kill_worker()` commits `state='dead'` and `stopped_ts`, then `provider.kill()` runs and its failure is swallowed — printed and discarded at `controller.py:49` and `:97`, and discarded **silently** by the bare `except Exception: pass` at `:115-116`, which is the shutdown path where nothing will ever retry. There is no `stop_requested`/`stop_confirmed` distinction and no reconciliation sweep. (The write ordering itself is correct — reversing it would gate the fast shard release behind a provider API call. The defect is the missing confirmation, not the order.) The **create** side is unrecorded too: `controller.py:77-79` calls `provider.launch()` before `register_worker()`, so a create that times out locally after succeeding remotely leaves an instance with no row at all — never killed, never in the ledger. | `controller.py:45-49,93-97,111-116`; `control/db.py:298-310,405-411` | A stop that failed or never arrived leaves the instance running while Firmbatch records it dead. `ledger()` then bills to `stopped_ts` (`db.py:407`), so real spend continues past the point the ledger stops counting and `cost_per_1m_accepted` is understated by an unbounded amount. Roadmap §5 invariants 12 and 16. |

---

## CURRENT — agent tooling

Established by the repository-initialization pass and its R0 remediation (see
`docs/adr/0001-agentic-repository-operating-model.md`).

| Item | State |
| --- | --- |
| `AGENTS.md` | Canonical instructions. `CLAUDE.md` imports it and adds Claude-only surfaces. Carries the guardrail's scope limits and the approval-required file list. |
| `scripts/verify-repository.sh` | The one verification entry point. **Sixteen** gates since Milestone 3.3b, which added the Terraform and delivery foundation gate (it fails rather than skips without the pinned Terraform) and **74 more `REQUIRED_FILES` entries, taking the manifest to 241**, with the human's explicit approval and no gate removed, reordered or weakened; its first correction pass (2026-09-14), at the human's instruction, added **15 more**, taking the manifest to **256**, and its second correction pass, with the human's explicit approval, added **one more** (`infra/terraform/bootstrap/delivery_policies.tf`), taking it to **257**, changing no gate, command or ordering. Before that, fifteen gates: fourteen since M2.1, unchanged by M2.2, M2.3, M2.4 and M3.1, and **one added by M3.2** — the customer-portal gate, which runs `npm run verify` in `portal/` (format, lint, types, tests, production build) and **fails rather than skips** when `npm` or `portal/node_modules` is absent, because an unrun test suite reports the same green as a passing one. Of the fourteen, the thirteenth checks that production code imports nothing outside the runtime lock, and the fourteenth runs the PostgreSQL foundation suite. Invoked identically by the human, the `verify` skill, and CI. No longer side-effect free: the last gate creates and drops one disposable database and, since M3.1, **five** per-run roles (owner, application, provisioning, authenticator, and the `NOLOGIN` lifecycle writer), and leaves the persistent `firmbatch_disposable_test_cluster` attestation marker in place. M2.4 changed it in two approved, narrow ways: **eleven more entries in `REQUIRED_FILES`** — nine with the milestone and two more with its third correction pass, taking the manifest to 97 files — and a header comment describing the then four-role test lifecycle. M3.1 changed it the same two ways, with the human's explicit approval: **twenty-two more `REQUIRED_FILES` entries**, taking the manifest to **119** files, so deleting any one of them fails the layout gate, and a header comment describing the five-role lifecycle. **M3.2 changed it in two approved, narrow ways**: **forty-eight more `REQUIRED_FILES` entries** — forty-seven with the milestone and one more with the independent review's corrections (`portal/src/lib/one-time-token.ts`), under the same approval — taking the manifest to **167** files, and the one new gate above. Through M3.1 no gate had been added; M3.2 adds one and removes, reorders and weakens none. |
| `.agents/skills/` | `verify`, `record-evidence`, `milestone`. Symlinked into `.claude/skills/`; single body each. |
| `.agents/policy/guard.py` | Shared deterministic policy engine, `--adapter claude` and `--adapter codex`. An accident-prevention guardrail, **not** a sandbox or security boundary. **Milestone 3.3b extended it, with the human's explicit approval (ADR 0012 decision 11):** every AWS CLI call but `aws --version` and help pages is refused, read-only calls included; Terraform is limited to `fmt`, `validate`, `version`, `providers lock` and `init -backend=false`, with the mocked tests run only through `infra/terraform/scripts/static-checks.sh`; registry login and push are refused; and writes under `docs/evidence/m3/aws-staging/` are refused until M3.3d. |
| `.agents/policy/test_guard.py` | **460** synthetic checks after Milestone 3.3b's third correction pass (2026-09-14; observed locally, no artifact), including the M3.3b cases for bounded Terraform, refused AWS CLI calls, registry pushes and M3.3 staging evidence; the second pass's wrapper-option, mutating `gh api` and `.exe`/OpenTofu/`aws2` spellings; and the third pass's `gh api` flag clusters, `find`/`tree` write options and GNU long-option prefixes. The progression, each an earlier local count kept as history: **247** before Milestone 3.3b; **315** at M3.3b's first full run (2026-09-13); **343** after the independent reviews' corrections; **408** after the second correction pass; **460** after the third, and current. |
| `.claude/settings.json` | Blocking `PreToolUse` hook over `Write\|Edit\|MultiEdit\|NotebookEdit\|Bash\|Read\|Grep\|Glob`. |
| `.codex/hooks.json` | Synchronous blocking `PreToolUse` hook over `shell\|local_shell\|apply_patch\|Edit\|Write`. Resolves the guard via `git rev-parse --show-toplevel`, so it works from any directory **inside** the work tree rather than only from its root. It is not fully cwd-independent: from outside the tree — including `/home/chams/src`, the parent directory `AGENTS.md` tells every command to run from — the substitution is empty and the hook blocks every action with empty stdout. See `docs/tasks/current.md`. |
| Reviewers | `distributed-systems-reviewer`, `test-evidence-reviewer`, `security-operations-reviewer`, defined for both agents. **Declared** read-only: `tools: Read, Grep, Glob` on Claude (Bash removed), `read_only = true` on Codex — though Codex is also granted `shell` and must honour the flag itself. Whether either harness enforces the declaration is NOT VERIFIED; see below. |
| `pyproject.toml` | Ruff config only — no packaging table, deliberately. Frozen per-file ignores for the three v0 files. Unchanged by M2.1: the parent-directory import contract is preserved and `control_plane/` passes the full rule set. |
| `requirements-v1.txt`, `requirements-v1-dev.txt` | Pinned v1 direct dependencies: SQLAlchemy 2.0.44, alembic 1.16.5, psycopg[binary] 3.2.10, pytest 8.4.2, ruff 0.16.5. Separate from the v0 `requirements.txt`; the two are never installed together by any gate. |
| `.github/workflows/ci.yml` | Calls `scripts/verify-repository.sh` exactly once. Checks out into `firmbatch/`; `permissions: contents: read`; runs a `postgres:16` service container; marks that container as a disposable test cluster in an explicit step; and installs **`requirements-v1-dev-lock.txt` with `--require-hashes`** — the fully resolved graph, never the unlocked input file. Its only credentials are the ephemeral container's test-only `postgres:postgres`. **M3.2 added two steps, with the human's explicit approval**: `actions/setup-node@v4` pinned to Node 24 LTS, and `npm ci` in `portal/`, which installs exactly the tracked `package-lock.json` and fails if the lock and the manifest disagree — the same property `--require-hashes` gives the Python locks. It still calls the verify script exactly once and re-spells no gate. **Milestone 3.3b added, with the human's explicit approval**, `hashicorp/setup-terraform` pinned by SHA to Terraform 1.15.8 for the new gate, `AWS_EC2_METADATA_DISABLED` on the verify job, and a separate `container` job written to build the production image with no registry login, push or AWS credential; that job has not yet run. |

---

## VERIFIED LIVE

Every row here has a captured artifact. Claims without one are in the next section.

| Claim | Evidence | Captured at |
| --- | --- | --- |
| v0 durability properties hold under the property tests: lease expiry and reaping, immediate release of a dead worker's shards, re-claim re-issues only unfinished requests, duplicate submissions do not double-count, and sub-increment worker life rounds up to one 10-minute increment. 14/14 checks pass. The billing check sleeps 0.05s and asserts `billed_h == 1/6`, which holds under correct ceiling rounding *and* under D2's floor-plus-one — it pins sub-increment behaviour, not the invoice invariant, and cannot fail on D2. | `docs/evidence/v0/v0-existing-property-tests.txt` — no provenance header; the artifact's own capture commit is not recoverable from the file. Committed at `1f83ff3`. | **HISTORICAL** at `1f83ff3`. `git log 1f83ff3..HEAD` over `control/ controller.py fb.py providers/ worker/ tests/` is empty, so the code under test is unchanged. |
| A 4,000-request local run completed 4,000/4,000 accepted across four workers, with three shards re-leased and re-issued correctly after their workers were released. Worker terminations recorded: one `job_complete`, three `scaled_down`. | `docs/evidence/v0/local-demo-001-report.txt`, `-reconciliation.json`, `-environment.txt` | **HISTORICAL.** Only `-environment.txt` carries a header, at `1952161`. The report and reconciliation were re-derived in place at `d0aeee2` and carry no header, so their capture commit is not recoverable from the files. Product code is unchanged across both commits. |
| Controller interruption behaviour before and after cleanup. | `docs/evidence/v0/accidental-controller-interruption-{before,after}-cleanup.txt` — no provenance headers; committed at `d0aeee2`. | **HISTORICAL** at `d0aeee2` |

**What the chaos artifact does not show.** The `local-demo-001-*` set was previously
described here as evidencing "three workers `SIGKILL`ed mid-flight, deadline met". It does
not. Every worker termination in it reads `job_complete` or `scaled_down`; there is no
`no_heartbeat` stop reason and no `lease.expired` event, and `no_heartbeat` is the only
record a preempted worker leaves (`controller.py:45`). `fb chaos` deliberately writes no kill
record, so the kill is visible only on stdout — which was not captured. No artifact contains
a deadline verdict either. What the run evidences is re-lease after a **controller-initiated**
release, which is the easy case; the unannounced-kill path is unevidenced. Corrected here per
the immutability rule rather than by rewriting the artifacts.

**On the v0 artifacts' provenance.** Five of the six files under `docs/evidence/v0/` carry no
`captured_at` / `database` / `python` / `commit` / `uname` header; only
`local-demo-001-environment.txt` does, and `local-demo-001-reconciliation.json` carries none
of the fields as keys. They predate the header standard. They are HISTORICAL evidence, not
invalid evidence, and they must not be rewritten to add a header — back-filling provenance
onto an unobserved run would be fabrication. Everything from R0 onward carries the header.

**Unexplained in-place correction.** Commit `d0aeee2` modified
`local-demo-001-report.txt` and `-reconciliation.json` in place. The rule that a wrong
artifact is corrected by capturing a new one was written *because* of that incident, and the
incident itself was never explained here. It is now.

---

## Asserted — artifact pending

Re-checkable claims with **no captured artifact**, and therefore **NOT VERIFIED** under this
repository's evidence standard. R0 and Milestone 0 are now committed; the remaining work is to
capture new artifacts with provenance matching the committed tree.

| Claim | How to settle it |
| --- | --- |
| All gates in `scripts/verify-repository.sh` pass — **sixteen** gates since Milestone 3.3b, over **257** required files since its second correction pass (2026-09-14; **256** after its first, **241** before it): **16 passed, 0 failed** at the 2026-09-13 run of the uncommitted M3.3b working tree over `86d4195` (241 files) and at the first correction pass's run (256 files). The second correction pass's edits came after both runs, which verify none of them. The third correction pass's canonical run on its final staged tree (staged-diff SHA-256 `7b93440739c6b6e7e860ed9c7b462cce8ff114377d325107d39d71ecd3284c17`), observed locally on 2026-09-14 with no artifact: **16 passed, 0 failed**, **257** required files — the current gate and manifest counts (the 241 and 256 above are historical). The fourth and fifth correction passes came after that run; **the final local canonical run**, on the finished tree committed as M3.3b implementation commit `cff27c8` (staged-diff SHA-256 `e6b90bc5efb35903bae89ef6f35933c9198a5a1ead2ee16788ccc66a1930dd0d`), observed locally on 2026-09-14 with no artifact: **16 passed, 0 failed**, **257** required files. All recorded in `docs/tasks/current.md` under M3.3b; **fifteen** gates over **167** required files from Milestone 3.2 to Milestone 3.3a, **15 passed, 0 failed** at the 2026-09-13 Milestone 3.3a run recorded at the end of this cell. The lineage, kept as history: at Milestone 2.4 there were **fourteen** gates, **14 passed, 0 failed**: layout (**119** required files since Milestone 3.1 registered its production and test modules; 97 at Milestone 2.4), agent configuration, hygiene, v0 property tests 14/14, `ruff check .` clean under the frozen per-file ignores, policy tests 247/247, the runtime import closure check, and the PostgreSQL foundation suite **1,746 collected — 1,745 passed, 1 skipped** locally — the one skip is the pre-existing REPLICATION skip (granting REPLICATION needs a superuser admin, which CI has and the developer cluster does not. On CI that test runs and two others skip instead -- the owner-only-refusal assertions, which have no meaning for a superuser bootstrap administrator). Observed locally on 2026-09-06, after all three correction passes, against PostgreSQL 16.15 on the developer's WSL machine, at Milestone 2.4 implementation commit `d91e4f2` — that suite count is HISTORICAL to that commit. **Re-run for Milestone 3.0** on 2026-09-06 at `main` `4511f7d`, twice — once with the rev D documentation changes uncommitted in the working tree, and again after the correction to rev D.1 with the documentation changes staged — against the same attested PostgreSQL 16.15 cluster: **14 gates passed, 0 failed** both times, 97 required files; the script's passing output does not print the foundation suite's collected/passed/skipped counts, so no new count is claimed here. Still no artifact. **Re-run for Milestone 3.1** on 2026-09-09 at implementation commit `f92ecb9`, against the same attested PostgreSQL 16.15 cluster: **14 gates passed, 0 failed**, with **119** required files in the layout gate, and no disposable database, role or session left behind. The foundation-suite figure current at that commit is the **2,038 collected — 2,037 passed, 1 environment-dependent REPLICATION skip** recorded in the Milestone 3.1 row below; the 1,746 above stays HISTORICAL to `d91e4f2`. **No milestone from M2.2 to M3.1 added a gate**; the foundation-suite gate already runs the whole `control_plane/tests` directory, so each of those milestones' new modules runs inside it. **Milestone 3.2 is the first since M2.1 to add one** — the customer portal is TypeScript and the foundation-suite gate cannot reach it — taking the count to **fifteen**; see the Milestone 3.2 row below. **Re-run for Milestone 3.3a** on 2026-09-13 at the working tree over `main` `ae61747`, with the documentation changes uncommitted, against the same attested PostgreSQL 16 cluster: **15 gates passed, 0 failed**, 167 required files; the passing output prints no suite counts, so none is claimed for this run. **Re-run after the M3.3a review corrections** the same day, at the corrected working tree before it was re-staged, against PostgreSQL 16.15 and Node 24.19.0: **15 gates passed, 0 failed**, 167 required files. Wording fixes prompted by the post-correction reviews, all in the eight M3.3a markdown files, came after that run. Still no artifact. | `/record-evidence` → `docs/evidence/r0/gates.txt` (and a Milestone 2 artifact for the foundation suite). Not yet captured. |
| The M2.1 tenant-isolation properties hold in PostgreSQL: absent context reads nothing and writes nothing; tenant A cannot read, insert, update or delete tenant B's rows; a fabricated cross-tenant or dangling foreign key is rejected; tenant context is not inherited from a session value, a pooled connection, or a URL option; a reused ORM `Session` cannot serve a previous tenant's object; a temporary relation cannot shadow a Firmbatch table; the application role is non-owner, `NOSUPERUSER`, `NOBYPASSRLS`, is refused at connect time if it were any of those, cannot disable a policy, cannot create tables or temporary tables, cannot read the schema history, and cannot create a tenant even with matching context; workspace uniqueness is tenant-local. | `/record-evidence` → `docs/evidence/m2/tenant-isolation-suite.txt`, after the Milestone 2.1 commit. Until then this is a re-runnable claim with no captured artifact. |
| The M2.2 idempotency and outbox properties hold in PostgreSQL: an identical retry returns the stored result and invokes the mutation once; four identical calls leave one workspace, one claim and one linked event; a conflicting reuse is rejected; two callers observed contending on a real lock commit one effect and one event, and the loser replays; a failure before commit leaves nothing and does not block the retry; a mutation callback cannot commit or roll back the primitive's transaction and an escape by any other route is detected; unflushed ORM state at entry is rejected; malformed operations and keys are refused before the mutation runs; the same key is independent between tenants; cross-tenant reads and writes on both new tables fail closed; missing context fails closed; a committed event is immutable to the application role and matches zero rows even for the owner; an internal state change appends an event with no idempotency record and a rollback removes both; and no value of the request identity reaches a row. **At M2.2 this was 511 passing checks with 1 skipped, of which 130 were new; the same properties are asserted at M2.3 inside a suite of 806.** | `/record-evidence` → `docs/evidence/m2/idempotency-outbox-suite.txt`, at or after Milestone 2.2 implementation commit `d362717`. Until then this is a re-runnable claim with no captured artifact, and M2.2 is **not** VERIFIED LIVE. |
| The M2.3 authenticated-context, authorization, audit and secrets properties hold in PostgreSQL: a forged `app.tenant_id` or any fabricated setting grants nothing; a fabricated tenant, binding id, fingerprint, actor or scope grants nothing; the function that writes a context is executable by nobody; a relation forged where the context lives is ignored because it is not owned by the schema owner; unknown, malformed, revoked and expired credentials fail closed with one indistinguishable message; binding twice or switching identity is refused; context survives no commit, rollback, failed statement, pool reuse or `Session` reuse, and a Connection-bound `Session` is refused; a valid credential reaches its own tenant and no other; the credential is never stored; authorization is deny-by-default with read/write scope distinctions, minimal framework capabilities and no non-customer scope; every `SECURITY DEFINER` function is owned, path-pinned, `PUBLIC`-revoked, minimally granted and free of dynamic SQL; the registry has no grants and no policy; audit events derive tenant and actor, refuse a supplied alternative, cannot be backdated, are immutable, roll back with their action and reject secret-shaped metadata; secrets never render themselves and production fails closed; and the migration reverses to the M2.2 shape and back. **1,314 pytest checks pass, 1 skipped**, a net increase of 803 collected checks over M2.2's 512 -- five new modules, plus every existing module moved onto the authenticated mechanism, plus a handful of M2.1 tests replaced by the stronger property that superseded them. | `/record-evidence` → `docs/evidence/m2/authenticated-context-suite.txt`, at or after Milestone 2.3 implementation commit `89fbdd9`. No evidence artifact has been captured, so this remains a re-runnable claim and M2.3 is **implemented and tested**, **not** VERIFIED LIVE. |
| The M2.4 lifecycle properties hold in PostgreSQL: a malformed definition is refused in Python and again by the schema; a registered version is immutable for the owner too; migration `0004` seeds no machine; an instance starts at revision zero in its machine's initial state and cannot be created elsewhere; its tenant, machine and version are immutable and its revision advances by exactly one; cross-tenant reads, writes and moves fail closed and produce the same refusal an invented id does; the required capability is read from the protected definition and a caller cannot name, lower or manufacture one; every declared edge can be taken and an undeclared one, a terminal source, a stale state and a stale revision each change nothing; one transition writes exactly one revision, history row, audit event and outbox intent, and a rollback removes all four; two callers racing from one revision with different idempotency keys produce one move, with the contention observed on `pg_stat_activity`; an identical retry replays and moves nothing; no runtime role may write either lifecycle table directly, register a machine, add an edge or call an internal reader; a grant or column grant on a definition table refuses the connection at connect time; and `0004` upgrades, downgrades and re-upgrades with exact role wiring at each revision. And, after the six-finding correction pass: a definition is invisible and unusable until it is published, cannot be published unless every one of its rows was written by the publishing transaction, and cannot be revised, unpublished or extended afterwards; a raw-SQL caller cannot commit a lifecycle move without its history row, audit event and outbox intent, and neither can a caller that catches the database's refusal; `mutation:execute` alone reads no lifecycle claim or event; two identical concurrent requests produce one move and two replays while a stale, cross-tenant or wrong-identity conflict still conflicts; a stale revision gets the common conflict rather than a graph diagnosis; and no unit-of-work method can be redirected to another `Session` operation. And, after the five-finding second pass: a replay is refused unless the protected provenance linking the claim, the transition, the instance, the revisions and the event checks out, so a fabricated generic claim carrying a plausible lifecycle result replays nothing; the operation name and the request fingerprint are derived inside PostgreSQL, so raw SQL cannot bind a claim to a request it did not make; `audit:read` alone reads no lifecycle audit row, its resource identifiers or its details; a hand-written `UPDATE` publishing a machine runs exactly the validation the supported function runs, a pre-published `INSERT` is refused, and publication and every child mutation serialise on one machine-row lock with the contention observed on `pg_stat_activity` and no deadlock; and a chosen primary key and a reserved-namespace claim are both refused before any index could answer whether a hidden row exists. And, after the two-finding third pass: a generic outbox link naming a hidden lifecycle claim and one naming an absent identifier are refused identically, before the foreign key, the one-event-per-claim index and the `ON CONFLICT` arbiter, in the plain and the `ON CONFLICT` forms; and every lifecycle-derived write — the three machine tags, the provenance row and the lifecycle outbox link — is refused to every identity but the dedicated `NOLOGIN` lifecycle writer, the schema owner's own DML and its own definer functions included, while migration `0003` stays untouched history and a database taken from head down to `0003` is catalogue-for-catalogue identical to one migrated freshly to it. **1,746 pytest checks are collected — 1,745 pass and 1 is skipped**, a net increase of 431 collected checks over M2.3's 1,315 — eight new modules plus new migration, rollback, catalogue, append-only, column-privilege, ownership, role-count and unit-of-work assertions in the existing ones. | `/record-evidence` → `docs/evidence/m2/lifecycle-state-machine-suite.txt`, **at or after Milestone 2.4 implementation commit `d91e4f2`**. No evidence artifact has been captured, so this remains a re-runnable claim and M2.4 is **implemented and tested**, **not** VERIFIED LIVE. |
| The M3.1 identity properties hold in PostgreSQL — the four `AUTH-MEMBERSHIP-BOUND-IDENTITY` cases and everything listed under "What M3.1 proves": **2,038 pytest checks collected, 2,037 pass, 1 environment-dependent REPLICATION skip** at implementation commit `f92ecb9` on 2026-09-09 — a net increase over M2.4's 1,746 that is the new modules, the extended migration, shape and protected-state assertions, and the correction passes' regression and concurrency coverage. The final independent review's focused verification of the same state passed **202 tests with no failures**, and the canonical verification passed all 14 gates over 119 required files. | `/record-evidence` → `docs/evidence/m3/identity-membership-suite.txt`, **at or after Milestone 3.1 implementation commit `f92ecb9`**. No evidence artifact has been captured and nothing is deployed, so this remains a re-runnable claim and M3.1 is **implemented, tested and independently reviewed**, **not** VERIFIED LIVE. |
| The M3.2 portal properties hold — everything listed under "What M3.2 proves": `./scripts/verify-repository.sh` reports **15 gates passed, 0 failed** with **167** required files; the PostgreSQL foundation suite is **2,188 passed, 1 environment-dependent REPLICATION skip** of 2,189 collected, a net increase of **151** over M3.1's 2,037 (four new modules — preferences and the mutation boundary, the password change and the account-plane lock order, the HTTP surface including the expected-workspace contract on every workspace route, and the migration's drift, hardening and restore checks); and the portal's own suite is **392 tests across 10 files**, run by the new gate together with `biome ci`, `tsc --noEmit` and a production `vite build`. Observed on 2026-09-12, after the independent review's eleven corrections, the centralised sign-out operation, the session lease on every route, the clean-context review's eight corrections and the final review's two P3 corrections, against the attested local PostgreSQL 16.15 cluster, on the code committed as implementation commit `ce097cb`; the canonical script re-run at `ce097cb` on 2026-09-13 reports the same **15 gates passed, 0 failed** over 167 required files; the 2026-09-09 figures (2,133 passed, 239 portal tests) and the 327 portal tests of 2026-09-11 are HISTORICAL to the earlier trees. The gate's fail-closed behaviour was checked rather than assumed: with `portal/node_modules` moved aside the portal gate fails and the script exits non-zero (the "13 passed, 2 FAILED" once recorded here included a foundation-suite failure from a `FIRMBATCH_TEST_DATABASE_URL` emptied in the same experiment; see the Milestone 3.2 section). | `/record-evidence` → `docs/evidence/m3/portal-suite.txt`, **at or after Milestone 3.2 implementation commit `ce097cb`**. No evidence artifact has been captured and nothing is deployed, so this remains a re-runnable claim and M3.2 is **implemented, tested and independently reviewed**, **not** VERIFIED LIVE. |
| The destructive-safety properties hold: a forged, altered, cross-server, or foreign-cluster teardown handle is refused and the database survives; an unattested server refuses both creation and teardown; a failure after creation removes the database and both roles; a generated password never reaches exception text, stdout, or stderr. Covered by `control_plane/tests/test_bootstrap_safety.py`. | Same artifact as the row above. |
| The shared policy engine denies the R0 accident classes across both adapter protocols — multi-line blocks classified line by line, `git -C`/`git -c`, `gh` and `aws` global options, `env`/`timeout` prefixes, `cd`/`cd -`/`pushd`/`popd`/`||` sequences, subshell grouping, argparse-abbreviated provider selection, evidence-tree ancestors including glob and `mv` forms, source and destination operands, in-place archivers, `git restore`/`checkout` over a path, credential reads on every surface including the `.env.*` family, wrapper- and prefix-depth exhaustion, unparseable input, unknown tool names carrying a payload, and engine exceptions. The synthetic check count, each value kept as history: **247** before Milestone 3.3b; **315** at Milestone 3.3b's first full run (2026-09-13), which adds bounded Terraform, refused AWS CLI calls (read-only included), refused registry login and push, and refused writes of M3.3 staging evidence; **343** after that milestone's independent reviews' corrections; **408** after its second correction pass (2026-09-14), which adds `timeout` and `env` wrapper options, mutating `gh api` spellings, and `.exe`, OpenTofu and `aws2` program names; and **460**, current, after its third correction pass (2026-09-14), which adds `gh api` flag clusters, `find`/`tree` write options and GNU long-option prefixes. The `.agents/policy/test_guard.py` row carries the same progression. | `/record-evidence` → `docs/evidence/r0/policy-tests.txt`, after the R0 commit. |

---

## NOT VERIFIED — do not claim

- **Any Milestone 3.3b behaviour outside a static check.** The Terraform has been validated and
  tested against mocked providers only; no plan, apply, IAM policy, bucket policy, S3
  conditional-write condition, workflow run, GitHub API read by the preflight job, or image build
  has happened. In particular it is unobserved whether the workflow token can read an
  environment's `can_admins_bypass` and `prevent_self_review` fields; if it cannot, the preflight
  refuses, failing closed. That assumption is assigned to M3.3d qualification with the others in ADR 0012
  "Still open". The CI `container` job has never run.

- **Three workers SIGKILLed in the v0 baseline, and the deadline being met.** Neither appears
  in any artifact. See above. `README.md` previously presented both as a captured result, in an
  "A real run looks like this:" block showing three SIGKILLs, a met deadline, six workers, and
  `$40.00` per million accepted — none of it in any artifact, against a captured figure of
  `$26.67`, and not verbatim output (it omitted fields `controller.py:101-107` prints). That
  block has been replaced with an evidence-accurate description that cites the three
  `docs/evidence/v0/` artifacts and marks unannounced-preemption recovery and the deadline
  verdict NOT VERIFIED.

  Counted-figure errors remain in `README.md` and are deliberately left, to keep this
  correction bounded to the evidence claims: `README.md:8` says "about 900 lines" (1,437),
  and the Layout block understates every module it lists — `control/db.py ~330` (434),
  `fb.py ~220` (259), `providers/verda.py ~150` (162), `tests/ ~110` (95, an overstatement),
  with `providers/base.py` (25) absent. The block's own figures already sum to roughly
  1,350, contradicting the "about 900" in the same file.
- **The real preemption path** — unannounced SIGKILL → missed heartbeat → `no_heartbeat` →
  re-lease — has never been captured. The corrected `--chaos` procedure in the `verify` skill
  is what would capture it.
- **That a stale worker cannot settle a live shard.** D1 says by inspection that it can. No
  failing test reproduces it yet.
- **That the reconciliation report is reproducible.** No script in the repository generates
  `local-demo-001-reconciliation.json`, and the database it derives from is gitignored.
- **Codex loading `.codex/hooks.json` and `.codex/agents/*.toml`** at runtime. Both adapter
  protocols pass synthetic tests; live discovery is unobserved.
- **A repository-captured CI result.** GitHub reported successful push and pull-request runs for
  PR #2, but no artifact under `docs/evidence/` captures their run IDs and output. Do not promote
  the result to VERIFIED LIVE until provenance is saved under the evidence procedure.
- **That the reviewer tool declarations are enforced by either harness.** Removing `Bash`
  from the three `.claude/agents/*.md` and keeping `read_only = true` on the Codex side makes
  the declaration correct, and `scripts/verify-repository.sh` gates both. It does **not**
  establish that the harness applies them. During the R0 remediation review, one dispatched
  `test-evidence-reviewer` reported that it had `Bash` available and `Glob` unavailable —
  the inverse of its own `tools:` line. That observation is unexplained and was not
  reproduced. Until it is, treat "read-only" as an instruction the reviewer follows, not a
  constraint the harness imposes, and do not rely on it to bound a reviewer's effects.
- **The guard's behaviour as a boundary.** It is an accident-prevention guardrail. Interpreters,
  `sudo`, `xargs`, `busybox`, subshells, command substitution, `eval`, and here-documents are
  outside its guarantee by decision. Do not describe it as a sandbox or a security control.
- **Verda SDK 1.24.1 conformance**, and anything about provider behaviour, real-GPU execution,
  cost, request-level accounting correctness, or pilot readiness. v0 has never been run against
  a real provider in this repository's recorded history.

**Resolved by the R0 audit** (previously listed here): Claude Code does resolve the
`.claude/skills/` symlinks — `verify` and `record-evidence` appear in the session skill
listing, and `milestone` is absent only because it sets `disable-model-invocation: true`.
The Claude `PreToolUse` hook is confirmed loaded and blocking, observed denying a
`credential-read` with the rule name intact.

---

## PLANNED

The canonical roadmap is `docs/firmbatch-v1-roadmap.md`, at architecture **revision D.1**
since Milestone 3.0; the pilot roadmap is superseded context, and the revision C sequence is
git history.

Milestone 0 and Milestone 1 are complete (Milestone 1 merged at `6b4f341`). **Milestone 2
is complete and merged**: M2.1 at `712b51a`, M2.2 at `b028f21`, M2.3 at `dca2d49`, and
M2.4 at `4511f7d` (PR #7, implementation commit `d91e4f2`).

**Milestone 2's declared implementation scope is complete.** Every item the canonical
roadmap lists under Milestone 2 — PostgreSQL migrations, tenant and workspace records, the
transactional outbox, audit events, tenant-scoped authorization, the secrets and encryption
model, the test and production configuration boundaries, the idempotent API mutation
framework, and explicit lifecycle state machines — is built and merged. The completion gate
was met by M2.1 and M2.2 and re-established by M2.3; what remained was scope rather than
gate, and M2.4 closed it.

That is a statement about the code, not about a deployment. Milestone 2 is **not
deployed**, and **nothing in Milestone 2 is VERIFIED LIVE**: no evidence artifact has been
captured for any of its four slices. Revision D.1 does not reopen it: later domain work
extends the foundation through new migrations, and `0001`–`0004` are history (ADR 0008).

### PLANNED — everything revision D.1 adds

Target revision D.1 (ADR 0008) is adopted and **none of it is implemented**: the purchased
supply class and its frozen `supplier_account` and `purchase_rate`; the platform bridge
envelope, enforced as gross accrued spend with reservations, usage replacement and invoice
reconciliation and reported net of invoiced billings; purchase records with an immutable
launch snapshot and append-only usage and invoice adjustments; measurement records and the
seven-day Gate 1 protocol; the price register loaded from `gpu_price_register_1.xlsx`;
cost-aware routing (`E[V]` per dollar) and measured throughput in the certification
registry; the Google, Azure, AWS and Verda spot drivers; the evaluation tier with its
per-tenant-per-corpus rule, its caps and its always-produced report; the internal
qualification tier; `auto_accept_below` with its comparison, currency and consent-binding
rules; `provider_policy` scoped to execution placement only; the usage basis per supply
class and per-request endpoint metering; the frozen-terms-versus-measured-outcomes split
on every attempt; the settlement canon's cause enum, revocation column, grouping parameter
and 90-day true-up on the dark settlement paths; node-level windows and multi-GPU
`execution_spec` fields; the firm tier redefined as a customer-named deadline of at least
24 and under 72 hours; and the phase triggers (Phase P, endpoint extension, Phase B).
The ten rev D review items are resolved by D.1 and recorded with their sources in
`docs/architecture/rev-d-decision-register.md`; what remains open there are configuration,
contract and measurement choices with named owners — the configured bridge caps, the
evaluation caps, the quote expiry, the corpus identity rule, the qualification allow-list,
per-contract settlement parameters, supplier-quoted rates, the model band, the staging
authorisation and the agent language — none of which blocks Milestone 3.

### PLANNED — `AUTH-MEMBERSHIP-BOUND-IDENTITY` (Milestone 3), and it blocks launch

The successor to the identity half of `AUTH-BOUND-TENANT-CONTEXT`, recorded under its own
name because the old one describes a gap that is now closed and would otherwise be read as
still open.

**What must become true.** An authenticated customer identity must be **proven to be an
active member of the selected workspace and tenant** before a browser session or an account
credential is issued for it. Today a credential *is* the membership: a binding names one
tenant, and the database will not issue a context for any other. That is sufficient while
credentials are provisioned out of band and there are no user accounts. It stops being
sufficient the moment a person can sign in and choose a workspace, because then something
has to decide which workspaces that person may choose from -- and nothing does yet.

**Why it is not M2.3's to close.** There are no users, no memberships, no invitations and
no sessions in this repository. Case 5 of the old completion gate asks what happens to an
authenticated non-member; with no membership model there is no such person to test. Writing
a partial one here would be the half-built capability ADR 0004 §8g argues against.

**Customer-facing deployment remains blocked** until Milestone 3 supplies identity,
membership and credential lifecycle together. This is the same blocking status the old task
carried, under a name that matches what is actually missing.

**Milestone 2's completion gate was satisfied before its scope was, and the distinction is
kept.** The gate — cross-tenant reads and writes fail closed in automated tests, **and**
duplicate mutations produce one contractual effect — was met by M2.1 and M2.2 together, and
M2.3 re-established the first half on a mechanism a compromised runtime cannot drive. The
milestone's declared scope is wider than its gate, and the last item of it — explicit
lifecycle state machines — is what M2.4 built. Milestone 2 is complete when its scope is, not
when the gate sentence is quotable.

**Milestone 3 is active.** M3.0, the revision D.1 documentation adoption, merged at
`116b5ee` (PR #8). **M3.1 — membership-bound identity, sessions and credential issuance — is
merged at `87159d5` (PR #9)**: signup, verification, recovery, browser sessions, workspace
membership and roles, and the trusted issuance path from a verified identity and an active
membership to
the protected M2.3 database context, with browser sessions distinct from scoped API
credentials (see "CURRENT — Milestone 3.1" and ADR 0009). The four completion cases pass as
named tests at the database and HTTP boundaries. **M3.2 — the customer-only portal — is
merged at `ae61747` (PR #10, implementation `ce097cb`)** (see "CURRENT — Milestone 3.2" and
ADR 0010): the authenticated customer application with honest empty states for later
features, the four gate cases now also exercised through the interface's own journeys, one
new tenant-plane relation for the customer's stated policy, and the signed-in password change
M3.1 left to it. **Customer-facing deployment stays blocked until an authorized M3.3d.**
**M3.3 is in progress as four slices (ADR 0011).** **M3.3a**, merged through PR #11 at `86d4195`, adopts the
AWS staging, Cognito and Terraform architecture — one customer origin,
`https://staging.app.firmbatch.com`, with the API same-origin under `/v1/*`; Cognito
authenticating behind a Firmbatch identity broker on `/auth/*` with no token in the browser;
an `(issuer, subject)` identity mapping bound explicitly by a manually invoked identity-binding task that holds only a dedicated one-function binding credential, and never by email; RDS PostgreSQL 16
with a managed-RDS qualification; Terraform in separate roots with an S3 lockfile backend;
OIDC delivery through two protected GitHub environments with saved plans kept out of GitHub — and records the **Cognito adoption decision**: Amazon Cognito owns
customer authentication (password, required TOTP, recovery and verification email in AWS
mode), while Firmbatch retains its server-side browser session, the CSRF cookie, workspace
authorization, row-level security, the audit trail, consent and API credentials. **M3.3b**,
the current slice, is implemented, statically tested and independently reviewed at `cff27c8`, awaiting
pull-request CI and merge — the Terraform and task
scaffolding, the container build and the fail-closed delivery structure, not operational until
M3.3c passes review (ADR 0012); **M3.3c**, next, builds every program that scaffolding runs — database
bootstrap, identity binding, the broker and its Cognito, JWT and KMS clients — with migration
`0008` (renumbered from `0007`, which the M3.3b password-hash correction took), the `__Host-fb_session` rename, the AWS-mode route changes, the portal adaptation,
the reviewed dependencies and lock files, and the security tests;
**M3.3d** — and only M3.3d, after a reviewed plan, a current cost estimate and the human's
explicit authorization — deploys, qualifies RDS, runs the browser journey and captures
evidence. **Nothing of M3.3 is deployed**: M3.3b's Terraform exists as scaffolding only, and no
AWS resource, plan, apply, image, deployment or evidence exists; M3.2 signs customers in through the M3.1 path; the customer can see the
real hosted portal only after M3.3d.

**The portal Milestone 3 builds is the customer application and nothing else.** The
**operator capacity agent remains separate operator-side software**: a static Rust or Go
binary installed in an operator's own cluster (target architecture §2 and §4.2), built in
**Phase P** when a supplier signs, with its language chosen by ADR then. It is not part of
the customer portal, and §17 invariant 11 — customer, internal-operator and supplier
permissions and interfaces remain separate — is why the two are not built as one surface.

Then, following the canonical sequence at revision D.1:

- Milestone 4: immutable quotes and contracts with `auto_accept_below`, the dormant firm
  contract, the evaluation allowance, billing and payment projection in sandbox, and the
  bridge budget and price model.
- Milestone 5: native JobSpec with `provider_policy` and `movable_to_shared`, the
  tenant-scoped presigned payload path, the evaluation and paid flows — and the **actual job
  lifecycle**, whose machine definition is registered there, alongside the job tables it
  describes. M2.4 registered none.
- Milestone 6: fenced attempts, validator/canonicalizer, the three ledgers, spend and bridge
  enforcement, the first purchased driver (Google Cloud spot) with **admitted, capped,
  human-authorized internal qualification jobs** and Gate 1 measurements, measured pricing
  and cost-aware admission and routing, the remaining VM drivers, and the firm, window and
  operator-statement paths built and tested dark — and **window offers, attempts, leases
  and execution state**, whose machine definitions are registered there for the same reason.
- Milestone 7: the evaluation journey and the paid flex journey, end to end in staging.
- Milestone 8: production deployment and the Phase 0 release; read-replica routing, which
  is what would lift the writable-primary-only limitation M2.3 named and M2.4 inherits.
- Phase P, the endpoint extension and Phase B follow their own triggers (target §15.4).

Real-provider qualification and a real-GPU slice remain unverified, separately authorized
work. They were not prerequisites for the Milestone 1 audit gate or for Milestone 2, they
are not prerequisites for Milestone 3, and they must not be run implicitly. Under
revision D.1 the first billable execution is Milestone 6.2's, behind admission, caps,
credentials and a human's specific authorization of each run.
