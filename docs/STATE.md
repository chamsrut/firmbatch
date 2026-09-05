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

Last updated: 2026-09-05, at `main` merge commit `b028f21` (Milestone 2.2, PR #5), plus
Milestone 2.3 on `feat/milestone-2-3-auth-audit-secrets`, **implemented, tested, reviewed
and awaiting merge**, after four independent security reviews whose twenty-three findings
are all corrected (see the four correction-pass sections below). Milestone 1 merged at
`6b4f341`; M2.1 merged at `712b51a` (implementation
commit `521870b`, with the bootstrap trust-boundary correction `78eae1d` — see the CI
correction section below); M2.2 merged at `b028f21` (implementation commit `d362717`).

**M2.3 is at implementation commit `89fbdd9`.** The branch carries it and nothing has been
pushed or merged; the human pushes and merges. Wherever this document says "at M2.3", it
means the state of that commit.

---

## CURRENT — Milestone 0 documentation baseline

Milestone 0 aligns repository guidance with revision C of the approved v1 target architecture:

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

The third slice of Milestone 2, on `feat/milestone-2-3-auth-audit-secrets`, delivered by
implementation commit `89fbdd9` and **reviewed, awaiting merge**. It closes the gap M2.1
named and M2.2 left standing: a transaction no longer chooses its tenant, it presents a
credential and is told which tenant it got.

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
| `scripts/verify-repository.sh` | The one verification entry point. **Fourteen** gates since M2.1, unchanged by M2.2 and M2.3 — the thirteenth checks that production code imports nothing outside the runtime lock, and the fourteenth runs the PostgreSQL foundation suite. Invoked identically by the human, the `verify` skill, and CI. No longer side-effect free: the last gate creates and drops one disposable database and **three** per-run roles (owner, application, provisioning), and leaves the persistent `firmbatch_disposable_test_cluster` attestation marker in place. |
| `.agents/skills/` | `verify`, `record-evidence`, `milestone`. Symlinked into `.claude/skills/`; single body each. |
| `.agents/policy/guard.py` | Shared deterministic policy engine, `--adapter claude` and `--adapter codex`. An accident-prevention guardrail, **not** a sandbox or security boundary. |
| `.agents/policy/test_guard.py` | 247 synthetic checks. |
| `.claude/settings.json` | Blocking `PreToolUse` hook over `Write\|Edit\|MultiEdit\|NotebookEdit\|Bash\|Read\|Grep\|Glob`. |
| `.codex/hooks.json` | Synchronous blocking `PreToolUse` hook over `shell\|local_shell\|apply_patch\|Edit\|Write`. Resolves the guard via `git rev-parse --show-toplevel`, so it works from any directory **inside** the work tree rather than only from its root. It is not fully cwd-independent: from outside the tree — including `/home/chams/src`, the parent directory `AGENTS.md` tells every command to run from — the substitution is empty and the hook blocks every action with empty stdout. See `docs/tasks/current.md`. |
| Reviewers | `distributed-systems-reviewer`, `test-evidence-reviewer`, `security-operations-reviewer`, defined for both agents. **Declared** read-only: `tools: Read, Grep, Glob` on Claude (Bash removed), `read_only = true` on Codex — though Codex is also granted `shell` and must honour the flag itself. Whether either harness enforces the declaration is NOT VERIFIED; see below. |
| `pyproject.toml` | Ruff config only — no packaging table, deliberately. Frozen per-file ignores for the three v0 files. Unchanged by M2.1: the parent-directory import contract is preserved and `control_plane/` passes the full rule set. |
| `requirements-v1.txt`, `requirements-v1-dev.txt` | Pinned v1 direct dependencies: SQLAlchemy 2.0.44, alembic 1.16.5, psycopg[binary] 3.2.10, pytest 8.4.2, ruff 0.16.5. Separate from the v0 `requirements.txt`; the two are never installed together by any gate. |
| `.github/workflows/ci.yml` | Calls `scripts/verify-repository.sh` exactly once. Checks out into `firmbatch/`; `permissions: contents: read`; runs a `postgres:16` service container; marks that container as a disposable test cluster in an explicit step; and installs **`requirements-v1-dev-lock.txt` with `--require-hashes`** — the fully resolved graph, never the unlocked input file. Its only credentials are the ephemeral container's test-only `postgres:postgres`. |

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
| All **fourteen** gates in `scripts/verify-repository.sh` pass — **14 passed, 0 failed**: layout (**86** required files since Milestone 2.3 registered thirteen), agent configuration, hygiene, v0 property tests 14/14, `ruff check .` clean under the frozen per-file ignores, policy tests 247/247, the runtime import closure check, and the PostgreSQL foundation suite **1,314 passed, 1 skipped** locally — the one skip is the pre-existing REPLICATION skip (granting REPLICATION needs a superuser admin, which CI has and the developer cluster does not. On CI that test runs and two others skip instead -- the owner-only-refusal assertions, which have no meaning for a superuser bootstrap administrator). Observed locally on 2026-09-05 against PostgreSQL 16.15 on the developer's WSL machine, at Milestone 2.3 implementation commit `89fbdd9`. **Neither M2.2 nor M2.3 added a gate**; the foundation-suite gate already runs the whole `control_plane/tests` directory, so the new modules run inside it. | `/record-evidence` → `docs/evidence/r0/gates.txt` (and a Milestone 2 artifact for the foundation suite). Not yet captured. |
| The M2.1 tenant-isolation properties hold in PostgreSQL: absent context reads nothing and writes nothing; tenant A cannot read, insert, update or delete tenant B's rows; a fabricated cross-tenant or dangling foreign key is rejected; tenant context is not inherited from a session value, a pooled connection, or a URL option; a reused ORM `Session` cannot serve a previous tenant's object; a temporary relation cannot shadow a Firmbatch table; the application role is non-owner, `NOSUPERUSER`, `NOBYPASSRLS`, is refused at connect time if it were any of those, cannot disable a policy, cannot create tables or temporary tables, cannot read the schema history, and cannot create a tenant even with matching context; workspace uniqueness is tenant-local. | `/record-evidence` → `docs/evidence/m2/tenant-isolation-suite.txt`, after the Milestone 2.1 commit. Until then this is a re-runnable claim with no captured artifact. |
| The M2.2 idempotency and outbox properties hold in PostgreSQL: an identical retry returns the stored result and invokes the mutation once; four identical calls leave one workspace, one claim and one linked event; a conflicting reuse is rejected; two callers observed contending on a real lock commit one effect and one event, and the loser replays; a failure before commit leaves nothing and does not block the retry; a mutation callback cannot commit or roll back the primitive's transaction and an escape by any other route is detected; unflushed ORM state at entry is rejected; malformed operations and keys are refused before the mutation runs; the same key is independent between tenants; cross-tenant reads and writes on both new tables fail closed; missing context fails closed; a committed event is immutable to the application role and matches zero rows even for the owner; an internal state change appends an event with no idempotency record and a rollback removes both; and no value of the request identity reaches a row. **At M2.2 this was 511 passing checks with 1 skipped, of which 130 were new; the same properties are asserted at M2.3 inside a suite of 806.** | `/record-evidence` → `docs/evidence/m2/idempotency-outbox-suite.txt`, at or after Milestone 2.2 implementation commit `d362717`. Until then this is a re-runnable claim with no captured artifact, and M2.2 is **not** VERIFIED LIVE. |
| The M2.3 authenticated-context, authorization, audit and secrets properties hold in PostgreSQL: a forged `app.tenant_id` or any fabricated setting grants nothing; a fabricated tenant, binding id, fingerprint, actor or scope grants nothing; the function that writes a context is executable by nobody; a relation forged where the context lives is ignored because it is not owned by the schema owner; unknown, malformed, revoked and expired credentials fail closed with one indistinguishable message; binding twice or switching identity is refused; context survives no commit, rollback, failed statement, pool reuse or `Session` reuse, and a Connection-bound `Session` is refused; a valid credential reaches its own tenant and no other; the credential is never stored; authorization is deny-by-default with read/write scope distinctions, minimal framework capabilities and no non-customer scope; every `SECURITY DEFINER` function is owned, path-pinned, `PUBLIC`-revoked, minimally granted and free of dynamic SQL; the registry has no grants and no policy; audit events derive tenant and actor, refuse a supplied alternative, cannot be backdated, are immutable, roll back with their action and reject secret-shaped metadata; secrets never render themselves and production fails closed; and the migration reverses to the M2.2 shape and back. **1,314 pytest checks pass, 1 skipped**, a net increase of 803 collected checks over M2.2's 512 -- five new modules, plus every existing module moved onto the authenticated mechanism, plus a handful of M2.1 tests replaced by the stronger property that superseded them. | `/record-evidence` → `docs/evidence/m2/authenticated-context-suite.txt`, at or after Milestone 2.3 implementation commit `89fbdd9`. No evidence artifact has been captured, so this remains a re-runnable claim and M2.3 is **implemented and tested**, **not** VERIFIED LIVE. |
| The destructive-safety properties hold: a forged, altered, cross-server, or foreign-cluster teardown handle is refused and the database survives; an unattested server refuses both creation and teardown; a failure after creation removes the database and both roles; a generated password never reaches exception text, stdout, or stderr. Covered by `control_plane/tests/test_bootstrap_safety.py`. | Same artifact as the row above. |
| The shared policy engine denies the R0 accident classes across both adapter protocols — multi-line blocks classified line by line, `git -C`/`git -c`, `gh` and `aws` global options, `env`/`timeout` prefixes, `cd`/`cd -`/`pushd`/`popd`/`||` sequences, subshell grouping, argparse-abbreviated provider selection, evidence-tree ancestors including glob and `mv` forms, source and destination operands, in-place archivers, `git restore`/`checkout` over a path, credential reads on every surface including the `.env.*` family, wrapper- and prefix-depth exhaustion, unparseable input, unknown tool names carrying a payload, and engine exceptions. 247 synthetic checks pass. | `/record-evidence` → `docs/evidence/r0/policy-tests.txt`, after the R0 commit. |

---

## NOT VERIFIED — do not claim

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

The canonical roadmap is `docs/firmbatch-v1-roadmap.md`; the pilot roadmap is superseded context.

Milestone 0 and Milestone 1 are complete (Milestone 1 merged at `6b4f341`). Milestone 2 is
active. Its first slice, M2.1, is merged at `712b51a`; its second, M2.2, at `b028f21`; its
third, M2.3, is implemented and tested above at commit `89fbdd9` and **reviewed, awaiting
merge**.

The remaining Milestone 2 slice is PLANNED and not started, and is the next planned slice:

- **M2.4** — explicit lifecycle state machines with conditional transitions that cannot race.

Milestone 2 remains active until M2.4 is completed.

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

**Milestone 2's completion gate is satisfied and the milestone is still open.** The gate —
cross-tenant reads and writes fail closed in automated tests, **and** duplicate mutations
produce one contractual effect — was met by M2.1 and M2.2 together, and M2.3 re-establishes
the first half on a mechanism a compromised runtime cannot drive. The milestone's declared
scope is wider than its gate: of the items listed under Milestone 2 in the canonical
roadmap, audit events, tenant-scoped authorization and the secrets and encryption model are
now built, and **explicit lifecycle state machines are not**. Milestone 2 is complete when
its scope is, not when the gate sentence is quotable.

Then, following the canonical sequence:

- Milestone 3: customer accounts, workspaces, permissions, credentials, and portal shell.
- Milestone 4: quotes, commercial records, payment projection, and billing interface.
- Milestone 5: native JobSpec and tenant-scoped S3 payload path.
- Milestone 6: fenced attempts, validator/canonicalizer, providers, routing, spend, and ledgers.

Real-provider qualification and a real-GPU slice remain unverified, separately authorized work.
They were not prerequisites for the Milestone 1 audit gate, they are not prerequisites for
Milestone 2, and they must not be run implicitly.
