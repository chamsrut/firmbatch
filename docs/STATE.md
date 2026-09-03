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

Last updated: 2026-09-03, at `main` merge commit `6b4f341` (Milestone 1), plus
Milestone 2.1 on `feat/milestone-2-foundation`, delivered by PR #4: implementation
commit `521870b` (with its review-hardening pass) and the bootstrap trust-boundary
correction introduced in `78eae1d` (see the CI correction section below).

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
| `control_plane/tests/` | **382 pytest checks** against real PostgreSQL 16, in nineteen modules: configuration boundary, settings separation, connection specification, connection environment, migrations, migration entry points, version preflight, tenant isolation, isolation hardening, bind forms, ownership boundary, admin escalation, bootstrap safety, bootstrap lifecycle, connection identity, destructive safety, verification reporting, role privileges, plus the shared conftest. They **fail rather than skip** when the server, the attestation, or `FIRMBATCH_TEST_DATABASE_URL` is absent, and refuse any PostgreSQL major version other than 16. |
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
working contract forbids.

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

### The tenant-context limitation, and what it blocks

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

### What the 381 passing tests establish, and what they do not

They establish **implemented and tested** behaviour on a locally provisioned PostgreSQL 16
server, in a database created and destroyed by the run. They are **NOT VERIFIED LIVE** under
this document's taxonomy: no artifact under `docs/evidence/` captures the run, no RDS instance
exists, and nothing is deployed. Do not cite the test count as deployment proof.

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
| `scripts/verify-repository.sh` | The one verification entry point. **Fourteen** gates as of M2.1 — the thirteenth checks that production code imports nothing outside the runtime lock, and the fourteenth runs the PostgreSQL foundation suite. Invoked identically by the human, the `verify` skill, and CI. No longer side-effect free: the last gate creates and drops one disposable database and **three** per-run roles (owner, application, provisioning), and leaves the persistent `firmbatch_disposable_test_cluster` attestation marker in place. |
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
| All **fourteen** gates in `scripts/verify-repository.sh` pass: layout (67 required files), agent configuration, hygiene, v0 property tests 14/14, `ruff check .` clean under the frozen per-file ignores, policy tests 247/247, the runtime import closure check, and the PostgreSQL foundation suite 381/381 (1 skipped locally: granting REPLICATION needs a superuser admin, which CI has and the developer cluster does not. On CI that test runs and two others skip instead -- the owner-only-refusal assertions, which have no meaning for a superuser bootstrap administrator). Observed locally on 2026-09-03 against PostgreSQL 16.15 on the developer's WSL machine. | `/record-evidence` → `docs/evidence/r0/gates.txt` (and a Milestone 2 artifact for the foundation suite), after the commit. |
| The M2.1 tenant-isolation properties hold in PostgreSQL: absent context reads nothing and writes nothing; tenant A cannot read, insert, update or delete tenant B's rows; a fabricated cross-tenant or dangling foreign key is rejected; tenant context is not inherited from a session value, a pooled connection, or a URL option; a reused ORM `Session` cannot serve a previous tenant's object; a temporary relation cannot shadow a Firmbatch table; the application role is non-owner, `NOSUPERUSER`, `NOBYPASSRLS`, is refused at connect time if it were any of those, cannot disable a policy, cannot create tables or temporary tables, cannot read the schema history, and cannot create a tenant even with matching context; workspace uniqueness is tenant-local. 381/381 pytest checks pass, 1 skipped. | `/record-evidence` → `docs/evidence/m2/tenant-isolation-suite.txt`, after the Milestone 2.1 commit. Until then this is a re-runnable claim with no captured artifact. |
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
active; its first slice, M2.1, is implemented and tested above and awaits human review and
commit.

The remaining Milestone 2 slices are PLANNED and not started:

- **M2.2** — idempotent API mutation framework and the transactional outbox: idempotency
  records keyed per tenant, duplicate mutations producing one contractual effect, conflicting
  reuse rejected, and state change plus outbox event committed in one transaction.
- **M2.3** — audit events, tenant-scoped authorization, and the secrets/encryption model,
  including binding tenant context to an authenticated credential rather than to a caller-set
  setting. Until that exists, the isolation boundary is bounded as described in ADR 0004.
- **M2.4** — explicit lifecycle state machines with conditional transitions that cannot race.

Milestone 2's completion gate — cross-tenant reads and writes fail closed in automated tests,
**and** duplicate mutations produce one contractual effect — is **not** satisfied: M2.1
delivers the first half only.

Then, following the canonical sequence:

- Milestone 3: customer accounts, workspaces, permissions, credentials, and portal shell.
- Milestone 4: quotes, commercial records, payment projection, and billing interface.
- Milestone 5: native JobSpec and tenant-scoped S3 payload path.
- Milestone 6: fenced attempts, validator/canonicalizer, providers, routing, spend, and ledgers.

Real-provider qualification and a real-GPU slice remain unverified, separately authorized work.
They were not prerequisites for the Milestone 1 audit gate, they are not prerequisites for
Milestone 2, and they must not be run implicitly.
