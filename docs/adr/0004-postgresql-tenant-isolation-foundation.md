# ADR 0004: PostgreSQL tenant isolation is enforced by the database

- **Status:** Accepted
- **Date:** 2026-09-02
- **Decision owners:** Firmbatch product owner and maintainers
- **Milestone:** 2.1, the shared product foundation
- **Related:** `docs/architecture/v1-target-architecture.md` sections 3.1 and 17;
  `docs/architecture/v0-to-v1-migration-audit.md` section 10; ADR 0003

## Context

Target invariant 2 is that every tenant-owned row, credential, and object key is
tenant-scoped, and the Milestone 2 completion gate is that cross-tenant reads and writes
fail closed in automated tests. v0 has no tenancy at all: one shared `FB_TOKEN`, no
`tenant_id` column anywhere, and a SQLite store (`control/db.py:26-92`).

The obvious implementation is a `tenant_id` column plus a `WHERE tenant_id = ?` clause in
every repository method. That is a convention, not a boundary. It holds exactly as long
as every query, every join, every ad-hoc report, and every future contributor remembers
it, and it fails silently and invisibly when one does not — the failure is a query that
returns *more* rows, which no test asserts against unless it was written for that purpose.

This foundation carries every later milestone: jobs, quotes, attempts, ledgers, and S3
keys all inherit whatever isolation model is chosen here. Getting it wrong later means
retrofitting a boundary underneath live commercial records.

## Decision

### 1. PostgreSQL row-level security is the isolation mechanism

Both tenant-scoped tables have RLS **enabled and forced**, with one `FOR ALL` policy
comparing the row's tenant column against a transaction-local setting:

```sql
CREATE POLICY workspaces_tenant_isolation ON workspaces
  FOR ALL TO PUBLIC
  USING      (tenant_id = app_current_tenant_id())
  WITH CHECK (tenant_id = app_current_tenant_id());
```

`FORCE` is the half that matters. `ENABLE` alone exempts the table owner, which would
mean the isolation tests pass while the owner connection reads everything.

`tenants` is scoped by its own primary key (`id = app_current_tenant_id()`): a tenant row
is visible to exactly the tenant it is.

The repositories in `control_plane/db/repositories.py` deliberately contain **no**
`WHERE tenant_id = ...` clause. A reader can verify the claim by noticing there is no
filter to get wrong.

### 2. Tenant context is a transaction-local PostgreSQL setting

`app.tenant_id`, set through `set_config(..., is_local => true)` — parameterisable, which
`SET LOCAL` is not, so a UUID-validated value is bound rather than interpolated.

- **Absence fails closed.** Unset, `app_current_tenant_id()` returns NULL, every policy
  predicate is NULL, reads match nothing and writes are rejected.
- **Context cannot outlive its transaction.** `SET LOCAL` is discarded at COMMIT or
  ROLLBACK, and SQLAlchemy's pool rolls back on check-in. A pooled connection handed to
  the next request carries nothing from the last one.
- **Context is never inherited.** Every transaction opens by clearing `app.tenant_id` to
  empty *before* applying what the caller asked for, and the setting is cleared again on
  every new pooled connection. Transaction-local is not the same as absent: a plain `SET`
  (not `SET LOCAL`) executed earlier on a pooled connection, or an
  `options=-c app.tenant_id=...` smuggled into a connection URL, is a **session** value
  that `current_setting` returns quite happily to a transaction that set nothing. Both
  were reproduced against a real server before this baseline existed, and both are now
  regression-tested with a one-connection pool.
- `set_tenant_context` refuses to run outside a transaction, where `SET LOCAL` would
  apply to one statement and then silently vanish — appearing to work and leaving the
  next statement unscoped.

### 2a. The ORM identity map is cleared whenever the context changes

SQLAlchemy answers `session.get()` from its identity map without consulting the database,
so a `Session` reused across a tenant switch returned the previous tenant's object with
PostgreSQL never asked and the policy never evaluated. Reproduced against a real server;
the strong reference matters, because the identity map holds weak references and a test
that dropped the object would pass for the wrong reason.

Any change of tenant context — including clearing it — now calls `expunge_all()`. Objects
the caller already holds become detached with their loaded attributes intact; what they
lose is the ability to be served again without a query. Re-reading under a legitimate
context still works, which is tested (A → B → A).

### 2c. A savepoint may not change the tenant

The tenant context is fixed for the lifetime of an outer transaction. `set_tenant_context`,
`clear_tenant_context` and `reset_tenant_context` all refuse inside a `SAVEPOINT`.

The reason is a PostgreSQL fact that cannot be papered over from Python: rolling a
savepoint back restores the outer `SET LOCAL` value, but **releasing** one does not. A
switch made inside a savepoint that commits leaves the outer transaction genuinely running
as the other tenant. And on the rollback path, PostgreSQL restores the setting while
SQLAlchemy keeps the objects — an object loaded under tenant B stayed in the identity map
and was served after the rollback, with the policy never re-evaluated. Both were measured.

A second, independent guard covers callers who bypass this module and set the GUC by raw
SQL: an `after_transaction_end` listener empties the identity map whenever any savepoint
ends on an engine this package built — rollback, commit, or exception. It is registered on
the `Session` class rather than on sessions created by our helpers, because a
hand-constructed `Session(bind=engine)` is the case a contributor is most likely to write,
and scoping it narrowly is how the gap was found in the first place.

### 2b. The connected principal is verified, not assumed

Nothing in a URL says whether the role it names is a superuser. A connection string
carrying `postgres:postgres@` and one carrying `firmbatch_app:...@` are the same shape,
so **comparing URL strings cannot establish this**. Every new pooled application
connection is asked, against the live catalogue, whether its identity holds any of the
capabilities the runtime profile forbids — `SUPERUSER`, `BYPASSRLS`, `REPLICATION`,
`CREATEDB`, `CREATEROLE` — or owns a tenant-scoped table, or is a member of any role that
does. `pg_has_role(..., 'MEMBER')` covers both inherited privilege and reachability by
`SET ROLE`.

Ownership is disqualifying because an owner can `ALTER TABLE ... NO FORCE ROW LEVEL
SECURITY`. `REPLICATION` is disqualifying because **row-level security has no bearing on
the WAL**: a role that can open a replication connection can stream the entire cluster,
every tenant included, without executing a single `SELECT`. `CREATEROLE` is a route to the
others. The check enforces the whole profile this ADR promises, not the two attributes that
happen to be the most obvious.

**The authenticated identity is `session_user`, not `current_user`.** A privileged login
can preselect a restricted role at startup (`?options=-c role=firmbatch_app`); PostgreSQL
then reports the restricted role as `current_user` while the privileged identity remains
`session_user`, one `RESET ROLE` away. Measured: the check pronounced such a connection
safe while the authenticated identity was the table owner. It now issues `RESET ROLE`
first, requires `current_user` and `session_user` to agree afterwards, requires
`session_user` to be the role the URL named, and runs every privilege, ownership and
membership test from both identities.

The check runs on **every new connection and again on every pool checkout**, not once at
startup: role attributes and memberships change while a connection sits idle, and a
connection accepted hours earlier went on serving DML after its role was granted ownership
of a tenant-scoped table — measured. A failed checkout invalidates the connection rather
than returning it to the pool. An inspection that cannot complete is a failure, not a pass,
and a connection that fails at connect is closed rather than leaked.

The cost is two catalogue queries per checkout. That is deliberate: the alternative is a
window, of unbounded length, in which a role that has stopped being safe keeps serving
tenant-scoped queries.

### 2e. One explicit identity, one explicit endpoint

Rejecting dangerous parameters is not sufficient on its own, because libpq also *fills in*
what a URL omits — from `PGUSER`, `PGHOST`, `PGPORT`, `PGDATABASE` — and accepts *several*
hosts in one URL, choosing among them at connect time. An omitted field is an
environment-supplied field; a host list is a connection that may not be the same one twice.

So a URL is parsed into a canonical `ConnectionSpec` in which every field is required and
singular: one username, one database, one endpoint (a hostname and numeric port, or an
absolute socket directory and numeric port), no commas anywhere, and no second endpoint
hiding in the query. The connection is then **rebuilt from the spec**, so what was
validated and what is opened are the same object by construction. The same spec is used for
database swapping, fingerprinting and the expected-user check.

The cost is that a previously working URL without an explicit port is now refused. That is
the intended trade: the port it was silently using came from `PGPORT` or a compiled-in
default, which is precisely the ambiguity being removed.

### 2f. Migrations run on the connection that was validated

The bootstrap used to probe one connection and let Alembic open another from the same URL.
Two physical connections: DNS, a failover endpoint, or a load balancer can put the second
on a different cluster than the one just checked, and the DDL would land there.

Alembic is now handed the already-open connection through its programmatic `connection`
attribute, and `env.py` re-validates that exact connection immediately before the first
DDL — database, cluster system identifier, endpoint, and authenticated principal. The same
check runs again immediately before the grants, on the same connection. Database-name-only
validation is not enough, and validating a *different* connection is not validation at all.

### 2d. A URL may not carry connection parameters that redirect it

libpq reads connection parameters from the query string as well as from the URL, and they
win. `postgresql://u@/postgres?dbname=customer_prod` validates as `postgres` and connects
to `customer_prod`; measured. The same trick redirects the server (`host`, `hostaddr`,
`port`), the role (`user`), the entire connection definition (`service`, `servicefile`),
and the session (`options`, which can preselect a role, unpin `search_path`, or set the
tenant context before any application code runs).

So connection parameters are governed by an **allowlist**, not a denylist: libpq gains
parameters over time and a denylist would silently stop covering them. `host` is permitted
only in the unix-socket shape — an absolute path, and only when the URL names no host.

Because the URL is still only a claim, the server is asked to confirm it: after connecting
through a maintenance URL, `current_database()` must be a maintenance database; before
migrations and before grants, it must equal the disposable database just created.

### 3. Three roles, and no runtime role can bypass RLS

| Role | Holds | Under RLS |
| --- | --- | --- |
| Owner / migration | Schema ownership, DDL, migrations | Yes — `FORCE` applies to the owner too |
| Application | `SELECT` on `tenants`; full DML on `workspaces` | Yes |
| Provisioning | `SELECT, INSERT, UPDATE` on `tenants`; **nothing** on `workspaces` | Yes |

All three are `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, `NOBYPASSRLS`. The application
role is not the table owner, cannot disable or drop a policy, cannot create tables, and
cannot read `alembic_version`.

Privileged provisioning is distinguished by one grant, not by an exemption. Creating
tenant X still requires the context of tenant X, because the `WITH CHECK` on `tenants` is
self-referential — so even the provisioning role cannot write a row into another tenant's
scope.

### 4. Role grants are not in the migration

Role names differ per environment and per disposable test database. Putting them in a
migration would either hard-code an environment into the schema history or make that
history non-deterministic. The migration is role-agnostic (`TO PUBLIC`); grants live in
`control_plane/db/roles.py` and are applied by the test bootstrap and, in production, by
an explicit operator step.

### 5. Tenant-local uniqueness, and a composite key for future child tables

Workspace slugs and names are unique **within** a tenant, never globally. A global unique
index would leak the existence of another tenant's names through a constraint violation,
and would let the first tenant to claim `production` deny it to everyone else.

Every tenant-owned table also carries a `UNIQUE (id, tenant_id)`. PostgreSQL performs
referential-integrity checks with row security **bypassed**, so a plain
`REFERENCES workspaces(id)` on a future child table would happily point across tenants.
Child tables from M2.2 onward carry their own `tenant_id` and reference
`(workspace_id, tenant_id)` against this key, which makes tenant consistency a database
fact rather than a code review.

### 5a. A dedicated schema, and three defences against relation shadowing

Firmbatch v1 metadata lives in a `firmbatch` schema, never in `public`, and every
relation, foreign key, migration operation, raw statement, and the Alembic version table
is schema-qualified.

This is a security property, not tidiness. PostgreSQL searches the session's **temporary
schema before `search_path`** when resolving a relation name, so any role holding the
default `TEMP` privilege can run `CREATE TEMP TABLE workspaces (...)` and have every later
unqualified reference on that connection read the forgery instead — silently, for the life
of a pooled connection, with row-level security attached to a table the query never
reaches. This was reproduced against a real server: an unqualified `SELECT` with no tenant
context returned the forged row.

Three independent measures, because one of them is always the one that gets refactored
away:

1. Everything is schema-qualified.
2. Connections are pinned to `search_path = firmbatch, pg_catalog, pg_temp` at connect
   time — `pg_temp` named explicitly and **last**, which is what stops it being searched
   first.
3. `TEMP` is revoked from PUBLIC on the database and granted to no runtime role.

### 5b. Nothing is inherited from a PostgreSQL default

PUBLIC loses `CREATE` on every schema, `TEMP` on the database, `EXECUTE` on
`app_current_tenant_id()`, and all table privileges; each runtime role is then granted back
only what it needs. Defaults change between major versions and differ between a stock
server and a hardened one, so a grant that is only correct because of a default is a grant
that is only correct here. In particular, the tenant-context helper is not left on
PostgreSQL's default of `EXECUTE TO PUBLIC`.

### 6. UUID keys, timezone-aware timestamps, PostgreSQL only

UUID primary keys defaulted server-side with `gen_random_uuid()`, so a row inserted from
`psql` obeys the same rule as one inserted through the ORM. `timestamptz` everywhere: a
naive timestamp in a system whose product is a deadline is a defect waiting for a
daylight-saving boundary.

`control_plane/config.py` rejects any non-PostgreSQL URL. There is no SQLite fallback and
none may be added — PostgreSQL is the single metadata authority (target architecture 3.1),
and a fallback backend is how that decays into "PostgreSQL unless something else is
configured".

### 7. Configuration is explicit and carries no production default

`FIRMBATCH_ENV` must be stated (`test` or `production`); there is no default environment.
Application and migration URLs are separate variables, so the privilege split is a
configuration fact rather than a convention. No URL is committed anywhere — not in
`alembic.ini`, not as a module constant — and a test scans the package to keep it that
way. Everything that renders a URL for a human redacts the password first.

### 8. Tests run against real PostgreSQL 16 and fail rather than skip

The properties under test — forced policies, role attributes, referential integrity,
transaction-local settings — have no faithful in-memory substitute, so there is no fake
and no fallback. The suite bootstraps a `firmbatch_test_<12 random hex>` database and
throwaway roles from an admin maintenance URL, migrates it, and drops it. PostgreSQL 16 is
required and checked; another major version fails the run rather than reporting a green
that says nothing about the target.

When the server is absent the gate **fails**. A skipped isolation suite reports the same
green as a passing one, and "cross-tenant access fails closed" is precisely the kind of
claim this repository's evidence rules say may not rest on an unobserved run.

### 8a. A server must attest that it is disposable

A URL ending in `/postgres` is not evidence of anything: every PostgreSQL cluster has that
database, production included. A copied environment variable, a stale shell, or a tunnel
left open is enough to aim `CREATE DATABASE` and `DROP DATABASE` at something real.

A server is treated as disposable only if it carries a marker somebody created on purpose:
a `NOLOGIN` role `firmbatch_disposable_test_cluster` whose comment is exactly
`firmbatch-disposable-test-cluster`. Checked before any create **and** again before any
drop.

A role with a comment was chosen because it must be creatable by a non-superuser with
`CREATEROLE` (the local WSL setup) and by the superuser in a CI service container;
readable without superuser rights (`pg_roles` is readable, `pg_authid` is not);
cluster-wide rather than per-database, since the bootstrap creates databases; and
impossible to arrive at by accident. A custom GUC would have been the obvious choice but
needs `ALTER SYSTEM` or a config edit, which the local non-superuser admin cannot do.

CI marks its own ephemeral container in an explicit, visible step. That satisfies the check
rather than weakening it — the container is created and destroyed by the job.

### 8b. Teardown does not trust its handle

`handle.database` is not authority to drop a database. Before any `DROP DATABASE` the
teardown requires: the name is not a protected database; the name and every URL match the
disposable conventions; the handle is internally consistent (the database named in the
handle is the one its migration URL points at, and every URL names it); every runtime URL
is at the endpoint recorded when the roles were created; the server is still attested; the
admin connection is a maintenance connection; the live cluster fingerprint
(`system_identifier`) matches the one recorded at creation; and the handle was produced by
this process and has not been altered since — compared field by field against what was
recorded, because `dataclasses.replace` preserves an opaque token.

Writing these tests found a real gap: the first endpoint cross-check used
`inet_server_port()`, which is NULL on a unix-socket admin connection, so a handle whose
URLs pointed at two different servers passed unnoticed and the real database was dropped.
The endpoint is now recorded at creation and compared against that.

A failure anywhere after the database and roles exist — including during migration or
grant configuration, not only during a normal fixture teardown — removes them before
re-raising, and reports any cleanup problem without masking the original error.

### 8c. Generated passwords never reach a log

Role passwords are composed with psycopg literal quoting rather than f-string
interpolation, and every exception raised out of role provisioning is scrubbed of them
before it propagates. psycopg echoes the failing statement, so a `CREATE ROLE ... PASSWORD
'...'` that failed would otherwise put a live password into CI output that is retained for
as long as the run is. Verified: the password was present in the exception text before the
scrubbing existed.

## What this does not claim

**RLS bounds a query, not a compromised control plane.** The application role can set
`app.tenant_id` to any value it likes. What RLS guarantees is that *given* a context, no
query — including one with a forgotten or wrong `WHERE` clause, a bad join, or an ad-hoc
report — reaches another tenant's rows. It does not guarantee that the control plane
chose the right context. Binding the context to an authenticated API credential is
M2.3/M3 work; until then the credential-to-tenant resolution is not implemented and must
not be described as if it were.

**Passing tests are not deployment proof.** Under this repository's taxonomy the
behaviour here is implemented and tested, not VERIFIED LIVE. Nothing is deployed, no RDS
instance exists, and no evidence artifact has been captured for this milestone.

## Consequences

- Later Milestone 2 tables inherit a boundary that is already enforced, and a table added
  without a policy fails the suite instead of quietly becoming readable across tenants.
- Every environment needs three roles provisioned before the control plane can start.
  That is deliberate operational friction: a single all-powerful connection string is the
  shape this ADR exists to prevent.
- Local development and CI both need a real PostgreSQL 16 server. There is no
  zero-dependency way to run the foundation suite, and adding one would mean testing
  something other than the property claimed.
- Migrations and role wiring are two separate steps, so a deploy runbook must include
  both.

## Rejected alternatives

### 8d. Objects are identified by OID and provenance marker, not by name

A database or role can be dropped and recreated under the same name between creation and
teardown. Measured: teardown destroyed a same-name replacement. Every object created is
therefore recorded as `(name, kind, oid, marker)` — the marker a random string written as a
`COMMENT` at creation — and re-checked at the moment of each drop. An object that is
absent, replaced, or inconsistent is left alone and reported.

Objects are tracked **individually and only on success**. A `CREATE ROLE` that collides
with an existing role aborts setup and never records that role as created, so cleanup
cannot remove a role that merely shares a generated name. Normal teardown and failed-setup
cleanup run the *same* validated path: attestation, cluster fingerprint, maintenance
database, name, provenance and per-object identity are checked either way. If that
validation cannot complete, the objects are **leaked deliberately** and reported rather
than dropped on a weaker check — the failure mode that costs a leaked test database is
strictly better than the one that costs somebody else's.

### 8e. Deletion is bound to an identity, and the residual is named

`DROP DATABASE` **cannot run inside a transaction** in PostgreSQL 16. Any check-then-drop
sequence therefore has a window between the two, and no amount of care closes it. Claiming
otherwise would be the kind of statement this repository exists to avoid.

What *is* evaluated atomically is PostgreSQL's own permission check, against the object
present at the instant the statement runs. So the deletion is bound to an identity:

* Each run creates a dedicated owner role, `firmbatch_test_own_<suffix>`. It owns the
  database and the schema, and it is the migration principal.
* The final `DROP DATABASE` is issued **as that role**, over its own connection, not with
  the ambient cluster-admin authority that created it. A same-name replacement owned by
  anybody else fails the ownership check and survives — verified.
* **The temporary owner membership is given back.** `CREATE DATABASE ... OWNER` needs the
  creator to be able to `SET ROLE` to the new owner, so the bootstrap takes that membership
  for exactly one statement and gives it back in a `finally` — with `INHERIT FALSE,
  ADMIN FALSE`, because a plain grant leaves an inheriting row behind after
  `REVOKE SET OPTION FOR`. The revoke is verified on a **new** admin session, against
  `pg_auth_members` directly, including a recursive walk for indirect paths; bootstrap fails
  rather than leave an explicit standing grant nobody asked for on somebody's cluster.

  That check is deliberately **catalogue-only**. It does not ask `pg_has_role`, and it does
  **not** require the bootstrap administrator to be unable to reach the owner. §8f states
  why: the administrator is trusted, CI runs it as a superuser, and a superuser satisfies
  `pg_has_role(..., 'SET'/'USAGE')` for every role in the cluster no matter what is
  revoked. Requiring the opposite made bootstrap fail on exactly the cluster shape this ADR
  describes. Verified live on a *non-superuser* administrator: afterwards it gets `must be
  owner of database` for `COMMENT`, `ALTER ... CONNECTION LIMIT`, `ALTER ... RENAME` and
  `DROP DATABASE`. Removing the creator's `ADMIN OPTION` row is not attempted —
  PostgreSQL 16 does not allow it, and §8f states the consequence.
* **Nothing is altered before it is identified.** Revoking `CONNECT` and terminating
  backends are destructive to a running system, and they used to run by name on the admin
  connection *before* any OID or provenance check. They now run as the owner, after the
  target's OID, marker and live `datdba` have been re-read on that same connection — so a
  replacement owned by somebody else has its grants, its connection limit and its live
  sessions all left untouched. Verified with a live session on a replacement.
* No `FORCE`, anywhere, and it must not be introduced. `FORCE` requires the privileges of
  the roles whose backends are being terminated, which means broadening this role rather
  than narrowing it. The owner clears the backends itself, using membership in the two
  runtime roles — a strictly narrower grant. If it cannot, the database is **left in place
  and reported**: a safe leak is the correct outcome, and an operator must not widen
  teardown authority to make cleanup pass.
* Roles are removed by **rename, re-verify, drop** inside one transaction. The rename takes
  the lock and the OID is re-read after it, so what is dropped is provably the object that
  was validated; a concurrent recreation gets the original name, which the transaction is
  no longer referring to.
* OID, provenance marker, attestation, endpoint and cluster fingerprint checks all remain.
  They catch the ordinary case with a clear message; the privilege check is what holds
  under a race.

**The threat boundary, stated precisely.** These measures defeat: a concurrent test process
in this or another checkout; a stale or edited handle; a database or role replaced under
the same name by any non-superuser, *including a non-superuser shared admin that created
it*; and a mistyped `FIRMBATCH_TEST_DATABASE_URL`.

A **superuser** remains outside it, and that is accepted rather than eliminated. A
superuser can drop the disposable database and recreate one with the same name owned by the
per-run owner role, between the validation and the DROP, and the DROP would then remove it.
PostgreSQL offers no lock or statement that closes this: `DROP DATABASE` cannot participate
in a transaction, and there is no drop-by-OID. This is not hypothetical — **CI's bootstrap
administrator is the `postgres` superuser** of an ephemeral `postgres:16` service container
— and it is exactly why the boundary is drawn where §8f draws it: the administrator is
trusted, and it is confined to `TestBootstrapSettings` and to a cluster that has explicitly
attested it is disposable. A shared cluster with untrusted superusers is not a place to run
this suite, and the attestation marker is the control that says so.

### 8f. The bootstrap administrator is trusted, and confined rather than constrained

An earlier revision of this section treated the shared admin's reach into the per-run owner
as a **blocker**: it asked for the *entire* owner-role membership to be revoked, ADMIN
included, and bootstrap refused to return a handle unless
`pg_has_role(admin, owner, 'SET')` and `(..., 'USAGE')` were both false. That was the wrong
boundary, and it was wrong in a way that showed up as a CI failure rather than as an
argument:

> `DisposableDatabaseError: the shared admin can still reach the per-run owner (pg_has_role
> reports SET and USAGE)`

CI's bootstrap administrator is the `postgres` **superuser** of an ephemeral `postgres:16`
service container. A superuser satisfies `pg_has_role` for every role in the cluster by
definition, so the assertion was unsatisfiable on the very cluster shape this ADR
prescribes — and it was asserting a property the architecture never promised.

**The boundary this design actually draws.**

* The bootstrap administrator is **trusted**. It is reachable only through
  `TestBootstrapSettings`, and only against a cluster carrying the
  `firmbatch_disposable_test_cluster` attestation (§8a).
* **CI** runs it as the `postgres` superuser inside an ephemeral service container created
  and destroyed by the job. **Local verification** runs it as a non-superuser `CREATEROLE`
  administrator on an explicitly attested disposable cluster. Both are inside the boundary.
* PostgreSQL administrative reachability into the per-run roles is **accepted inside that
  boundary**, and nowhere else. Nothing here claims the administrator is isolated from the
  roles it creates.
* **Customer and runtime roles remain untrusted and separated.** The per-run owner,
  application and provisioning roles hold no `SUPERUSER`, `CREATEDB`, `CREATEROLE`,
  `BYPASSRLS` or `REPLICATION`; none of them can reach the administrator; and the
  application and provisioning pair cannot reach the migration owner. That separation is
  what forced RLS rests on, and it is asserted identically in CI and locally.

**What is asserted at bootstrap, and what is not.** Asserted, catalogue-only: the `SET`
membership taken for one statement is given back, so no explicit `set_option` or
`inherit_option` row survives on any direct or indirect membership path where PostgreSQL
permits revoking it. That is hygiene — an explicit standing grant nobody asked for is state
this bootstrap would be leaving behind — and it is true of a superuser and a non-superuser
administrator alike. Not asserted: anything from `pg_has_role`, which answers about
effective authority and cannot be revoked away from a superuser.

**PostgreSQL 16's own limitation, for a non-superuser administrator.** When a non-superuser
`CREATEROLE` role creates a role, the creator receives a `pg_auth_members` row whose
**grantor is the bootstrap superuser**, carrying `admin_option`, and cannot remove it. All
three spellings were tried against a real server:

| Attempt | Result |
| --- | --- |
| `REVOKE owner FROM CURRENT_USER` | `WARNING: role "admin" has not been granted membership in role "owner" by role "admin"` — the row survives |
| `REVOKE ADMIN OPTION FOR owner FROM CURRENT_USER` | the same warning, the same outcome |
| `REVOKE owner FROM CURRENT_USER GRANTED BY postgres` | `ERROR: permission denied to revoke privileges granted by role "postgres"` |

That row carries `ADMIN` and neither `SET` nor `INHERIT`, so it passes the catalogue check
and stays — which is what it must do: it is what lets a non-superuser administrator
`DROP ROLE` the three per-run roles at teardown. Removing it, if that were possible, would
trade an accepted property for a guaranteed leak of three roles per run. A superuser
administrator receives no such row at all; PostgreSQL 16 grants the creator `ADMIN` only
when the creator is not a superuser.

`control_plane/tests/test_admin_escalation.py` pins all of this: bootstrap completes under
either kind of administrator; no revocable membership row carries `SET` or `INHERIT`; the
per-run roles gain no administrative attribute and no route into the administrator or into
the owner; the administrator's credentials appear in no runtime URL; and the PostgreSQL 16
limitation above is asserted for a non-superuser administrator and skipped, with a stated
reason, for a superuser. It contains no test asserting that the escalation works.

The suite's own cleanup helper re-acquires `SET` by re-granting it, which is the honest
demonstration that this reach is understood and accepted rather than hidden.

### 8g. What this isolation does and does not protect against

Milestone 2.1 buys a specific, real thing, and it is worth being exact about its shape
rather than letting "tenant isolation" carry more weight than it can.

**The interim Milestone 2.1 guarantee — structural isolation.**

* Forced row-level security applies to `tenants` and `workspaces`. `FORCE` binds the table
  owner too, so there is no role for which the policies are advisory.
* A missing `WHERE tenant_id = ...` in application code does not expose another tenant. The
  filter is in the database, not in the query the developer remembered to write.
* A transaction with no context fails closed: reads return nothing, writes are rejected.
* Pooled connection state and ORM identity maps do not carry one tenant's rows into
  another's transaction — the connection is re-hardened on checkout and the identity map is
  emptied at every transaction and savepoint boundary.
* The application credential and the migration credential are separate, and the runtime
  process cannot load the privileged one (see §8h).
* **The application service is a trusted setter of tenant context.**

That last line is the boundary. It is what the design assumes, not what it enforces.

**What it does not protect against.** The runtime role can execute
`set_config('app.tenant_id', <any uuid>, true)`. Row-level security then evaluates
faithfully against whatever tenant it was told. So an attacker who obtains the runtime
database credential, or who reaches arbitrary SQL through an injection flaw, can select any
tenant they can name. RLS is doing its job in that scenario; the job is simply not the one
that stops it. This defends against *mistakes* — a forgotten filter, a stale pooled
connection, an ORM cache — and not against a compromised runtime credential.

That is an acceptable place for a shared product foundation to stand. It is **not** an
acceptable place from which to serve customers.

**The final customer-facing v1 guarantee**, which remains unchanged and is not yet met:

* the runtime service cannot select an arbitrary tenant UUID;
* tenant and workspace context is derived from a verified customer credential rather than
  from a caller-supplied identifier;
* the database trusts an opaque or signed capability, or a protected mapping, rather than a
  raw `app.tenant_id` any holder of the connection may set;
* the runtime process does not hold the authority to mint a capability for an arbitrary
  workspace;
* a leaked runtime database credential, or SQL injection, cannot select another tenant;
* **customer-facing deployment is blocked until this is implemented and tested.**

Closing that gap is deliberately not attempted here. A partial mechanism — a convention, a
second GUC, an application-side check — would look like the property without being it, and a
half-built capability is worse than a documented absence because it stops people asking.
The work is tracked as **`AUTH-BOUND-TENANT-CONTEXT`** in Milestone 3, with the adversarial
tests that must pass before it can be called done. See `docs/firmbatch-v1-roadmap.md`
Milestone 3 and `docs/STATE.md`.

No test in this repository asserts that the current limitation exists. A passing test whose
subject is a vulnerability reads as a specification for it, and would have to be deleted
rather than fixed when the capability lands. The ADR, `docs/STATE.md` and the blocking task
carry it instead.

### 8h. Runtime and privileged credentials are separated by type

There is no settings object that carries both the runtime URL and a privileged one, and no
loader that returns both. Three types, three loaders, one environment variable each:
`ApplicationSettings`, `MigrationSettings`, `TestBootstrapSettings`.

The combined `Settings` this replaced was wrong twice. It made an application process
unable to start without a migration URL in its environment — backwards, since the runtime
is the one deployment that must never hold owner credentials. And it *handed* the
privileged URL to every caller, wanted or not: a credential that reaches a process is a
credential that can leak from it, into a traceback, a repr, a crash dump, a log line. The
cheapest way not to leak the owner password from the API server is for the API server never
to have been told it.

`ApplicationSettings.__repr__` renders no URL at all, not even a redacted one. Everything
else in this package redacts and keeps the host, because knowing which environment a
traceback came from is worth something; here it is not worth a rendering path that is one
refactor away from including the password again.

The module boundary that goes with it is enforced statically, as its own verification gate:
runtime modules may not import the migration entry point or the test bootstrap, and may not
reach for a privileged loader. `create_migration_engine` moved out of `db/engine.py` into
`migrate.py` for exactly this reason — a module an API server imports should not be able to
construct an owner engine. Prose about a credential is still allowed: `db/principal.py`
tells an operator to use `FIRMBATCH_MIGRATION_DATABASE_URL` for privileged work, which is
advice, not access.

There is deliberately no compatibility wrapper. A shim would reintroduce the coupling
quietly, which is worse than reintroducing it loudly.


### Repository-level `WHERE tenant_id = ?` only

Rejected. It is a convention every future query must honour, its failure mode is silent
and returns more data rather than less, and it offers nothing against an ad-hoc query, a
reporting job, or a psql session.

### A `BYPASSRLS` role for provisioning and background work

Rejected. It would make the boundary conditional on which connection string a process
happened to pick up, which is the failure mode forced RLS exists to remove. Provisioning
is separated by one narrow grant instead, and remains fully under policy.

### Schema-per-tenant or database-per-tenant

Rejected for v1. It complicates migrations (N schemas to keep in step), connection
pooling, and cross-tenant operator queries, and it buys isolation this design already
gets from forced policies. Revisit only if a customer contract requires physical
separation of metadata — the execution plane already isolates per tenant (target
architecture 4.1).

### Putting role creation and grants in the Alembic migration

Rejected. Role names are environment-specific; embedding them makes the schema history
either environment-coupled or non-deterministic, and both break the property that the
migration tests prove is the same migration an operator applies.

### Keeping the tables in `public`

Rejected once the temporary-schema shadowing path was demonstrated. `public` is the schema
an unqualified name is most likely to resolve through, and pinning a dedicated schema makes
both the qualification and the `search_path` control obvious rather than conventional.

### Trusting the application URL to name an unprivileged role

Rejected. It is unverifiable from the string, it is exactly the mistake that turns forced
RLS into decoration, and asking the server costs two catalogue queries per connection.

### Treating a `/postgres` admin URL as sufficient evidence for a disposable server

Rejected after asking what would actually stop a mistyped variable from dropping a real
database, and finding the answer was "nothing". An explicit server-side marker is the
smallest thing that cannot happen by accident.

### Pinning only direct dependencies

Rejected. Exact pins on three packages leave the rest of the closure floating, so CI can
resolve a transitive version the suite was never run against. The hash-pinned lock is
generated from this project's own inputs with `pip-compile --generate-hashes`, never from
a `pip freeze` of an unrelated environment.
