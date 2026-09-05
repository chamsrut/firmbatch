# ADR 0006: tenant context is what a credential proves, not what a caller asks for

- **Status:** Accepted
- **Date:** 2026-09-04, revised 2026-09-05 after two independent security reviews
- **Decision owners:** Firmbatch product owner and maintainers
- **Milestone:** 2.3, authenticated tenant context, tenant-scoped authorization, audit
  events, and the secrets/encryption model
- **Related:** `docs/architecture/v1-target-architecture.md` sections 2.1, 3.1, 14 and
  invariants 2 and 11; `docs/firmbatch-v1-roadmap.md` Milestone 2 and
  `AUTH-BOUND-TENANT-CONTEXT`; `docs/architecture/v0-to-v1-migration-audit.md` sections 6
  and 10; ADR 0003; ADR 0004 (especially §8g); ADR 0005

## Context

ADR 0004 built structural tenant isolation and was explicit about what it did not build:

> The application role can set `app.tenant_id` to any value it likes. What RLS guarantees
> is that *given* a context, no query reaches another tenant's rows. It does not guarantee
> that the control plane chose the right context.

That is a sound place for a shared foundation to stand and an unsound place from which to
serve customers. The gap was tracked as **`AUTH-BOUND-TENANT-CONTEXT`**, it blocks
customer-facing production launch, and this ADR is what closes it for the database and
runtime boundary Milestone 2 owns.

Three further pieces of Milestone 2's declared scope arrive with it, because they are the
same decision seen from different sides. **Tenant-scoped authorization** is meaningless
without an authenticated tenant to scope it to. **Audit events** are worthless unless
"who acted" is derived rather than asserted. And the **secrets and encryption model** is
what says where a bearer credential may be stored, which is the first question the
authentication design has to answer.

## Decision

### 1. A transaction acquires context by presenting a credential, and by no other route

Four pieces, and none of them works without the others.

**A protected credential registry.** `firmbatch.auth_bindings` maps a one-way SHA-256
fingerprint of a bearer credential to one tenant, one principal, and one set of scopes,
with optional expiry and a revocation timestamp. `REVOKE ALL ... FROM PUBLIC`, and
`db/roles.py` grants **nothing** on it to any runtime role — so no connection can read it,
write it, or discover whether a row exists.

**A protected transaction-scoped context.** `firmbatch.auth_context_begin` — a
`SECURITY DEFINER` function that **no role may execute** — writes one row into
`firmbatch.auth_transaction_context`, an unlogged table in the pinned schema keyed by the
backend's pid and carrying the `xid8` of the transaction that wrote it. No role but the
schema owner holds any privilege on it. `firmbatch.auth_context()` reads a row back only
when its `xact_id` equals `pg_current_xact_id_if_assigned()`.

**One way in.** `firmbatch.bind_authenticated_context(credential)` hashes what it is
given, looks the digest up, refuses an unknown, revoked or expired binding, and otherwise
establishes the context. It takes no tenant, no principal, no binding id and no scope from
the caller. The only input is a 244-bit secret — two `gen_random_uuid()` values, 122
random bits each. (The standalone Python generator in `security/secrets.py` uses 32 random
bytes and so carries 256 bits. Both render as the same 43 URL-safe characters, and the 43
is the rendering rather than the measurement. The two numbers are different and are written
down as they are; the roadmap asks for high entropy, and 244 bits is high entropy.)

`firmbatch.begin_tenant_provisioning()` is the one other entry, for the path that creates a
tenant before any credential for it can exist. It takes **no arguments** and generates the
tenant id itself — see decision 4.

**Policies that read the context.** Every policy on every tenant-owned table is replaced,
and `firmbatch.app_current_tenant_id()` is **dropped**. Setting `app.tenant_id`, or any
other custom setting, now buys nothing.

### 2. Why the context is a protected table keyed by the transaction id

**This decision was made twice.** The first version put the context in
`pg_temp.firmbatch_auth_context` with `ON COMMIT DELETE ROWS`, on the reasoning that a
temporary table owned by another role is a store the caller cannot write and PostgreSQL
scopes to a transaction. The second half of that was true. The first was not, and the way
it failed is worth the space.

**`DISCARD TEMP` drops every temporary table in the session, including one owned by
somebody else.** It is legal for any role, requires no privilege, and there is nothing to
revoke. Measured: the application role ran `DISCARD TEMP` inside an authenticated
transaction, the context vanished, and `bind_authenticated_context` then accepted a
*second* credential — so one transaction could act as two tenants and commit both. The
ownership check the design leaned on did not help, because the relation was never forged;
it was destroyed. `firmbatch.auth_context_reset()`, this package's own clearing function,
did the same thing more politely.

So the store had to be somewhere `DISCARD` does not reach, which means an ordinary table,
which means finding a different source of transaction scoping. That source is the
transaction id itself:

* a row written by transaction T is invisible to every other transaction until T commits;
* once T has committed, its id can never equal a future `pg_current_xact_id()`;
* a rollback removes the row like any other uncommitted write.

So `firmbatch.auth_context()` reads a row only when `xact_id =
pg_current_xact_id_if_assigned()`, and a committed row grants nothing to anybody, ever.
**Nothing clears it, because nothing needs to — and, decisively, because there is no
operation that could.** `reset_auth_context` is gone from Python and
`auth_context_reset()` from the database.

Three details carry the rest:

* **`pg_current_xact_id_if_assigned` in the reader, not `pg_current_xact_id`.** The second
  *assigns* a transaction id, and the reader runs inside every policy predicate on every
  read. A read-only transaction that consumed an xid per query would be spending the
  wraparound budget to answer "who are you". NULL means nothing wrote a context, which
  fails closed.
* **One row per backend pid, replaced in place.** The table is bounded by the pid space and
  never grows, so there is no pruning job and nothing to schedule. The pid is only the key;
  the *authority* is the `xact_id`, so a row left by a backend whose pid was reused is
  simply replaced.
* **`UNLOGGED`.** Every row is dead the moment its transaction ends, so a crash that
  truncates the table destroys nothing that survived the crash — and the WAL it would
  otherwise write on every authenticated request buys nothing.

The cost is one upsert per authenticated transaction. That is the trade the first design
was avoiding, and it was not worth what it cost.

### 2a. Binding once, and what a savepoint may and may not do

The writer's `ON CONFLICT (backend_pid) DO UPDATE ... WHERE existing.xact_id <>
excluded.xact_id` is the whole of "a transaction binds once": if the row already carries
this transaction's id the update matches nothing, and the function raises. There is no
delete path to pair with it.

Savepoints, precisely:

* **Release** keeps a context established inside the savepoint, so a second bind in the
  enclosing transaction is still refused. Asserted.
* **Rollback** removes the context *and every write made under it*, because they are the
  same savepoint. A transaction can therefore end up acting as a different identity — and
  nothing the first identity did survives to be committed alongside. That is the property
  that matters, and it is asserted end to end: no transaction commits effects or audit
  attribution belonging to two tenants.
* `refuse_inside_savepoint` keeps this package's own callers out of the nested case
  entirely, so the behaviour above is what an adversary gets rather than what an ordinary
  caller has to reason about.

### 2b. The routes that were tried

Every route a runtime role has to remove, replace or shadow the context is enumerated in
`tests/test_authenticated_context.py`, because the previous design failed on a route
nobody had enumerated: `DISCARD TEMP`, `DISCARD TEMPORARY`, `DISCARD PLANS`,
`DISCARD SEQUENCES`, `DELETE`, `TRUNCATE`, `DROP`, `ALTER ... RENAME`, `UPDATE`, a
temporary relation of the same name, a permanent relation in the pinned schema, direct
invocation of `auth_context_begin`, and savepoint release and rollback. Each is followed by
an attempt to bind a second identity.

### 3. Every `SECURITY DEFINER` function is hardened, and each property is asserted separately

A definer function runs with its owner's privileges. That is what makes this design
possible and it is also the thing most likely to become a standing escalation, so five
properties are enforced and each has its own test in
`tests/test_protected_auth_state.py`:

| Property | Why |
| --- | --- |
| Owned by the schema owner | A function's owner can `CREATE OR REPLACE` it. These decide who every caller *is*. |
| `SET search_path = pg_catalog` | Otherwise unqualified names resolve through whatever path the caller arrived with. |
| Every object reference schema-qualified | Belt and braces behind the pinned path, and it fails at definition rather than mid-authentication. |
| `EXECUTE` revoked from `PUBLIC`, granted per role | PostgreSQL's default is `EXECUTE TO PUBLIC`; a future role with only `CONNECT` must inherit none of this. |
| No dynamic SQL, no caller-controlled object lookup | The two shapes that turn a definer function into an injection surface. |

`auth_context_begin` and `auth_require_read_committed` are executable by **nobody**: a
role that could call the first could name any tenant and any scope set it liked. Both are
reached only from inside other definer functions, where the current user is the schema
owner and the privilege is implicit. `audit_events_set_occurred_at` is granted to nobody
either, and needs no grant: PostgreSQL does not check `EXECUTE` when firing a trigger.

No function resolves any relation by name at runtime. The `to_regclass` lookup the first
version needed went with the temporary table; a test now refuses `to_regclass`,
`to_regprocedure` and the `regclass`/`regprocedure` casts outright in every one of these
bodies.

### 3a. The reader is a definer function, which reverses ADR 0004's position on purpose

ADR 0004 said a definer-rights function in a policy predicate is "a standing bypass waiting
for a mistake", and made `app_current_tenant_id()` a plain `SECURITY INVOKER` function. The
policies now call accessors that are invoker functions but reach `firmbatch.auth_context()`,
which is a definer.

That is a deliberate reversal and the reasoning has changed with the mechanism. The 2.1
helper read a value the caller could write, so definer rights would have bought it nothing
except risk. The 2.3 reader reads a relation the caller **cannot** read, which is the whole
point: the context has to be inaccessible to the role whose queries it governs. The
function takes no arguments, contains no dynamic SQL, resolves one fixed relation name, and
returns only what that relation says about the current transaction. It grants no ability
the caller did not already have — it reports one.

### 3b. Revoking from `PUBLIC` is not stating the access control

`REVOKE ALL ... FROM PUBLIC` removes what PostgreSQL hands out by default. It does nothing
about this:

```sql
ALTER DEFAULT PRIVILEGES FOR ROLE <owner> IN SCHEMA firmbatch
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO <application role>;
    GRANT EXECUTE ON FUNCTIONS TO <application role>;
```

which is applied **by the creator, at the instant each object is created**. The grant is
therefore on `auth_bindings` and on `auth_context_begin` before the migration's next
statement runs, and no revoke aimed at `PUBLIC` touches it. An operator who set that rule up
for convenience on ordinary tables would have handed the runtime role the credential
registry and the context writer, and every test that checked only `PUBLIC` would still have
been green.

So the migration ends by **sanitising the whole schema's access control**: every relation,
function and type in `firmbatch` loses every privilege held by anybody except its owner.
The grantees are enumerated from `pg_catalog` and quoted with `format('%I', ...)`; object
names come from `regclass`/`regprocedure`/`regtype` casts, which quote too. No role name is
written down in the migration, because a migration must not know what an environment calls
its roles.

`db/roles.py` runs the **identical** block before its grants, and a test asserts the two
copies are the same text. Both are needed and neither is sufficient: default-privilege
rules outlive a migration, so a later one would inherit a rule `0003` could not have known
about; and a database can be migrated without ever being wired.

The third measure is on the connection itself. `db/principal.py` now refuses a runtime
connection that holds **any** privilege on a protected relation or `EXECUTE` on an internal
function, checked with `has_table_privilege`/`has_function_privilege` so a grant reached
through a role membership is caught alongside a direct one. Stripping a grant at migration
time does not help a database where one was added afterwards; this is what does.

### 3c. The bind is refused outside READ COMMITTED, in the database

`bind_authenticated_context` and `begin_tenant_provisioning` both call
`firmbatch.auth_require_read_committed()` first, and refuse anything else with
`SQLSTATE 0A000`.

The property is about the snapshot the *registry lookup* runs under, which is why it cannot
be a Python check. Under `REPEATABLE READ` or `SERIALIZABLE` every statement reads the
snapshot taken at the first one, so a revocation committed after the transaction opened
would be invisible to it and a revoked credential would still authenticate. Under
`READ COMMITTED` each statement takes a fresh snapshot, which fixes the linearisation point:

> **The bind observes every revocation and expiry committed before the bind statement
> began.** One committed while that statement runs is not observed — and after the bind,
> validity is not re-checked, exactly as a session established before a revocation is not
> retroactively ended.

Expiry is compared against `clock_timestamp()` rather than `now()` for the same family of
reason: `now()` is transaction-*start* time, so a long-running transaction would extend a
credential's life by its own duration.

`db/idempotency.py` keeps its own `READ COMMITTED` check. It is now unreachable in practice
— a transaction cannot hold a context under a stricter level — and it stays because the
reason for it is unchanged, with a test that calls it directly so it is not deleted by the
next person who notices nothing exercises it.

### 3d. Every reachable role, not every inherited privilege

`db/principal.py` refuses a runtime connection that is, or can reach, a role holding
anything a runtime principal must not have. The first version asked that question with
`has_table_privilege` and `has_function_privilege`, which answer about **inherited**
privilege — and `SET ROLE` is not inheritance.

Measured against a real server:

```sql
GRANT other TO firmbatch_app WITH INHERIT FALSE, SET TRUE;
GRANT EXECUTE ON FUNCTION firmbatch.auth_context_begin(...) TO other;
```

`has_function_privilege(current_user, ...)` answered `false`, `pg_has_role(current_user,
'other', 'USAGE')` answered `false`, and `pg_has_role(current_user, 'other', 'MEMBER')`
answered `true`. The application connection opened, passed the principal check, ran
`SET ROLE other`, and queried `firmbatch.auth_bindings`.

So the check now enumerates the reachable set once, with `MEMBER` semantics, and runs every
attribute, ownership and object test against it. The ownership tests were already correct —
they used `pg_has_role(..., 'MEMBER')` on the owner — which is exactly why the discrepancy
was easy to miss: two of the three checks in one module used the right predicate and the
third used a family of functions that looks equivalent and is not.

**And any membership at all is disqualifying**, not merely a membership in a role that
happens to hold something today. A runtime principal has no documented need for one, the
bootstrap grants none, and a membership is the cheapest route to every other condition — a
single `GRANT` in a migration that reads as housekeeping. The per-reachable-role object
tests are kept alongside it rather than replaced by it, so that relaxing the blanket rule
for a documented requirement would leave the boundary checked rather than assumed.

### 3e. The protected inventory is a catalogue, not a name

`auth_transaction_context` was absent from every protected-object inventory: the principal
check, the `PUBLIC` revocation, and the per-command refusal tests all named `auth_bindings`
and stopped. It is the relation that *is* the mechanism — a role holding `INSERT` there
writes itself any tenant, principal and scope set, and one holding `DELETE` clears the
context and binds again as somebody else inside one transaction.

It is now a `ResourceRule` of kind `protected` beside `auth_bindings`, and everything
derives from that one catalogue. The general lesson is the reason it is written down: an
inventory with one entry is an inventory that gets its second object added *next to* it.

### 3f. Column privileges are part of the same boundary

The inventory named the right relations and the checks asked the wrong catalogue. A grant
can name a *column*, and PostgreSQL keeps those in `pg_attribute.attacl` — where neither
the principal check nor the ACL sanitiser was looking. Measured against a real server, as
the migration owner:

```sql
GRANT SELECT (backend_pid), UPDATE (tenant_id)
ON firmbatch.auth_transaction_context TO <application role>;
```

The hardened checkout accepted the connection. The application could then authenticate as
tenant A, `UPDATE` the protected context row's `tenant_id` to tenant B, and read tenant B's
workspaces — the whole isolation boundary, from a grant that confers no table privilege at
all.

Two independent defects, corrected separately because either alone would have left the
other:

* **The sanitiser never named the grantee.** Both copies of the ACL sanitiser — migration
  `0003` and `db/roles.py` — enumerated grantees from `pg_class.relacl`, and a role holding
  only column privileges is absent from `relacl` entirely: after `GRANT SELECT (a) ON t TO
  r` the relation ACL is still NULL. The verb was never the problem — `REVOKE ALL ON TABLE
  t FROM r` does remove r's column grants — so the correction is a second enumeration, over
  `pg_attribute.attacl`, and a `REVOKE ALL (col)` per column and grantee. Both copies carry
  it, and the equality test that keeps them identical is what stops them drifting.
* **The principal check asked about the table.** `has_table_privilege` answers about the
  table and nothing else. `db/principal.py` now reads column ACLs from `pg_attribute`
  directly, for every non-dropped user column of every protected relation, against every
  `MEMBER`-reachable role and against PUBLIC — and reports them in a **separate** field
  from the table privileges. Deliberately not `has_column_privilege`, which answers "at
  table level *or* column level" and would have conflated the two: a report built on it
  could not distinguish a column-only grant from a table grant, and revoking the table
  grant would have made the column grant invisible again.

All four column privileges PostgreSQL has — `SELECT`, `INSERT`, `UPDATE`, `REFERENCES` —
disqualify, on either protected relation. Neither column names nor role names are written
down: both are enumerated from the catalogue, and every identifier reaching a `REVOKE` is
rendered by `format('%I')` or by a `regclass` cast.

### 4. Provisioning cannot name a tenant, including an existing one

A tenant has no credential until it exists, so tenant creation needs a context it cannot
authenticate into. The obvious shape is `begin_provisioning(tenant_id)`, and it would have
made the provisioning role a trusted setter of context — the exact thing this ADR removes
one layer up.

So `firmbatch.begin_tenant_provisioning()` takes **no arguments** and generates the tenant
id with `gen_random_uuid()` inside the function. The caller cannot point it at an existing
tenant because it cannot name a tenant at all. `TenantRepository.create` takes no
`tenant_id` either; it uses whatever the context carries.

This is strictly narrower than Milestone 2.1, where the provisioning role could set context
to any tenant and read or amend that tenant's row. `tests/test_role_privileges.py` asserts
the new property directly.

### 5. Authorization is a closed catalogue, deny by default, enforced per command

`security/authorization.py` names every capability that exists. Seven scopes, and there are
no others:

| Scope | What it permits |
| --- | --- |
| `tenant:read` | Read the tenant's own record — one row, by primary key |
| `tenant:provision` | Create and amend a tenant record; held only by the provisioning path |
| `workspace:read` | Read workspaces in the authenticated tenant |
| `workspace:write` | Create, amend and remove them |
| `mutation:execute` | Claim idempotency keys and append outbox events |
| `audit:read` | Read the tenant's audit trail |
| `credential:manage` | Register and revoke bindings **within the authenticated tenant** |

Three places agree about that, and a test checks each: the catalogue, the check constraint
on `auth_bindings.scopes`, and the policies. Adding a scope means a migration, which is the
honest cost of deny-by-default — a vocabulary that can be extended at runtime cannot be
audited.

**One policy per command, rather than one `FOR ALL` policy.** That is what makes "no
policy" mean "no access": `tenants` has no `DELETE` policy and the append-only tables have
neither `UPDATE` nor `DELETE`, so those commands reach no row for any role, the owner
included, because row security is `FORCE`d.

**The customer boundary is enforced by absence.** No scope names an operator, supplier,
provider, routing, settlement, certification or internal-control capability, so no
credential can carry one and no policy would honour one if it did
(`RESERVED_NON_CUSTOMER_DOMAINS`, and a test that walks it). The operator capacity agent
remains separate software with its own identity and protocol (ADR 0003 decision 8); it is
not a scope here and must not become one.

### 5a. A PostgreSQL fact the read/write split has to live with

`INSERT ... RETURNING` applies the table's `SELECT` policies to the returned rows, and the
ORM writes rows carrying server-side defaults with `RETURNING`. So a credential holding
`workspace:write` and not `workspace:read` can insert with a plain statement and cannot
insert through the repository. That is PostgreSQL behaving correctly rather than a defect,
it is why the `tenants` read rule includes `tenant:provision`, and it is asserted as a
documented behaviour in `tests/test_authorization.py` rather than discovered later.

### 5b. Delegation is bounded by the issuer, and there is no wildcard

`credential:manage` authorises **creating** a credential. It does not decide what that
credential may do, and the first version let it: `register_auth_binding` accepted any scope
in the closed catalogue, so a leaked credential holding nothing but `credential:manage`
could mint itself a successor holding `workspace:write` and `audit:read`. That is privilege
escalation inside the tenant, performed entirely through the supported interface.

Two rules, both in the `SECURITY DEFINER` function because that is the only place they hold
under arbitrary runtime SQL, and mirrored in Python so a caller gets the rule by name:

1. every requested scope must be **delegable**. `tenant:provision` is not: it belongs to
   the bootstrap path and is acquired from `begin_tenant_provisioning()`. The catalogue
   already said no customer credential is issued it; this is what enforces the sentence;
2. a **credential** issuer may grant only scopes it holds itself.

**`credential:manage` is itself delegable**, and that was a decision rather than an
oversight. It is bounded by rule 2 — the issuer already holds it — it is confined to the
issuer's own tenant because the database derives the tenant from the context, and refusing
it would only mean credential rotation could not be delegated. There is deliberately **no
administrator wildcard**: no scope, and no value of any scope, means "all".

**The provisioning actor is the one exemption from rule 2.** It carries `tenant:provision`
and `credential:manage` and nothing else, yet it issues a tenant's first credential with the
customer capabilities. That is not an escalation: it holds no credential to inherit from, it
is reachable only by the separate provisioning database role, and the tenant it is acting in
was generated by `begin_tenant_provisioning()` inside the same transaction — so it cannot
reach an existing one. Bootstrapping a tenant's first credential has to come from somewhere,
and this is the somewhere.

Unknown scopes are refused by the function **before** the `scopes_known` check constraint
would refuse them, and that ordering is load-bearing: a constraint violation renders the
failing row in its `DETAIL`, so letting the constraint do the refusing would put the
rejected value into the error text. Nothing in the delegation path echoes a scope value.

### 6. Audit events derive their actor, and cannot be revised

`firmbatch.audit_events` records who acted, for which tenant, what was attempted or
completed, against what, when, and under which request. `tenant_id`, `actor_kind`,
`actor_principal_id` and `actor_binding_id` come from the authenticated context by column
default **and** are re-checked by the insert policy, so a caller that names a different
value is refused rather than silently corrected.

`occurred_at` is written by a `BEFORE INSERT` trigger from `clock_timestamp()`, which
overwrites whatever arrives. The first version defaulted it to `now()` and had the policy
require it to equal `now()`, which refused an explicit wrong value and **missed the
interesting case entirely**: a caller does not have to supply anything to backdate an
event, it only has to open its transaction early, because `now()` is transaction-start time
and the policy would then be comparing the backdated value against the same backdated
clock. A trigger rather than a column default, because a default only applies when the
column is omitted; and row-level security's `WITH CHECK` is evaluated *after* `BEFORE`
triggers, so the policy sees what the trigger wrote and has nothing left to check.

Append-only in the same two independent ways as the M2.2 tables: no runtime role holds
`UPDATE` or `DELETE`, and there is no `UPDATE` or `DELETE` policy at all.

`actor_binding_id` references `auth_bindings` on `(id, tenant_id)`, because referential
integrity is checked with row security bypassed and a single-column reference would accept
a binding from another tenant as a perfectly valid actor.

**`outcome` is a closed set including `attempted` and `denied`.** A trail that records only
successes cannot answer the question it exists for.

### 6a. Appending requires no scope, and the cost of that is named

Reading the trail requires `audit:read`. **Appending requires a valid authenticated context
and nothing more.** The alternative — an `audit:append` capability — makes it possible to
issue a credential that acts without leaving a trail, which is the one outcome an audit
trail exists to prevent.

The price is real and is not hidden: a credential with no scopes at all can write audit
rows in its own tenant. They are bounded metadata, they are tenant-scoped, and they are
immutable. That is a better failure than unauditable action.

### 6b. The audit insert carries no `RETURNING`, and the id comes back from the function

Because of 5a: an insert with `RETURNING` would need `audit:read` to append, which would
reintroduce exactly the coupling 6a rejects. So nothing returns the row. What the
identifier has to be is **immutable**, and append-only is what makes it so; being
server-generated was never the property that mattered.

**Revised.** The first version issued a Core `INSERT` from Python with an
application-generated `uuid4`. That was the right shape and the wrong place: see decision
6e, which moved the whole append into the database and took the `INSERT` privilege away.

### 6c. Audit events and outbox events are different records, and stay separate

An **outbox event** is intent to tell somebody that state changed: addressed outward, read
one day by a dispatcher, content chosen by the state machine that emitted it. An **audit
event** is a record of who did what: addressed inward, dispatched to nobody, actor and
tenant not chosen by anyone. Neither is derivable from the other — an action that changes
no state still belongs in the trail, and an internal transition with no actor still belongs
in the outbox.

**There is no hash chain and no external audit delivery.** The canonical architecture asks
for audit events; a tamper-evident log and an audit shipper are neither required by it nor
buildable honestly here, and either would be machinery invented ahead of a requirement —
with a verifier nobody runs and a repair story nobody has written. What makes these rows
trustworthy today is narrower and checkable: nobody can change one, and nobody can write
one about another tenant or another actor. A test asserts the absence, so that "we decided
not to" and "we forgot" remain different states.

### 6d. Authentication *failures* are not in the trail, and cannot be

A failed bind yields no tenant to scope a row to, and it aborts the transaction that would
have written one. So the trail records credential lifecycle — registration and revocation —
and not authentication attempts. Successful binds are not recorded either: one happens per
request, and recording them would make the audit trail an access log with the write volume
of the traffic.

Authentication failure belongs in the application log, which is Milestone 8's
observability work. Recording it here is not deferred because it is hard; it is deferred
because this is the wrong place for it.

### 6e. No runtime role writes the audit trail directly

The bounded-metadata policy in `db/metadata.py` was a **Python** boundary. A runtime role
held `INSERT` on `firmbatch.audit_events`, so it could compose the statement itself — and
the table's check constraints bound a details document's *size and shape* and said nothing
whatever about its content. A bearer credential under an innocuous key was refused by
Python and accepted by PostgreSQL.

So the privilege is gone from both runtime roles, and `firmbatch.append_audit_event(...)` is
the only way in. It applies the whole policy inside the database — denied and secret-shaped
keys, secret-shaped values, nested objects and arrays, unsupported JSON types, key count,
key length, string length and encoded size — and it has **no parameter** for the tenant, the
actor kind, the principal, the binding or the timestamp, so there is nothing derived for a
caller to supply correctly or incorrectly. The insert policy still evaluates, because row
security is `FORCE`d and a definer function runs as the owner, whom `FORCE` binds too.

Two implementations of one rule is the arrangement that drifts, so a shared corpus of
accepted and rejected documents is walked by both, and the two shape recognisers — Python
`re` and PostgreSQL's ARE, which are not the same dialect — are compared answer for answer.

The check constraints stay. They are the layer under this one, and they are exercised from
the schema owner, which is now the only identity that can reach the table with an `INSERT`.

### 6f. Audit metadata errors name the rule, and the database's do too

Extending decision 8 across the boundary. Every refusal in
`firmbatch.audit_require_acceptable_details` names the rule and the position — "entry 3",
"entry 3, item 5" — and never the key, the value or its length, for the same reason the
Python side does not. That includes not letting a check constraint refuse the row instead:
PostgreSQL renders the failing row in a constraint violation's `DETAIL`.

On the Python side the refusal is built inside the `except` and raised **outside** it. The
statement carries the caller's whole details document as a bound parameter and a
`DBAPIError` renders its parameters, so an error that let the psycopg exception travel as
`__cause__` or `__context__` would reattach exactly the document it exists to keep out of a
log. An unanticipated SQLSTATE produces a message with no database text in it at all.

### 7. Four classes of secret, four boundaries, and no silent fallback

`security/secrets.py` implements the model and not the infrastructure:

1. **High-entropy bearer credentials** — `Secret`: a random token prefixed `fbk_`,
   shown once at creation, stored only as a SHA-256 fingerprint computed **in the
   database**. There is deliberately **no function in this package that turns a credential
   into the stored form**, because a Python-side fingerprint is one refactor away from
   being written to a column.

   The credential a running system issues is generated **inside**
   `firmbatch.register_auth_binding` — see decision 7b — and
   `generate_bearer_credential()` mints the same shape for tests and for the recogniser
   that keeps one out of metadata.
2. **Reversible operational and provider secrets** — `SecretReference`. A provider API key
   has to be *used*, so it cannot be a digest; it therefore never appears in a product
   table at all. A row holds a backend, a name and optionally a version, and resolution
   happens in the one service role that owns the secret (target architecture 2.1).
3. **Encrypted values** — `EncryptedValue`: a versioned ciphertext envelope plus an opaque
   `KeyReference`. The scheme version lives inside each value so a rotation is a readable
   fact per row rather than a deployment note.
4. **Migration-owner credentials** — represented by the migration settings type in
   `config.py` and by nothing here. Giving that class a type in this module would put the
   owner credential in the import graph of every process that handles the other three.

`SECRET_CLASSES` states all four as data, so the model is something a test walks rather
than a paragraph somebody has to keep true.

**Production fails closed.** `resolver_for()` and `encryptor_for()` return adapters that
**raise**; the AWS Secrets Manager and KMS implementations are Milestone 8's. The test
doubles refuse to be constructed outside `FIRMBATCH_ENV=test`, and there is no parameter,
flag or variable that substitutes one. A resolver that quietly read a plaintext value from
somewhere else would hide the fact that the real one does not exist.

**Firmbatch implements no cryptography.** The test double is a dictionary and is named as
one; its "ciphertext" is a random opaque token. The one thing worse than not having
encryption here would be having one somebody in this repository invented.

### 7a. Nothing renders a secret, including its length

`Secret` closes `repr`, `str`, `format`, pickle, `copy`, `deepcopy` and hashing, and
renders `Secret(<redacted>)` with **no length**: the length of a short secret is most of a
short secret. `EncryptedValue` renders its version and key reference — both non-secret and
both useful in a traceback — and never its ciphertext. Every route is tested, including
`f"{secret}"`, `"{}".format(secret)`, `repr([secret])` and `str(RuntimeError(secret))`.

`looks_like_secret()` runs the other way: a small set of shapes meaning "somebody put a
credential where a reference belongs". **It reports the name of the shape and never the
value**, so catching a secret does not put it in the exception text instead.

It is applied in five places, and the fifth was a review finding: `SecretReference.name`,
`SecretReference.version`, `KeyReference.identifier`, metadata values — and metadata
**keys**, which the format check used to interpolate into its own refusal. A bearer
credential used as a metadata key was therefore echoed by the very check that existed to
notice it. The shape test now runs *before* every format test for that reason, and no
refusal in the metadata policy or in the reference types quotes its input at all: an error
names the rule and the position (`entry 3`, `entry 3, item 5`) and nothing else. Not the
key, not the value, and not its length — a length is a small leak in general and most of a
short secret in particular.

`SecretReference`, `KeyReference` and `EncryptedValue` all define `__repr__` explicitly
rather than taking the dataclass default, so adding a field is a decision about rendering
rather than an accident. `EncryptedValue` renders its key identifier, which is safe because
`KeyReference` refuses a secret-shaped one at construction — the transitive case, and it is
tested as one.

**What this cannot do, stated rather than implied.** `hunter2` is a valid reference name and
a valid metadata key, and no pattern can say otherwise. What the rules buy is that the
recognisable mistake is refused, and that *every* refusal — recognisable or merely
malformed, long or short — is silent about what it refused. The tests cover both halves,
including a passing test whose subject is the limit.

### 7b. The credential is generated where it is stored, so there is nothing to probe

The first version had `register_auth_binding(credential, principal, scopes, expires_at)`
and inserted what it was given. A holder of `credential:manage` in tenant A could submit a
*candidate* and watch the outcome: a unique violation on the globally unique fingerprint
meant "this exists somewhere", across a tenant boundary, in a table the caller cannot read.

Catching the violation and raising something else would not have fixed it. **Success versus
failure is the oracle**, whatever either one is called — the caller learns the answer from
which branch it took.

What removes the question is removing the caller's choice. The function now takes no
credential: it generates one from two `gen_random_uuid()` values (244 bits from
PostgreSQL's strong RNG, rendered as the same 43 URL-safe characters the Python generator
produces), inserts with `ON CONFLICT (fingerprint) DO NOTHING`, retries on the collision
that will not happen, and returns the value once. `tests/test_authenticated_context.py`
takes active, revoked and expired credentials belonging to another tenant and shows there
is no operation that accepts one.

A second thing falls out of it: registration no longer passes a secret as a statement
parameter, so the whole class of "a `DBAPIError` renders the parameters" leak is gone from
that path. It remains on the bind, where it is handled — see 7c.

### 7c. A database error must not carry a credential out with it

One statement in this package still passes a raw credential as a parameter — the bind —
and a `DBAPIError` renders the failing statement **and its parameters**. Every expected
failure of it is translated into an explanatory error; an unexpected one is re-raised as
`CredentialOperationError` with the value scrubbed out, so no surprise can put
`[parameters: {'credential': 'fbk_...'}]` into a traceback, a log, or a retained CI
artifact.

The raise happens **after** the `except` block rather than inside it, and that detail is
the reason `db/auth.py` has a small `_execute` helper rather than a context manager.
Inside a handler — including inside a context manager's `__exit__`, which runs while the
caller is unwinding — Python attaches the exception being handled as `__context__`.
`raise ... from None` suppresses it when a traceback is *printed*; it does not detach it,
so anything that walks the exception chain still finds the psycopg error and the parameters
it renders. Outside the handler there is no exception being handled and nothing is attached
at all. This was found by review rather than by a failure, and it is tested by forcing the
unexpected case on purpose.

### 8. The metadata policy moved, unchanged, so the audit trail can share it

`db/metadata.py` now holds the bounded-metadata rule ADR 0005 decision 9 describes;
`db/idempotency.py` re-exports every public name, so nothing that imported one from there
had to move. Three columns are governed by it: `idempotency_records.result`,
`outbox_events.attributes` and `audit_events.details`.

One rule was added: a value carrying a recognisable secret shape is refused. Like the key
denylist, it is defense in depth and **not a proof** — no pattern can establish that a
string is not a secret, and the data-flow proof is still Milestone 5's.

### 8b. Whitespace is enumerated, because `\s` and `[[:space:]]` are different sets

The metadata policy is implemented twice — `db/metadata.py` at the boundary, and
`firmbatch.audit_require_acceptable_details` inside the database, which is the half that
holds when a runtime role writes the call itself. Two of the shapes it recognises are
separator-sensitive, and "whitespace" was spelled `\s` in Python and `[[:space:]]` in
PostgreSQL.

Those are not the same set. Python's `\s` is Unicode; PostgreSQL's POSIX class is decided by
the server's `lc_ctype`. Measured on a real PostgreSQL 16 server: U+0085, U+00A0, U+2007 and
U+202F are whitespace to Python and are **not** whitespace to PostgreSQL — and neither are
the four ASCII information separators U+001C–U+001F. So a U+00A0 followed by
`Bearer example`, and `token` U+00A0 `=example`, were refused by `validated_metadata` and
accepted by the database. That is a way to store a credential in the audit trail, reachable
by any role that can call `firmbatch.append_audit_event`.

The correction is to stop asking either dialect. `security/secrets.WHITESPACE_CODE_POINTS`
enumerates the set explicitly — every code point Python's `\s` matches, checked against `\s`
itself by a test so that a Python upgrade widening it fails the suite rather than silently
reopening the gap — and both implementations fold all of them to a plain ASCII space before
any pattern runs. The patterns then say `[ ]` and `[^ ]` in both languages. PostgreSQL's
`translate()` maps code point to code point and consults no locale, so the two agree by
construction rather than by coincidence.

The fold rewrites separators and **nothing else**. Rejecting non-ASCII outright would have
closed the same gap and made a note in most of the world's scripts unstorable; accented
Latin, CJK, Cyrillic and Greek text remain valid metadata, and a test says so.

The migration duplicates the code-point list rather than importing it, because a migration
is a historical record and must not depend on application code that changes underneath it.
A shared corpus in `tests/test_audit_events.py` walks the whole declared set through both
implementations and asserts they name the same shape — the verdict *and* which shape it is,
since agreeing that something is a secret while disagreeing about which kind would still be
two rules.

The same argument applies to case, and decision 8c is the other half of it.

### 8c. Case is folded explicitly, in ASCII, and the patterns are the same text

Fixing whitespace left the identical bug one clause over. `re.IGNORECASE` is **Unicode**
case folding; `~*` is **locale** case folding. Measured on a real PostgreSQL 16 server,
after the whitespace fix was in:

| value | `looks_like_secret` | `firmbatch.secret_shape` |
| --- | --- | --- |
| U+017F + `ecret=x` (LATIN SMALL LETTER LONG S) | refused | **accepted** |
| `api` + U+212A + `ey=x` (KELVIN SIGN) | refused | **accepted** |

Unicode folds both of those onto ASCII letters and PostgreSQL's locale does not, so the two
implementations disagreed — and they disagreed in the direction that costs something, because
the database is the half with no Python in front of it. It is a defect, not a design
question, and it is fixed here rather than deferred.

**One pipeline, both steps explicit.** `security/secrets.normalize_for_shape_scan` folds the
29 enumerated whitespace code points to an ASCII space, then folds `A`–`Z` to `a`–`z`, and
touches nothing else. `firmbatch.secret_shape` performs the same two folds in the same order
with nested `translate()` calls. Neither uses `str.lower()`, `str.casefold()`, `lower()`,
`upper()` or any collation: `translate()` and `str.translate` map code point to code point
and ask nothing.

**And the patterns became one text rather than two dialects.** This is the part worth
noticing. The lists used to be a Python spelling and a PostgreSQL spelling of the same
intent — `\b` against `\y`, `(?i)` against `~*`, `\s` against `[[:space:]]` — and *every one
of those three pairings turned out to mean something different*. A rewrite is where two
rules drift apart invisibly. So every construct either engine has to look up is gone:

* no `\s`/`[[:space:]]` — the whitespace fold ran, so `[ ]` and `[^ ]` say it exactly;
* no `(?i)`/`~*` — the case fold ran, so lowercase case-sensitive patterns say it exactly;
* no `\b`/`\y` — an ASCII word boundary is written `(?<![0-9a-z_])`, which both engines
  evaluate without consulting a locale or a Unicode table. `\b` follows Python's Unicode
  `\w` and `\y` follows PostgreSQL's `[[:alnum:]]`, and there was no reason to expect two
  different tables to classify the same character alike.

What is left is literals, explicit ASCII classes and lookaround — so the migration can carry
a **character-for-character copy** of the pattern text, and a test compares it rather than
comparing answers on samples somebody thought of. `re.ASCII` is set on the compiled patterns
too; it changes nothing today and makes a future `\w` ASCII by default.

**Every caller inherits this**, because there are exactly two implementations and everything
goes through one of them: audit metadata keys and values, idempotency results and keys,
outbox attributes, request identities, secret and key references, scope pre-validation, and
the audit action/resource-type/outcome checks. A test asserts no third implementation exists.

**What is preserved.** Non-ASCII text is carried through unchanged and stays storable —
accented Latin, CJK, Cyrillic, Greek, emoji, and Turkish `İ`/`ı`. Rejecting non-ASCII would
have closed both gaps and made a note in most of the world's scripts unstorable.

**What is deliberately not claimed, and it is a real loss.** A Unicode **homoglyph** of a
marker is now recognised by *neither* implementation: U+017F + `ecret=x` passes both. Before
this change it was caught by one of them. That is the honest consequence of an ASCII fold,
and it is the right trade — the alternative keeps a detection in the layer a caller can walk
around while the layer that actually holds stays blind, which reads as protection and is
not. `looks_like_secret` is **defense in depth against the obvious mistake**: a credential
pasted where a reference belongs. It has never claimed to detect a semantic secret, and it
does not claim to survive a homoglyph attack. The proof that customer payload never reaches
this database is Milestone 5's data-flow path (ADR 0005 decision 9), not this denylist. Both
homoglyphs are in the accepted corpus, so the limitation is a test somebody has to change on
purpose rather than a sentence somebody can forget.

One behaviour change worth stating: because the word boundary is now ASCII-explicit, a
non-ASCII letter counts as a boundary, so `ıtoken=x` is recognised where `\b` and `\y` both
used to say nothing. Stricter, and both implementations say it together.


### 8a. Authenticated work requires a writable primary, and says so

The consequence of decision 2 that is worth failing deliberately on: acquiring a context
writes one row, so an authenticated transaction cannot run on a standby or inside a
read-only transaction — not even a purely read-only one.

`firmbatch.auth_require_writable_primary()` runs **before** the write and refuses both.
`pg_is_in_recovery()` is tested first, and the order is part of the diagnostic rather than
an accident: on a standby `transaction_read_only` is always `on`, so a guard that checked it
first would report every replica as "somebody set the transaction read-only" and send the
reader looking for a `SET` nobody wrote. `db/auth.py` translates the SQLSTATE to
`WritablePrimaryRequiredError`, carrying no SQL parameters and no exception chain.

**The guard has to be reached before anything touches the context relation, and it was
not.** `auth_transaction_context` is `UNLOGGED`, and PostgreSQL refuses to *plan* a query
that references an unlogged relation while the server is in recovery — the refusal arrives
before the query runs, so before any guard inside a function that query would have called.
Every authenticated entry path began by reading the current context: `db/engine.transaction`
asserts it starts with none, which is a `SELECT firmbatch.auth_tenant_id()`. On a standby
that read failed first, with PostgreSQL's own message about an unlogged relation, and the
deliberate diagnostic was never reached — which is exactly the outcome decision 8a exists to
prevent.

So a **preflight that names nothing in the schema** now runs first, in
`db/engine.require_writable_primary`: two catalogue functions, `pg_is_in_recovery()`
selected before `transaction_read_only`, and no relation at all. It runs at the top of
`transaction()` and again at the top of both binding entry points, because a transaction can
be made read-only after it begins and a caller may have built the `Session` itself. The
error is defined in `db/engine.py` — the preflight must run inside the transaction
machinery, which cannot import `db/auth.py` — and re-exported from `db/auth.py`, so nothing
that names it had to move.

The database's own guard is kept as defense in depth, and moved to be the **first executed
statement** of both `bind_authenticated_context` and `begin_tenant_provisioning` — ahead of
the isolation-level check and the registry lookup — so a caller reaching around the Python
boundary with raw SQL fails safely and with the same diagnostic. That ordering is asserted
from `pg_proc.prosrc` rather than from the migration file.

**Read-replica routing is Milestone 8 work.** This is a stated limitation of Milestone 2.3,
not a defect to be worked around here: making authenticated reads work on a replica means
either a context mechanism that does not write — which is decision 2 undone — or routing
that knows which transactions are read-only before they start, which is a deployment
concern this milestone does not have. **Every authenticated read is primary-only.**

The refusal is tested on a primary. **No live standby has been tested and none is claimed.**
What the tests establish is: that the preflight names no relation; that
`pg_is_in_recovery()` is consulted and consulted first, in the preflight and in the SQL
guard alike; that a recovery answer selects the standby diagnostic, reached by handing the
pure classifier the answer a replica would give; that no context helper runs after a failed
preflight, on the application path, the provisioning path, and a caller-built `Session`
alike; and that a real read-only transaction is refused with nothing from the DBAPI, the
URL or the credential anywhere in the exception graph. Live-standby qualification is
Milestone 8.

### 9. Role wiring knows which schema revision it is wiring

`db/roles.py` is deliberately outside Alembic — role names differ per environment, so
putting them in a migration would make the schema history non-deterministic. But it is not
schema-*independent*: every statement in it names a table or a function.

Measured: upgrade to `0003`, provision roles, downgrade to `0002`, provision again →
`UndefinedTable: relation "firmbatch.auth_bindings" does not exist`, on
`REVOKE ALL ON TABLE firmbatch.auth_bindings FROM PUBLIC` — the *first* wiring statement,
before any grant had run. A controlled rollback left an environment whose roles could not be
re-provisioned.

Each supported revision now has an explicit `RevisionPlan`: its tables, its functions, and
the per-role grant set. `0002` and `0003` are supported; everything else — an older
revision, an unknown one, a database with no version table, and a version table carrying
more than one row — is refused by name. Before granting anything, every object the plan
names is checked to exist, so a schema that disagrees with its own stamp is an error naming
the missing object rather than an `UndefinedTable` from whichever statement reached it
first.

**Nothing catches an undefined-object error and continues.** That would produce a half-wired
database, and a half-wired database looks provisioned.

**Schema `0002` is supported for controlled rollback and provisioning only.** Application
code at head does not run against it: the authenticated context, the audit trail and every
Milestone 2.3 policy are `0003` objects, and a runtime process pointed at `0002` fails at
its first bind. The revision is in the plan so that a rollback can still provision and
validate its roles, and so the round trip is testable.

## What this does not claim

**It does not protect against a compromised migration-owner credential.** That role owns
the functions and the policies and can redefine both. That is why `db/principal.py` refuses
to let a runtime connection *be*, or reach, that role, and why `test_ownership_boundary.py`
asserts it across the database, the schema, every relation, every function and every type.
The boundary is the one ADR 0004 §8h draws: the runtime process cannot load the privileged
credential, and a static gate proves it cannot even ask.

**It does not claim a credential cannot leak in transit.** On authentication the raw
credential travels to PostgreSQL once, as a bound parameter — psycopg sends parameters out
of line, so it does not appear in the query text or in `pg_stat_activity` — and is hashed
inside the database. On registration it travels the other way, in a result row. A server
configured to log parameters, or a client that logged result sets, would capture one
exactly as it would a password. That is a deployment property, and Milestone 8 owns it.

**It does not implement credential lifecycle.** `register_auth_binding` and
`revoke_auth_binding` are the minimal protected persistence foundation Milestone 3 will
build on. There is no listing, no last-use tracking, no rotation workflow, no HTTP surface,
no memberships, no invitations, no browser sessions and no account model.

**It does not establish invariant 3.** Customer payload bytes not passing through the API
process or PostgreSQL is still Milestone 5's presigned S3 path. The metadata bounds and the
secret-shape rules are defense in depth and prove nothing semantic.

**It does not deploy anything.** Under this repository's taxonomy the behaviour here is
implemented and tested, **not VERIFIED LIVE**: no evidence artifact has been captured, no
RDS instance exists, and nothing is deployed.

**It closes the database and runtime half of `AUTH-BOUND-TENANT-CONTEXT`, and not the
identity half.** Cases 1 to 4 of that task's completion gate — arbitrary context, a leaked
runtime credential, SQL injection, and replay or forgery — are about what arbitrary SQL can
do to the database, and are met here and tested adversarially. Case 5 — an authenticated
user with no membership in a workspace cannot obtain context for it — is not a database
question at all: there are no users and no memberships yet to be a non-member of.

That half is tracked separately as **`AUTH-MEMBERSHIP-BOUND-IDENTITY`** rather than under
the old name, because continuing to call it `AUTH-BOUND-TENANT-CONTEXT` would mean a
blocker whose description no longer matches what is missing. **Customer-facing deployment
remains blocked** until Milestone 3 supplies identity, membership and credential lifecycle.

**It does not claim an audit event's clock is trustworthy beyond the server's.**
`clock_timestamp()` is the database server's clock. A wrong server clock produces wrongly
dated events, and nothing here detects that. What is excluded is a *caller* choosing the
time, by supplying one or by opening its transaction early.

## Consequences

- **Every environment needs a way to mint the first credential.** Tenant creation and the
  first binding happen in one provisioning transaction, because the registry derives the
  tenant from the context. That is the shape Milestone 3's signup flow will have.
- **`tenant_transaction(engine, tenant_id)` is gone.** Callers use
  `authenticated_transaction(engine, credential)` or `provisioning_transaction(engine)`.
  A transaction that could be handed a tenant id was the whole of the gap.
- **Repositories take no tenant id.** An argument that can disagree with the authenticated
  context is an argument somebody will one day pass the wrong value to.
- **One upsert per authenticated transaction, and a primary-key lookup per policy
  evaluation.** The context is a real row now. That cost is what the first design was
  avoiding, and the property it bought instead was not real. Keying on the backend pid
  bounds the table and `UNLOGGED` removes the WAL, which is most of the difference; if the
  read ever matters, the fix is a per-transaction cache and not a weaker check.
- **`reset_auth_context` and `firmbatch.auth_context_reset()` do not exist.** A context
  cannot be dropped part-way through a transaction, by anybody, by any route. Callers that
  want an unauthenticated transaction open one.
- **Provisioning holds `INSERT` and not `SELECT` on the audit trail**, so it records what
  it did and cannot read it back. Reading is `audit:read`, which a provisioning context
  does not carry.
- **A scope is a migration.** Deny-by-default with a closed vocabulary costs a schema
  change per capability, which is the point.
- **Downgrading `0003` restores the Milestone 2.2 mechanism exactly** — the caller-set
  setting and the policies that read it — because a downgrade that dropped the new policies
  without restoring the old ones would leave a schema nothing could read or write. A test
  stops at `0002` and checks that, which a round trip to `base` cannot.
- **The schema's access control is re-stated on every wiring run.** `db/roles.py` sanitises
  before it grants, so an environment provisioned after somebody set a default-privilege
  rule ends up with the same ACL as one provisioned before. An operator runbook that skips
  the wiring step now leaves more than missing grants: it leaves whatever the migration
  inherited, which is why the migration sanitises too.

## Rejected alternatives

### Letting a `credential:manage` holder choose any scope in the catalogue

Rejected once it was pointed out, and it is worth naming because it is what "the catalogue
is closed" quietly stops sounding like. A closed catalogue bounds what a scope can *be*; it
says nothing about who may *grant* one. Without decision 5b the two together read as a
guarantee and were not one: the vocabulary was closed and any holder of one management
capability could assign the whole of it.

### An `admin` or wildcard scope to make delegation simple

Rejected. Every delegation rule in decision 5b is a subset test, and a wildcard is the value
that makes every subset test pass. It would also be the first scope in this catalogue whose
meaning is not a specific capability, which is how a permission model stops being auditable.
Where an issuer genuinely needs to grant something it does not hold, the answer is the
provisioning path — narrow, out of band, and unable to name an existing tenant.

### Keeping `INSERT` on `audit_events` and relying on the Python boundary

Rejected. See decision 6e: a boundary a caller can walk around by writing the statement
itself is a convention. The cost of removing it is one function call in place of one ORM
insert, and the property bought is that the metadata policy holds under arbitrary runtime
SQL rather than only when `db/audit.py` was asked first.

### Catching `UndefinedTable` in the role wiring and carrying on

Rejected. It is the two-line version of decision 9 and it produces the worst outcome
available: a database that reports successful provisioning and denies access at runtime,
with no record of which grants were skipped. An explicit refusal costs one error message.

### Making the context write conditional so standbys work

Rejected. There is no version of "acquire a context without writing" that keeps decision 2:
the write is what makes the context unclearable by any runtime SQL, and a read-only fallback
would be a second, weaker mechanism reachable by asking for it. Read-replica support is a
Milestone 8 routing problem, and decision 8a states the limitation rather than half-solving
it.

### A signed capability token verified in the database

Rejected. It needs a signing key somewhere, a verification implementation in PL/pgSQL, key
rotation, and replay bounds — cryptography Firmbatch would be inventing, in the one place a
mistake is invisible. The fingerprint registry gets the same property from a lookup: the
credential is unforgeable because it is 244 random bits, not because a signature says so.

### A second GUC, or a GUC the application promises to set correctly

Rejected, and it is worth being specific because it is the cheapest-looking option. Any
custom setting is writable by the role that holds the connection. A convention on top of
that is the *current* design under a different name, and ADR 0004 already recorded why a
half-built capability is worse than a documented absence.

### A temporary context table with `ON COMMIT DELETE ROWS`

**Built, measured, and replaced.** It was the original decision here, rejected on cost
grounds in favour of nothing — and the cost it was avoiding turned out to be the price of
the property. `DISCARD TEMP` drops a temporary relation whoever owns it, needs no
privilege, and left the caller free to bind a second identity in the same transaction. See
decision 2; the accounting that made a permanent table look expensive is answered there by
keying on the backend pid, which bounds the table, and by `UNLOGGED`, which removes the
WAL.

### Enabling row-level security on `auth_bindings`

Rejected as theatre. A policy constrains a role that holds privileges, and no role holds
any on that table. Enabling it without `FORCE` would exempt the owner and read as though it
did something; enabling it *with* `FORCE` would lock out the definer functions that are the
only legitimate access path. The absence of grants is the boundary, and a test asserts both
the absence and that no policy exists — so that "we decided not to" is distinguishable from
"we forgot".

### Translating the registration unique-violation into a different error

Rejected as the thing that looks like a fix. The caller learns the answer from *which
branch it took*, not from what the error said, so renaming the failure leaves the oracle
exactly where it was. Removing the caller's ability to submit a candidate is what removes
it. See decision 7b.

### Checking the isolation level in Python instead of in the database

Rejected. The property is about the snapshot the registry lookup runs under; Python can
observe the level but cannot make a stale snapshot fresh, and a caller reaching the
database function directly would skip the check entirely. It lives in
`auth_require_read_committed()`, which no role may execute and both entry points call.

### Auditing every successful authentication

Rejected. One bind happens per request, so the trail would become an access log with the
write volume of the traffic, and the signal — who changed what — would be buried in it.
Access logging is observability, and it belongs with the rest of it in Milestone 8.

### An `audit:append` scope

Rejected; see 6a. A credential that can act without leaving a trail is the failure an audit
trail exists to prevent, and it would be issued by accident within a week.

### A hash chain over audit events

Rejected as machinery ahead of a requirement. A chain needs a verifier that runs, an
alarm when it breaks, and an answer for what to do when it does — none of which the
canonical architecture asks for, and all of which would be built on speculation. The
property that is available today, and is asserted, is that no role can modify a row.

### Keeping `app_current_tenant_id()` beside the new functions

Rejected. A function that looks like the tenant-context mechanism and is not one is worse
than no function at all: the next reader of a policy would find two candidates and no way
to tell which one decides. It is dropped, and a test asserts it is gone.

### Letting the provisioning role name the tenant it provisions

Rejected once the argument was written down. It would have preserved Milestone 2.1's
ability for a privileged role to select any tenant, in the one place nobody would look for
it. Generating the id inside the database costs nothing and removes the capability.
