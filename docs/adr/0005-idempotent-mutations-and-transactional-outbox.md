# ADR 0005: one committed effect and one linked outbox event, decided by the database

- **Status:** Accepted
- **Date:** 2026-09-03
- **Decision owners:** Firmbatch product owner and maintainers
- **Milestone:** 2.2, idempotent mutations and the transactional outbox
- **Related:** `docs/architecture/v1-target-architecture.md` sections 3.1, 3.2 and 17;
  `docs/architecture/v0-to-v1-migration-audit.md` sections 10 and 11; ADR 0003; ADR 0004

## Context

The Milestone 2 completion gate has two halves. ADR 0004 delivered the first — cross-tenant
reads and writes fail closed. This is the second: **duplicate mutations produce one
contractual effect.**

The product is a durable obligation. A customer submits a job, the connection drops, and
the customer's SDK retries. If that retry creates a second job, the customer is billed
twice for one obligation and Firmbatch has manufactured work nobody asked for. The same
shape recurs everywhere the roadmap is going: accepting a quote, admitting a spend
envelope, claiming a shard, settling a period.

Two target invariants bear on it directly:

- **Invariant 1** — PostgreSQL is authoritative; queues and providers are reconciled
  observations. So a state change and the message announcing it cannot be two independent
  writes to two systems: one of them will fail, and the surviving half will be believed.
- **Invariant 3** — customer payload bytes never pass through the API process or
  PostgreSQL. So whatever an idempotency record keeps about a request, it cannot be the
  request. This ADR takes the invariant as a *constraint on its own design* and does not
  claim to establish it; the data-flow proof is Milestone 5's presigned S3 path.

v0 has a partial version of this and it is instructive. `control/db.py` upserts results
keyed `(job_id, request_id)`, which makes a duplicate *result* harmless. It has nothing
for duplicate *mutations*, no event record at all, and no tenant to scope a key to.

## Decision

### 1. An idempotency key is scoped by tenant and operation, never globally

`uq_idempotency_records_tenant_id_operation_idempotency_key`. A globally unique key space
would be a hole in the boundary ADR 0004 built: one tenant's key could collide with
another's, which is a cross-tenant read wearing a helpful name, and a caller could probe
for the existence of another tenant's key by observing a conflict.

Scoping by operation as well means `create` and `cancel` may share a key without one
replaying the other's result. That is one column and it removes a class of bug that would
otherwise be found in production.

### 2. There is no durable "in progress" record

The obvious design claims the key first with a `pending` row, commits that, performs the
mutation, and updates the row to `completed`. It is also the design that requires a
recovery system: a process that dies between the two commits leaves a `pending` row that
nothing will ever finish, and every later caller must decide whether to wait, take over,
or fail. Milestone 2.2 does not build a recovery system, and shipping the row without the
system that interprets it would be shipping the problem.

So **everything commits together or not at all**: the business mutation, the completed
idempotency record, and the outbox event are one transaction. Before `COMMIT` nothing
durable exists; a process that dies at any point leaves no row, and the retry that
follows takes the ordinary first-attempt path. `ck_idempotency_records_status_completed`
holds the `status` column to one value, so a future contributor who wants two phases has
to change the schema in the open rather than start writing a new value into a column that
already accepts anything.

### 3. The concurrency control is a unique index, not a lock in the process

Two transactions claiming one key serialise on the unique index: the second blocks until
the first commits, then sees a unique violation. Nothing in Python holds a lock.

This is not a stylistic preference. The control plane is one image run in three roles and
will be several processes on several machines; an in-process mutex is a guarantee that
evaporates the moment the second replica starts, and it evaporates *silently*, under
load, in production. A PostgreSQL advisory lock was considered and rejected: it would
avoid the loser's rolled-back attempt, but it introduces a second locking protocol with
its own deadlock-ordering rules for a benefit the transaction already provides.

`control_plane/tests/test_idempotency_concurrency.py` proves the property under real
contention rather than by argument. One caller is held with its claim written and
uncommitted; a third connection watches `pg_stat_activity` until the second caller is
observably waiting on a lock; only then is the first released. If the block is never
observed the test fails, because a concurrency test that silently degrades to a
sequential one is worse than no test.

### 4. The loser of a race replays, and its own work is rolled back to a savepoint

The mutation, the claim and the event run inside one `SAVEPOINT`. A caller that loses the
race rolls that savepoint back — undoing the business row it had already written — then
re-reads the winner's committed row and returns the winner's stored result.

Two consequences, both deliberate:

- **`mutate` may run more than once, but commit at most once.** So it must confine itself
  to the database it is handed. A function that sent mail or spent money inside it would
  do so from a transaction that never commits. That restriction is the reason the outbox
  exists: side effects are *recorded* in the transaction and *performed* afterwards.
- **The decision is "is this key taken now", not "which index raised".** A duplicate
  request usually violates a business constraint before it ever reaches the claim index —
  two callers creating the same workspace collide on the workspace slug first. So the
  recovery path re-reads the key and replays if it is taken, and re-raises the caller's
  own integrity error if it is not.

### 4a. The mutation is given a unit of work, not the caller's `Session`

The first version of this design passed the `Session` straight to the callback, with the
"database work only" rule written in a docstring. That was wrong, and wrong in a way that
defeats the whole primitive: **`Session.commit()` in SQLAlchemy 2.x commits the outermost
transaction even while a `begin_nested()` SAVEPOINT is open.** A callback that called it —
by habit, by copying code from a script, or through a helper that manages its own
transactions — would commit its business row *before* the claim and the event were
written, producing exactly the duplicate effect this ADR exists to prevent, with no error
anywhere.

So the callback is handed a `MutationUnitOfWork`. It forwards what a mutation legitimately
needs (`add`, `flush`, `execute`, `get`, `scalars`, `delete`, `merge`) and refuses, with an
explanatory error, everything that would take the transaction away from the primitive:
`commit`, `rollback`, `close`, `begin`, `begin_nested`, `connection`, `get_bind`,
`expunge_all`, and the legacy bulk API. It duck-types as a `Session`, so the repositories
in this package work through it unchanged.

**The contract, stated rather than implied.** A mutation performs rollback-safe
transactional DML through the unit of work and nothing else: no provider calls, no email,
no spending, no session or connection commits, no session-scoped advisory locks (the
transaction-scoped ones are released by a rollback; the session-scoped ones are not), no
file or queue writes, no outbound HTTP. A losing concurrent caller's mutation **is
executed and then rolled back**, so any effect a `ROLLBACK` does not undo will have
happened for a transaction that never committed.

**And the commit is refused before it happens, not noticed after it.** The unit of work
alone does not close this: the real `Session` is one `object_session(some_mapped_row)`
away. A first attempt at the problem relied on re-checking the transaction after the
callback returned, and that was wrong — by then the business row is committed with no
claim and no event, which is precisely the partial state this ADR exists to prevent, and a
later retry collides with a surviving row that nothing explains. **Nothing in Python can
un-commit.**

So for the duration of the callback, and only for that duration, the primitive attaches a
`before_commit` listener to the real `Session` and raises `MutationContractError` from it.
`before_commit` is dispatched at the top of `SessionTransaction._prepare_impl`, ahead of
the flush a commit performs, so the escape is refused with nothing written and nothing
committed. The listener is removed in a `finally` — before the primitive releases its own
SAVEPOINT, which itself dispatches `before_commit` because the transaction is nested, and
long before the caller commits the real transaction. Nothing is left attached to a session
that outlives the call.

`_require_intact_boundary` remains, and its role is now stated accurately: **secondary
detection** of a boundary destroyed some other way — a rollback reached through the real
`Session`, most obviously — where a rollback has already discarded the work and there is no
atomicity left to preserve. It is not, and is no longer described as, something that turns
a commit into a non-commit.

**What is still outside the guarantee.** The unit of work and the commit guard are an
accident-prevention guardrail for an aligned caller, not a sandbox against arbitrary
Python. A callback that opens its own engine or connection, drops to the DBAPI, or issues
`COMMIT` as raw SQL is operating outside this transaction and outside anything this module
can observe. That is the same position `AGENTS.md` takes about the policy engine, and it is
recorded rather than papered over.

### 4b. Pending ORM state at entry is rejected

`Session.begin_nested()` **flushes** whatever is pending before it emits the `SAVEPOINT`.
A row the caller added and did not flush would therefore be written *outside* the boundary
the primitive rolls back to, and would survive a lost race that discards everything else —
so the "one committed effect" guarantee would silently depend on what the caller happened
to leave lying around.

The primitive refuses at entry if `session.new`, `session.dirty` or `session.deleted` is
non-empty, and says why. Rejecting is the honest fix; absorbing the pending state into the
savepoint is not possible, and ignoring it would make the guarantee conditional on
something no caller thinks about.

**The check covers pending state only, and the rest is a contract.** A write the caller has
already *flushed* is in none of those three sets, so nothing here can detect it — and it
sits in the caller's outer transaction, outside the SAVEPOINT, where a lost race that
discards the mutation would leave it in place. The rule that closes that gap is stated
rather than enforced:

- **every business write belonging to the operation happens inside `mutate`**;
- **the primitive is called before any DML for that operation**.

The caller's own transaction still covers the ordinary failure — a process that dies before
`COMMIT` loses both writes, because they share one transaction even though they do not
share the savepoint. What it does not cover is a lost race, and that is why the rule is a
rule.

### 5. `READ COMMITTED` is required, and anything else is refused

That recovery re-read is only correct where each statement takes a fresh snapshot. Under
`REPEATABLE READ` or `SERIALIZABLE` the re-read runs against the transaction's older
snapshot, finds nothing, and the caller is told the key is free when it is not — a wrong
answer rather than a slow one. The isolation level is therefore checked and the wrong one
is refused with an explanation, rather than silently mishandled.

### 6. Outbox events carry bounded metadata, are append-only, and hold no delivery state

An event names what happened (`event_type`), what it happened to (`aggregate_type`,
`aggregate_id`), and carries a small bounded `attributes` object of identifiers, counts,
digests and references. It is not a message envelope, and it is not where a payload goes.

**Append-only is enforced twice, in two different directions:**

- the application role holds `SELECT, INSERT` and nothing else, so an `UPDATE` or `DELETE`
  is an error it can see;
- the tables carry **no `UPDATE` and no `DELETE` policy at all**, so any role that somehow
  held the privilege — including the table owner, since row security is `FORCE`d — reaches
  no row.

The second is the half a grant cannot buy. Revoking `UPDATE` from today's application role
says nothing about tomorrow's roles, and nothing about the owner. One route stays open by
design and is named rather than hidden: deleting a *tenant* cascades, and referential
actions are not subject to row security. No runtime role holds `DELETE` on `tenants`.

When a dispatcher exists (Milestone 6), its delivery state — attempts, last error, next
visible time — belongs in a **separate table** keyed by event id. Putting a mutable
`delivered_at` on the event would make the event row mutable, and then "the event content
is immutable" would be a claim about which columns people remember not to touch.

### 7. **At most one** linked event per claim, and the constraint says only that

`uq_outbox_events_tenant_id_idempotency_record_id` enforces that a claim carries no more
than one linked event. It **cannot** enforce that a claim has one: a unique constraint
bounds duplicates, it does not require existence. An earlier draft of this ADR said "one
committed mutation, one durable event — as a database fact", and that was an overclaim.

Stated accurately, and consistently in the code, the tests, `docs/STATE.md` and
`docs/tasks/current.md`:

- **the primitive writes exactly one linked event**, in the same transaction as the claim;
- **the database prevents more than one**;
- **atomicity is proved by the primitive's PostgreSQL tests**, which commit and then count
  the claim and its event together — not by the schema.

A deferred constraint trigger could turn "every claim has an event" into a database fact,
and is deliberately not built: it would be real machinery added to preserve a sentence,
and the tests already prove the property the machinery would assert.

The link is a **causation link**, and it is optional — see decision 7a. When it is present
the event references its claim on `(id, tenant_id)` against the composite unique key,
because PostgreSQL performs referential-integrity checks with row security bypassed: a
single-column `REFERENCES idempotency_records(id)` would happily attach an event to
another tenant's claim. This is the first use of the composite-key convention ADR 0004
section 5 established for exactly this reason.

### 7a. The outbox is not a feature of API idempotency

`idempotency_record_id` is **nullable**. The transactional outbox belongs to every
authoritative state transition, not only to mutations a customer submitted with a key: the
controller, the reconciler, the validator and the lifecycle machines of Milestones 4 to 6
all need to commit an event with the state change that caused it, and none of them has a
caller-supplied idempotency key.

Requiring one would mean manufacturing a claim per internal transition — rows nobody can
ever retry against, in the table that exists to record retries — and would leave the first
contributor who needs an internal event choosing between that and bypassing the outbox.

So `append_outbox_event(session, event, idempotency_record_id=None)` is the one writer, and
`execute_idempotent_mutation` calls it with the claim it just wrote. The tenant scoping is
unchanged either way: the event carries `tenant_id`, forced RLS applies, and the composite
foreign key still holds a *linked* event in its claim's tenant. An unlinked event is exempt
from that foreign key rather than dangling against it, because a composite `MATCH SIMPLE`
reference is satisfied when any of its columns is NULL, and unlinked events do not collide
on the unique constraint because PostgreSQL treats NULLs as distinct.

What is **not** built here: the dispatcher, SQS integration, delivery state, global
(non-tenant) events, and fan-out.

### 8. The primitive takes a request *identity*, not a request body

The parameter is `request_identity`, and it is **bounded metadata**: identifiers, counts,
digests, and references to objects that live elsewhere — `input_manifest_id`,
`output_object_key`, `artifact_digest`. It is validated against the metadata policy
**before the mutation runs**, then hashed; `request_fingerprint` is a hex SHA-256 digest
over the canonical JSON of `{tenant, operation, request_identity}` — sorted keys, no
insignificant whitespace, tenant and operation folded in as domain separation. Reusing a
key with a different digest is rejected as `IdempotencyConflict`; reusing it with the same
digest replays.

This started out as an arbitrary `request` mapping, and the test that went with it passed
a raw prompt and an API key and treated hashing them as compliance. That codified the data
flow the target architecture forbids: the argument reached the API process at all. Naming
the parameter for what it must be, and validating it before anything runs, is the fix.

**Be precise about what this establishes.** M2.2 proves that **the primitive persists only
a fingerprint and bounded metadata**. It does not prove that customer payload bytes never
enter the API process or PostgreSQL — that is target invariant 3, and its data-flow proof
is Milestone 5's presigned S3 path, where payload moves directly between the customer and
S3 and the API handles references only.

### 9. The metadata policy is defense in depth, and is not a proof

`db/idempotency.py` refuses, at the boundary where a caller gets a usable error: nested
objects, binary values, strings over 256 characters, documents over 2 KiB, more than 32
keys, keys that are not lowercase identifiers, and keys whose **whole name** is one of a
curated list meaning the content itself (`payload`, `prompt`, `input`, `api_key`,
`password`, `access_token`, …). Check constraints in migration `0002` bound the same
documents in the database, as the backstop for a writer that bypasses the module.

**Whole names, not substrings.** The first version matched substrings, and it was wrong in
the direction that matters: it rejected `input_manifest_id`, `output_object_key` and
`artifact_digest` — which are exactly the references this table exists to hold — while
doing nothing about a payload spelled under a name it had not thought of. Matching whole
names keeps the legitimate vocabulary usable and keeps the rule honest about its scope.

**And none of it is a proof, so it must not be cited as one.** Three claims were removed
from this repository because they were false:

- *"no `bytea` means PostgreSQL cannot store payload bytes"* — `TEXT` and `JSONB` hold
  text, and an encoded payload is text. The absence of a binary column makes it
  inconvenient, not impossible.
- *"256 characters is not a payload"* — 256 characters is a short payload.
- *"bounded JSONB proves no secrets or content are present"* — a bound is a size limit,
  not a semantic filter. No name rule or length limit can tell content from a reference.

What the bounds and the denylist do is stop the obvious mistake at a place where the
caller gets a clear error. What proves the data flow is Milestone 5.

### 10. Role grants were extended, not widened

The application role gained `SELECT, INSERT` on the two new tables. The provisioning role
gained **nothing** — it creates tenants; it has no business reading another role's
idempotency keys or the events they produced. Neither runtime role gained ownership, DDL,
`SUPERUSER`, `BYPASSRLS`, `REPLICATION`, `CREATEDB` or `CREATEROLE`, and
`control_plane/tests/test_outbox_isolation.py` asserts each of those from the live
catalogue rather than from the grant source.

Grants stay outside Alembic for the reason ADR 0004 section 4 gives: role names are
environment-specific, and a migration that hard-codes one is either non-deterministic or
wrong somewhere.

## What this does not claim

**Not exactly-once external delivery, and nothing here should be read as claiming it.**
The outbox records durable intent. No dispatcher exists. When one does it will deliver
**at least once**, SQS will duplicate and reorder, and consumers must be idempotent
themselves. What is proved at M2.2 is narrower and checkable: **one committed database
effect and one durable outbox event per (tenant, operation, key)**.

**Not protection against a compromised runtime credential.** Everything here sits inside
the boundary ADR 0004 §8g describes. An attacker who can set `app.tenant_id` can claim
keys in any tenant they can name. `AUTH-BOUND-TENANT-CONTEXT` still blocks customer-facing
deployment.

**Not a payload-plane proof.** M2.2 shows that the primitive persists a fingerprint and
bounded metadata, and that payload- and credential-shaped fields are refused before a
mutation runs. It does not show that payload never reaches the API process or PostgreSQL.
Milestone 5 owns that.

**Not "every claim has an event", by constraint.** The uniqueness constraint bounds
duplicates only; see decision 7.

**Not a sandbox around the mutation callback.** The unit of work removes the reflex route
out of the transaction and the boundary check turns any other escape into a raised error.
A callback determined to reach the real `Session` still can, exactly as `AGENTS.md`
describes the policy guard: a guardrail for an aligned caller, not a security boundary.

**Not an expiry or retention policy.** Idempotency records accumulate and nothing prunes
them. Pruning needs a `DELETE` policy, which these tables deliberately do not have, so it
is a schema change made on purpose rather than an operational script somebody writes at
3am. Deferred with the dispatcher.

**Not an HTTP surface.** There is no endpoint, no `Idempotency-Key` header parsing, and no
API framework. Milestone 3 owns that; the primitive is what it will call.

**Passing tests are not deployment proof.** Under this repository's taxonomy the behaviour
here is implemented and tested, not VERIFIED LIVE. No evidence artifact has been captured.

## Consequences

- Every mutating operation from Milestone 3 onward has one place to be idempotent, and a
  contributor who writes a new one without it is visibly not using the primitive.
- `mutate` functions are constrained to database work, through a handle that refuses
  transaction control rather than a docstring that asks them not to use it. Anything else
  goes through the outbox, which is the discipline invariant 1 requires anyway.
- A caller may not enter the primitive with unflushed ORM state. In practice the
  repositories in this package flush eagerly, so this costs nothing and removes a
  conditional guarantee.
- The outbox is usable by internal transitions from the day it exists, so Milestone 6 does
  not have to reshape the table or invent a fake claim to use it.
- The outbox is inert until Milestone 6 builds a dispatcher. Events accumulate and nobody
  reads them; that is a known and accepted intermediate state, not an oversight.
- Two more tables inherit the isolation boundary, and `TENANT_SCOPED_TABLES` /
  `APPEND_ONLY_TABLES` mean a future table added without policies fails the suite.
- The suite now depends on observable lock waits in `pg_stat_activity`. On a server where
  that view is restricted, the contention test fails rather than silently degrading.

## Rejected alternatives

### A two-phase claim with a `pending` row

Rejected under decision 2. It is the standard design and it is correct only alongside a
recovery process — a reaper that decides when a `pending` claim is abandoned, and on what
evidence. Building the row without the reaper produces a system that deadlocks on its own
records the first time a process is killed, which is a thing this product's chaos testing
does deliberately.

### An advisory lock taken before the mutation

Rejected under decision 3. It would spare the loser its rolled-back attempt, at the price
of a second locking protocol, hash collisions across tenants, and deadlock ordering rules
for any caller that ever claims two keys. The unique index is already authoritative; a
lock in front of it is a performance optimisation wearing a correctness argument.

### An in-process mutex or a cache of recent keys

Rejected outright. It stops being a guarantee at the second replica, and it stops silently.

### Passing the caller's `Session` to the mutation and documenting the rule

This is what the first implementation did, and it is the finding that produced decision
4a. A documented rule is worth nothing against `Session.commit()`, which is one word, is
what a contributor writes by reflex, and commits the outermost transaction from inside a
SAVEPOINT without complaint. The unit of work makes the reflex an error.

### An inner `Session` joined with `join_transaction_mode="create_savepoint"`

SQLAlchemy's documented pattern for this, and genuinely stronger: an inner session's
`commit()` releases a savepoint rather than committing. It was rejected here because
`db/engine.py` **refuses** a `Session` bound to an already checked-out `Connection` from a
hardened pool — an M2.1 control, with its own tests, whose whole point is that binding an
existing connection skips the checkout hardening. Taking this option meant carving an
exception into that refusal. The unit of work achieves the same practical result inside
this module, with no change to an M2.1 security control.

### A substring denylist on metadata key names

Rejected under decision 9 after it rejected `input_manifest_id` and `output_object_key`,
which are the metadata the table is for. A rule that blocks the vocabulary of the correct
design in order to look strict against the wrong one is a bad trade.

### Requiring an idempotency record for every outbox event

Rejected under decision 7a. It would force every internal state transition to manufacture
a claim nobody can retry against, or to skip the outbox.

### A deferred constraint trigger asserting that every claim has an event

Rejected under decision 7. It is real machinery whose only purpose would be to make an
earlier, inaccurate sentence true. The tests prove the property; the wording was corrected
instead.

### A monotonic sequence column on the outbox

Tempting for a dispatcher, and rejected: a cluster-wide sequence is shared across tenants,
so the gaps in one tenant's numbers measure another tenant's write volume. That is the same
leak that makes workspace slugs tenant-local under ADR 0004 section 5. A dispatcher orders
by `(occurred_at, id)` within the tenant it is reading.

### Storing the request body alongside the fingerprint

It would make conflicts easier to debug. It would also put customer request content in
PostgreSQL, which invariant 3 forbids, and it would make the idempotency table the most
attractive thing in the database to steal. The digest answers the only question the
primitive asks of it.

### Mutable delivery state on the event row

Rejected under decision 6. Immutability that depends on which columns people remember not
to touch is not immutability.

### An `UPDATE` policy restricted to rows created in the current transaction

Considered in order to allow a claim-then-fill-in-the-result design without giving up
append-only. It is expressible — a policy over `xmin` — and it is exotic enough that its
correctness would rest on a reviewer's familiarity with PostgreSQL system columns. Decision
2 removes the need for it.
