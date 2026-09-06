# ADR 0007: a lifecycle is a versioned graph in PostgreSQL, and a move is a compare-and-swap

- **Status:** Accepted
- **Date:** 2026-09-05, amended 2026-09-06 after two independent review passes (decisions
  4a-bis, 4d, 8e and 8f, and the extensions to 4b, 8d, 10 and 13, record the second), and
  amended again the same day after a third (decisions 8g and 8h, and the corresponding
  changes to "What this does not claim", "Consequences" and the rejected alternatives)
- **Decision owners:** Firmbatch product owner and maintainers
- **Related:** `docs/firmbatch-v1-roadmap.md` Milestone 2;
  `docs/architecture/v1-target-architecture.md` §5.1, §12.1, §17;
  `docs/architecture/v0-to-v1-migration-audit.md` §10 Milestone 2;
  ADR 0004 (tenant isolation), ADR 0005 (idempotency and outbox), ADR 0006 (authenticated
  context, authorization, audit)

## Context

The canonical roadmap lists **explicit lifecycle state machines** as the last declared item
of Milestone 2's shared foundation, and the migration audit states the test that has to
replace v0's trust: *"lifecycle transitions are conditional and invalid transitions cannot
race through"* (§10, Milestone 2).

What v0 does instead is the reason that sentence exists. A job is inserted directly as
`running`, and `set_job_status` writes any status over any other with no guard at all
(`control/db.py:116-151`); the migration audit marks the whole area **Replace**. There is no
notion of a legal move, no record of who made one, and nothing that stops two writers from
both deciding.

Three properties of the milestones after this one make the shape of the answer non-obvious:

1. **The domain is not here yet.** Jobs are Milestone 5; window offers, attempts and leases
   are Milestone 6. A lifecycle foundation built now has nothing real to attach to.
2. **The graphs are already drawn.** The target architecture specifies the job lifecycle
   (§5.1) and the window-offer machine (§12.1) as diagrams. They are product intent, and
   neither is fully specified: §5.1 shows no cancellation edges from most states, and §12.1
   does not say what happens to an accepted window whose job is admitted and then withdrawn.
3. **The commercial edges are contractual.** "An accepted quote is immutable" (§5.1,
   invariant 7) and "acceptance, not offer, is the commercial event" (§12.1) mean a wrong
   edge in a state machine is a wrong contract, not a bug.

So the question this ADR answers is not "what are the states" but "what is the smallest
mechanism that can hold a state machine safely, and what must it refuse to be".

## Decision

### 1. A lifecycle kernel, not a workflow engine

Milestone 2.4 builds a fixed-purpose kernel: immutable versioned definitions, tenant-owned
instances, and one conditional transition primitive. It has no expression language, no
scripting hook, no timers, no compensation, no retries and no scheduler. A machine is data
**we** author in a migration, and the only thing the runtime may do with one is move an
instance along an edge that already exists.

The alternative — a customer-configurable workflow product — is rejected under "Rejected
alternatives" below. The short version is that a configurable graph makes "what may a
customer's workflow do?" a question this system would have to answer, and every honest
answer to it is a sandbox.

### 2. No production machine is registered, and that is the decision

Migration `0004` registers **no** machine. The job lifecycle and the window-offer machine are
Milestone 5 and 6 definitions, and they land with the domain tables they describe.

Three reasons, in order of weight:

- **A graph is a product decision.** §5.1 and §12.1 establish intent and are not
  edge-complete, and the prompt for this milestone is explicit that M2.4 must not invent
  cancellation, failure, retry, reconciliation or commercial edges that belong to M5 and M6.
  Registering a partial job machine here would put a graph nobody had reviewed *as a
  contract* into every production database.
- **A definition is immutable.** Since a registered version can never be revised (decision 5),
  a guess made now could only be corrected by a version 2 that every later reader would have
  to know to prefer.
- **The working contract forbids it.** Implementing later-milestone work opportunistically is
  what §7.5 rules out, and a job lifecycle without a job is exactly that.

Tests install explicitly test-only definitions (`test_workflow`, `test_restricted`,
`test_cyclic`) into their own disposable database, through the owner.
`test_lifecycle_definitions.py::test_a_fresh_database_carries_no_lifecycle_definition`
asserts that a freshly migrated database carries none — so "we seeded nothing" is a checked
fact rather than a sentence here.

### 3. Definitions are global, protected and versioned

`lifecycle_machines`, `lifecycle_states` and `lifecycle_transition_edges` hold one immutable
graph per `(machine_key, version)`.

**Global, not tenant-owned.** Two tenants running `job` version 3 are running the same 3.
The target architecture already draws this line — "every tenant-owned authoritative row
carries `tenant_id`; shared provider and certification records are explicitly global" (§3.1)
— and a machine definition is a shared record in exactly that sense. Per-tenant graphs would
mean a per-tenant product.

**Protected, not policed.** No runtime or provisioning role holds any privilege on the three
tables, so they carry no row-level-security policy: a policy bounds a role that has
privileges, and here none does. They are in the same `PROTECTED_TABLES` catalogue as
`auth_bindings` and `auth_transaction_context`, so the ACL sanitiser, the `db/principal.py`
connect-time check, the column-ACL check and the hardening tests all cover them without a
special case.

The reason they must be protected is specific and worth writing down: **the required scopes
live in them**. A role that could write `lifecycle_machines` could lower the capability its
own instances demand; a role that could insert into `lifecycle_transition_edges` could make
any transition legal, for every tenant at once.

**Versioned, and an instance pins its version.** `lifecycle_instances` carries
`machine_version`, and every reference from the history is composite on it. So an instance
created under version 1 keeps meaning what it meant when version 2 is registered.

### 4. Registration is an owner-run admin action, outside Alembic, and it publishes last

`register_lifecycle_definition(connection, definition)` takes a `Connection`, not a
`Session`, and the type is the cheapest way to say what it is: an owner action, like the
grants in `db/roles.py`.

Outside Alembic for the same reason role wiring is: *which* definitions a deployment needs is
a property of which milestones it runs, not of the schema. A later milestone registers its
machines alongside its domain tables, in whatever unit of work makes those tables consistent.

### 4a. Draft, then publish — and only a published definition is consumable

A definition is assembled over several statements: the machine, then its states, then its
edges. Between the first and the last it is a **partial graph** — no initial state yet, or
states with no edges — and the first version of this milestone let every consumer read it in
that condition. A concurrent reader could resolve half a machine, and a registration that
failed at its fourth statement had already made three rows visible to anything that looked
before the rollback.

So `lifecycle_machines` carries `published_at`, and:

- registration inserts the machine **unpublished**, then its states, then its edges;
- the **last** statement is `firmbatch.publish_lifecycle_machine()`, in the same
  transaction;
- every consumer — the required-scope reader, the initial-state reader, the terminal reader,
  the edge reader, and therefore every policy, every trigger and both entry points — requires
  `published_at IS NOT NULL`. A draft has no scope, no initial state, no terminal states and
  no edges as far as anything that uses one is concerned.

**Publication is also where whole-graph properties are checked**, because it is the only
moment a definition claims to be complete:

- exactly one initial state, and *at least* one. The partial unique index bounds it above and
  cannot require existence — the same limit the Milestone 2.2 outbox link has, and the same
  answer: the property the constraint cannot state is checked where completeness is declared.
- every edge endpoint is a declared state (the foreign keys hold it too);
- no outgoing edge from a terminal state. The insert trigger catches an edge added *after* a
  state was marked terminal; publication catches the other order, where the state is marked
  terminal after its edges were written;
- the three declared scopes are eligible.

### 4a-bis. Publication is a boundary, not a path

Those rules lived inside `publish_lifecycle_machine()` in the first correction, and a
function is a **path** rather than a boundary: they applied to callers who chose to come
through it. The schema owner — the only identity that can reach these tables at all, and the
one that runs registration — could publish an arbitrary graph with

```sql
UPDATE firmbatch.lifecycle_machines SET published_at = now() WHERE ...;
```

and every consumer would then resolve it. And `published_at` could arrive already set on the
`INSERT`, which produced a published machine with no states, no edges and no validation of
any kind, because the validation was attached to the *update* that publishes.

Both are closed by moving the rules onto the table:

- a `BEFORE INSERT` trigger refuses a machine row that arrives published, so every machine is
  born a draft;
- a `BEFORE UPDATE` trigger carries the whole publication validation, so the supported
  function and a hand-written `UPDATE` run identically. `publish_lifecycle_machine()` is now
  a lock, two nicer error messages, and the statement;
- the publication instant is `clock_timestamp()`, written by the trigger. A caller that could
  supply it could date a definition into the past or the future, and `published_at` is what
  every consumer tests.

### 4b. One transaction, enforced by the database rather than by the driver

The publication trigger requires every row of the definition — the machine, every state,
every edge — to carry **this transaction's** `xmin`. A definition whose pieces became durable
independently cannot be published, however it got that way.

That is what refuses an `AUTOCOMMIT` registration, and it refuses more than that: a machine
whose states committed in one transaction and whose edges committed in another was, for a
while, a publishable definition that no single rollback could take back. The Python registrar
also reads the driver's autocommit flag and refuses early, but that check is a courtesy — it
is the `xmin` comparison that holds.

### 4c. A published version is sealed in every direction

- `INSERT` on states and edges is refused once the machine is published;
- `UPDATE` and `DELETE` on states and edges are refused always;
- `DELETE` on a machine row is refused always;
- `UPDATE` on a machine row is refused **except** for the single transition that publishes
  it: unpublished to published, with every other column unchanged. So there is no
  unpublishing, no republishing, and no editing of published metadata.

**What that does not claim.** A trigger binds ordinary DML, including the schema owner's. It
does not bind a superuser, and it does not bind an owner who first runs
`ALTER TABLE ... DISABLE TRIGGER` or sets `session_replication_role = replica`. Both are
deliberate, DDL-shaped acts by a role this design already trusts with the definitions
themselves — the same position ADR 0006 takes about the migration owner. What the triggers
buy is that no accident and no ordinary statement can revise a published definition.

### 4d. Publication and the graph serialise on one lock

Reading `published_at` is not deciding on it while somebody else may change it in between.
The first version of the child trigger read it without a lock, so

```
T1: insert an edge; sees the machine unpublished; proceeds
T2: publish; validates a graph that does not contain T1's edge; commits
T1: commits
```

left a *published* machine carrying an edge nothing had ever validated.

So there is exactly **one lockable object**: the machine row. Publication takes `FOR UPDATE`
on it before it inspects any child, and every state and edge insert takes the same lock
before it reads the publication column and again re-reads that column from the row the lock
hands back. One object and one order, so there is nothing to deadlock against; an edge locks
the *machine* rather than the states it names, because an edge's parent is the machine and a
state row is not something publication locks. The child triggers are `BEFORE` triggers, and
on edges the publication trigger sorts before the terminal-source one by name, so the lock is
held before anything else reads a definition row and before the composite foreign keys, which
are `AFTER` triggers.

`UPDATE` and `DELETE` on a state or an edge are refused unconditionally, so neither can race
a publication at all — which is also why "an update moving a row between machine parents must
lock both parents in a deterministic order" has nothing to implement: no update reaches a row
to move.

**And the original interleaving is unreachable rather than merely refused**, while 4b stands.
The bad sequence needs two transactions to touch one definition while one of them publishes,
and both halves are closed by different rules: a machine created in an uncommitted
transaction is invisible to any other connection, so a concurrent child cannot even name it;
and a machine that *is* committed cannot be published, because its rows carry another
transaction's id. The lock is what makes that true for the window where the two rules hand
over to each other. It is belt to 4b's braces, and the tests say which is doing what.

### 5. A registered version is immutable, and a change is a new version

A `BEFORE UPDATE OR DELETE` trigger on all three definition tables refuses the write — for
the **schema owner** as well as for every runtime role, and with row security not enabled on
them at all, so nothing else stands in the way.

That binds harder than a grant or a policy could, and it has to. Every existing instance and
every history row is interpreted against its definition: "this job is `partial`" means what
the machine says `partial` is. Revising a definition in place would silently change the
meaning of rows already written, which is precisely the failure an append-only history exists
to rule out.

The escape hatch is a migration that drops and recreates the object — DDL, in the open, in
the version history.

### 6. The graph rules, and the ones deliberately not imposed

**Enforced**, in Python at the registrar and again in the schema:

| Rule | Where the schema enforces it |
| --- | --- |
| Every edge endpoint is a declared state | composite foreign keys to `lifecycle_states` |
| An instance's state is a declared state | composite foreign key to `lifecycle_states` |
| Exactly one initial state per version | partial unique index on `is_initial` |
| No duplicate state, no duplicate edge | primary keys |
| No outgoing edge from a terminal state | `BEFORE INSERT` trigger on the edge table |
| Machine keys and state names are lowercase identifiers | check constraints |
| A version is a positive integer | check constraint |
| A required scope is in `LIFECYCLE_ELIGIBLE_SCOPES` | check constraint |

**Two further rules are imposed and are documented as additions**, because neither is derived
from a product requirement:

- **Bounds.** At most 64 states and 512 edges per version. A definition is data that every
  policy evaluation reads, and unbounded data in that position is a cost nobody chose. A
  machine needing more than this is a machine that should be several. **These two are
  enforced in the registrar only, not by the schema**, and the asymmetry is deliberate:
  registration is an owner action with exactly one supported path, so the registrar is the
  boundary rather than a courtesy in front of one. An owner writing the inserts by hand can
  exceed them, and an owner writing the inserts by hand has already stepped outside the
  supported interface. Every rule in the table above is enforced in *both* places, because
  each of those is a correctness property rather than a bound.
- **Eligible scopes exclude `tenant:provision`.** It is acquired from
  `begin_tenant_provisioning()` and cannot be placed on any credential, so a machine gated
  on it would be *unreachable* rather than protected. Catching that at registration is
  cheaper than discovering it when the first transition is refused for a reason nobody can
  act on.

**Three rules are deliberately not imposed**, and each is a test rather than a sentence so
that adding one later is a deliberate act:

- **Acyclicity.** A cycle is a legitimate machine — `offered -> accepted -> revoked ->
  offered` is in §12.1, and re-leasing a shard is in §10. Self-edges are permitted too: a
  move that changes only the revision is a real thing to want.
- **Reachability.** A state no edge leads to is odd and is not wrong; a definition may be
  built up across versions.
- **An outgoing edge from every non-terminal state.** A dead end that is not marked terminal
  is a definition mistake this kernel is not entitled to diagnose on a domain's behalf.

### 7. The required capability comes from the definition, never from the caller

A machine version declares `read_scope`, `create_scope` and `transition_scope`. Every policy
on `lifecycle_instances` and `lifecycle_transitions` reads it through
`firmbatch.lifecycle_required_scope(machine_key, machine_version, <literal>)` — a
`SECURITY DEFINER` reader over the protected definition.

So "who may move this" is a property of the machine, stored where the runtime cannot write
it, and no caller ever states a required capability. The capability argument is a literal at
every call site — three policies and two entry points — and an unrecognised one returns
`NULL`, which `auth_has_scope` coalesces to `false`.

**This does not reopen the closed catalogue.** A definition may name only a scope that
already exists (§5's `KNOWN_SCOPES` minus `tenant:provision`), enforced by a check
constraint. Milestone 2.4 adds **no scope**, and there is deliberately no `lifecycle:*`
wildcard: a machine reuses an existing customer capability, which keeps "who may move this
job" the same question as "who may write this job" rather than making it a second, parallel
one that has to be kept in step.

`lifecycle_required_scope` is granted to the application role, and that grant is necessary
rather than convenient: a policy is evaluated with the querying role's privileges, so a role
without `EXECUTE` could not read its own instances at all. What it discloses is which
capability a global, immutable machine version requires — a fact about the closed catalogue,
not about any tenant — and knowing the answer confers nothing, because the caller still has
to hold the scope.

### 8. A transition is one conditional `UPDATE`, and the graph is enforced underneath it

`firmbatch.transition_lifecycle_instance(instance_id, expected_state, expected_revision,
target_state, reason, details)` performs, in the caller's transaction:

1. resolves the instance **inside the authenticated tenant**;
2. derives the required capability from the machine version the instance pinned;
3. compares the caller's expectation to the persisted row;
4. confirms the target is a declared edge from the persisted current state, and that the
   source is not terminal;
5. performs **one conditional `UPDATE`** whose predicate carries the tenant, the instance,
   the machine version, the expected state and the expected revision, incrementing the
   revision by one;
6. appends exactly one history row, with the actor from the context;
7. appends exactly one audit event, from the same context.

**There is no read-then-write.** Steps 1 to 4 are *diagnosis*: they decide which error a
caller gets and nothing about whether the write happens. Step 5's predicate is what decides
that, against the row as it is at the instant of the write — which is why the expected state
appears in both places rather than only in the one that produced a nicer message.

**And underneath it, a `BEFORE UPDATE` trigger** requires that `(old, new)` be a declared
edge, that the source not be terminal, that the revision advance by exactly one, and that the
id, tenant, machine and creation time not change. A trigger sees `OLD` and `NEW` together,
which no policy can, so this holds for the schema owner, for a future definer function, and
for anything a later migration adds. The function's own edge check is a courtesy that gives
the caller a good error; **the trigger is the property**.

### 8c. Every artifact is written by the call that changes the state

The first version of this milestone had the database function write the state change, the
history row and the audit event, and had *Python* append the outbox intent afterwards. An
application role executing arbitrary SQL could therefore call the function and simply not
append one: a committed lifecycle move with nothing announcing it, reachable through the
supported grant.

The function now writes all of it — including the idempotency claim, when one is asked for —
and neither Python entry point appends anything. There is no caller and no ordering that
produces a subset, because there is only one call.

Two consequences follow, and both are deliberate:

- **`mutation:execute` is checked inside the function**, alongside the machine's transition
  scope. A transition commits framework records, and appending those is what that capability
  is; checking it in Python only would have left it advisory for a raw-SQL caller.
- **Creating an instance also commits an outbox intent** (`<machine>.created`) and also
  requires `mutation:execute`. Milestone 2.4 originally recorded creation in the audit trail
  and announced nothing, on the grounds that creation is not a *transition*. That left one
  lifecycle state change without a durable event, which is the exact ambiguity this
  correction exists to remove — so the rule is now uniform: no call changes lifecycle state
  without writing every artifact.

### 8d. The claim is created by the database, so there is nothing to attach

The idempotent form passes **one idempotency key** and nothing else about the claim. The
function derives the operation and the fingerprint, writes the claim in the authenticated
tenant with a result it computed from what it just did, and then writes the outbox event
carrying that claim's id.

The ordering is forced and worth writing down, because it is why this path does not go
through `execute_idempotent_mutation`:

- the event must be written by the function (decision 8c);
- an outbox row is append-only, so the link cannot be added afterwards;
- a claim's `result` is not known until the move has happened.

Claim and event therefore have to be written by the same call, claim first — and the generic
primitive writes its claim *after* the mutation it wraps. Everything else about M2.2 is
reused rather than re-implemented: the same table, the same unique index as the serialisation
point, the same fingerprint function, the same validators, the same `IdempotencyConflict`.
The generic primitive is untouched for every non-lifecycle mutation.

Because no claim identifier is caller-supplied, "validate a caller-supplied claim id belongs
to this tenant, identity, operation, request and transaction" is satisfied by there being
nothing to validate. That is the stronger form of the requirement, not a way around it.

### 8e. The whole of lifecycle idempotency lives inside the database entry point

The first correction moved the claim into the function and left the replay, the fingerprint
and the lost-race recovery in Python. That was the wrong place for two of the three, and the
review found both:

- **the operation name** was a caller's string. Two machines therefore shared a key space, so
  presenting a key already taken by a machine you cannot read failed — and "this key is
  taken" is readable for rows the read policies hide. Success versus failure was the oracle;
  renaming the error would not have helped.
- **the request fingerprint** was computed in Python and passed in. That made a
  caller-controlled value the thing a claim is matched on: a raw-SQL caller could move
  instance A while storing the fingerprint of a request about B, and the next genuine request
  for B would replay A's result.

Both are derived inside `transition_lifecycle_instance()` now, and the recovery went with
them, because a recovery that re-read a claim Python had named would have been re-reading the
caller's answer:

- the operation is `lifecycle.transition.<machine_key>.v<version>`, from the machine the
  **instance** pins. A caller cannot choose its uniqueness domain, and two machines never
  share one — so a key taken for a machine this context cannot read is in a namespace it
  never reaches. Authorisation on the actual machine happens **before** any claim is looked
  up, so a context that cannot reach the machine never gets as far as asking;
- the fingerprint is a SHA-256 over a `jsonb` descriptor of the authenticated tenant, the
  derived operation, the instance, the machine version it pins, the expected state and
  revision, the target state, and the validated reason and details. `jsonb` is what makes it
  canonical rather than merely deterministic: object key order is normalised, duplicates
  collapse, and NULL becomes `null` rather than disappearing. **PostgreSQL is the only
  implementation** — Python computes no lifecycle fingerprint at all — so there is no parity
  to prove and no second copy to drift;
- the lost-race recovery is a plpgsql exception block, which is a subtransaction: reaching it
  has already rolled back everything the call wrote, exactly as the Python savepoint did, one
  layer lower and out of any caller's reach. Both ways of losing recover the same way — the
  claim index, and the instance's row lock.

`READ COMMITTED` is required by the function itself, through the same internal guard
Milestone 2.3 uses, because the recovery is now there rather than in Python.

### 8f. A replay is backed by a transition, not by a machine tag

The tag introduced in decision 2 of the previous correction says which machine a framework
row belongs to. It does **not** say which transition a claim stands for — so a claim carrying
a plausible `result` and a valid tag would have replayed as a transition that may never have
happened.

`firmbatch.lifecycle_claim_provenance` is the link, and it is protected the way the definition
tables are: no runtime role holds any privilege on it, it is written only by
`transition_lifecycle_instance()` (which is `SECURITY DEFINER` and — since decision 8h —
owned by, and therefore executing as, the dedicated lifecycle writer), and a trigger refuses
every `UPDATE` and `DELETE` including the owner's — because a link that could be re-pointed
afterwards would prove nothing about the claim it was written for. Every column is a
composite foreign key into a row that transition wrote, so the relationship cannot dangle
and cannot reach across tenants.

A replay resolves the **whole chain** — claim, provenance, transition, instance, event — and
requires that every link agrees with every other, that the instance really reached the
revision the transition produced, and that the stored `result` describes that transition
rather than some other one. A claim in the reserved namespace without that chain is refused,
never replayed. It also carries a unique constraint per transition and per event, so "this
move was claimed once" is a property of the schema rather than of a check somebody remembers
to make.

The reserved namespace is what stops a generic writer manufacturing such a claim in the first
place: a check constraint ties the `lifecycle.` prefix to the machine tag, the tag is the
lifecycle writer's alone to set (decision 8h), and the application role holds no column
privilege on it. Untagged, the row violates the constraint; tagged, it is refused before it
is composed.

The history carries the graph too: `lifecycle_transitions` references the *edge* table on
`(machine_key, machine_version, from_state, to_state)`. Referential integrity is checked with
row security bypassed, so an invalid edge cannot be recorded as having been taken by any
writer at all.

### 8g. A generic outbox link is proved before any constraint sees it

The third review found the last write-side existence oracle, and it was in the one column of
the Milestone 2.2 outbox a generic writer may name. `idempotency_record_id` is optional and
caller-supplied — the generic primitive links each event to the claim it wrote — and, left to
the constraints, naming it answered a question the read policies refuse. A **hidden lifecycle
claim's** id reached the one-event-per-claim index (the transition had already linked its
event) and produced a uniqueness violation; an absent id reached the composite foreign key and
produced a foreign-key violation; and the foreign key is checked with row security bypassed,
so the hidden row was found. With `INSERT ... ON CONFLICT DO NOTHING` the difference was
cleaner still: silent success for the hidden claim, an error for the absent one.

The decision is that **a generic writer proves its link before either constraint is
evaluated**, and that the proof is an authorization check rather than an error rewrite:

- a `BEFORE INSERT` row trigger on `outbox_events`,
  `firmbatch.outbox_events_link_is_authorized()`, runs before the tuple is formed — before
  the unique index, before the `ON CONFLICT` arbiter, and before the referential-integrity
  trigger, which is an `AFTER` trigger;
- it is `SECURITY INVOKER`, so its lookup of the claim runs as whoever is inserting, under
  `FORCE` row security: whether the claim is visible is the read policy's decision, on the
  current authenticated context, and nothing bypasses it through a definer;
- for anybody but the lifecycle writer it requires the claim to be visible, in the row's own
  tenant and the authenticated tenant, **untagged**, and outside the reserved namespace.
  Untagged is what makes "has no provenance" true without reading the provenance relation,
  which no runtime role may reach: the provenance guard (decision 8h) refuses a row for an
  untagged claim, so provenance and a generic claim cannot coexist;
- every way the check can fail raises **one message from one raise site**, SQLSTATE `FB006`,
  because PostgreSQL puts the plpgsql line number in an exception's `CONTEXT` and a line
  number is a branch identifier. An absent claim, a hidden one, another tenant's, a claim the
  context is not entitled to, and a lifecycle claim the context *can* read are all the same
  refusal from outside;
- the lifecycle writer passes, because it is the boundary that links a lifecycle claim to the
  event it wrote in the same call, and its event and claim are both tagged.

What is preserved: an authorized generic claim links exactly as before, and an authorized
generic claim that already carries its event still meets the one-event-per-claim index by
name — the guard passes it and the constraint refuses it, which is the Milestone 2.2 outcome.
What changed for a legitimate caller is only that a cross-tenant link, which the foreign key
used to refuse, is now refused earlier and indistinguishably from an absent one.

### 8h. Lifecycle-derived rows are written by a dedicated identity, not by the schema owner

The third review's other finding was that ownership of the schema had been standing in for
authorship of a transition. The tag guard and the provenance guard checked
`current_user = schema owner`, and the two entry points are `SECURITY DEFINER` — so they
passed; but so did the schema owner's own `INSERT`, and so did any other `SECURITY DEFINER`
function the schema owner happened to own. Direct owner SQL could insert a tagged claim, a
tagged event and a provenance row matching an earlier transition, and the replay accepted
the forged association. Decision 8f rested on a guard that the identity it was guarding
against could pass.

The decision is a **fourth role, the lifecycle writer**, and an identity check that asks the
catalogue rather than the caller:

- the writer is `NOLOGIN`, has no credential, `NOSUPERUSER NOCREATEROLE NOCREATEDB
  NOREPLICATION NOBYPASSRLS NOINHERIT`, is a member of nothing, and can be reached by
  nobody through `SET ROLE` — not the application role, not provisioning, not the schema
  owner. It is created by the role-provisioning layer alongside the other three (per run, for
  a disposable test database, because roles are cluster-wide) and dropped with them;
- it **owns the two mutation entry points and nothing else**. `SECURITY DEFINER` makes the
  executing role the function's owner, so the entry points execute as the writer, and the
  only code that ever runs as the writer is those two bodies. It owns no table and no
  schema, holds `USAGE` on the schema, `EXECUTE` on exactly the helpers the bodies, their
  triggers and the policies they meet call, `SELECT` where the replay reads, and column-level
  `INSERT`/`UPDATE` on exactly the columns the bodies write. Row security stays `FORCE`d and
  it holds no `BYPASSRLS`, so the policies still evaluate against the caller's context;
- `firmbatch.lifecycle_writer_role()` answers **who the writer is** from `pg_catalog`: the
  role that owns both entry points, provided both are `SECURITY DEFINER`, that role is not
  the schema owner, and it holds none of `LOGIN`, `SUPERUSER`, `BYPASSRLS`, `CREATEROLE`,
  `CREATEDB` or `REPLICATION`. NULL otherwise — before the wiring has run, if the two entry
  points have different owners, if a third overload exists, if the writer were ever given a
  credential — and every guard fails closed on NULL;
- the tag guard on all three framework tables, the provenance guard, and the outbox-link
  guard require `current_user` to be that role. No caller-settable GUC, transaction
  variable, temporary object, token, query text or trigger depth is consulted anywhere: the
  identity is the executing role, and the executing role is what `SECURITY DEFINER` sets;
- the provenance guard additionally requires the claim it names to be a lifecycle claim of
  the same tenant and machine as the row sees it, so provenance can only ever describe a
  tagged claim (which is what decision 8g's "untagged means unlinked" rests on).

**Installation is a two-party act, and the split is deliberate.** PostgreSQL hands a
function to a new owner only if the current owner can `SET ROLE` to that owner and the new
owner holds `CREATE` on the schema — measured. The schema owner is `NOCREATEROLE` and holds
no membership, so it cannot give itself either; the trusted bootstrap administrator grants
the owner a `SET`-only membership in the writer (`WITH SET TRUE, INHERIT FALSE, ADMIN
FALSE`) for the duration of `roles.install_lifecycle_writer()` and revokes it immediately
after, exactly as it already does for the one statement that needs `CREATE DATABASE ...
OWNER`; a fresh connection then confirms no row carrying `SET` or `INHERIT` survived. The
entry points' `EXECUTE` grant to the application role is written under `SET ROLE` to the
writer, because the schema owner can neither `GRANT` nor `REVOKE` on a function it does not
own — which is also why the ACL sanitiser's two function loops now touch only functions the
schema owner owns. That ownership-aware body is carried twice: `db/roles.py` runs it as the
runtime `DO` block, and `0004` installs it as `firmbatch.sanitize_schema_privileges()`, calls
it, and drops it on downgrade. Migration `0003` is merged history and keeps its original
block, which is not edited to suit objects `0004` introduced; at `0003` there are no
writer-owned functions, so the original block is exactly right there.

**The migration stays role-agnostic.** It creates the entry points owned by the schema owner
like everything else it creates, defines how the writer is *recognised*, and on downgrade
reads the writer's name from the catalogue while the entry points still exist, drops
everything, and revokes every remaining grant the writer holds on what `0003` keeps — so
after a downgrade the role owns nothing and holds nothing in the database, `pg_shdepend`
carries no row for it, and `DROP ROLE` succeeds. Re-upgrading and re-wiring restores the
identical ownership, grant and recognition state, which a test compares field by field.

What this does not do, and says so: it does not bind a superuser, and it does not bind an
administrator who deliberately alters roles, functions or triggers — a schema owner may still
drop a writer-owned function inside its own schema, and doing so makes `lifecycle_writer_role()`
NULL, which closes every guard rather than opening one. That is the retained
trusted-administrator limitation, and the only route a test takes to the writer's identity
is the administrator exercising it on purpose.

### 8a. Why two callers cannot both move one instance

Two callers holding the same revision serialise on the **instance's row lock**. The first
`UPDATE` takes it; the second blocks; when the first commits, the second — under
`READ COMMITTED`, which ADR 0005 already requires — re-evaluates its own predicate against
the row that now exists, matches nothing, and conflicts.

The idempotency key is **not** what does this, and the distinction matters enough to state:
an idempotency key bounds *retries of one request*, and two callers using different keys are
two different requests entitled to their own claims. The revision bounds *concurrent
requests*. Neither substitutes for the other, and
`test_lifecycle_concurrency.py` uses different keys precisely so that it is the revision
under test.

### 8a-bis. Two identical requests running at once both return the original result

A retry that arrives while the original is still in flight is still a retry. The first
version of this milestone failed it: the loser hit the compare-and-swap, got a
`LifecycleConflict`, and an HTTP client that had retried on a timeout could not tell "you
already did this" from "somebody else moved it" — two situations whose correct next action is
completely different.

There are two ways to lose and the recovery is now the same for both. A caller can lose on
the **claim index**, when the winner's claim commits first; or on the **instance row lock**,
when the winner's conditional update commits first and the loser's predicate then matches
nothing. Either way the loser rolls its savepoint back, re-reads the claim for its exact
`(operation, key)`, and:

- an identical fingerprint → return the winner's stored result, `replayed=True`;
- a different fingerprint → `IdempotencyConflict`, the existing conflicting-reuse error;
- **no claim at all** → keep the refusal it earned.

That last branch is what stops the recovery becoming a way of laundering somebody else's
work. A genuine stale request, a cross-tenant identifier and a wrong-identity attempt all
find no claim — the re-read is tenant-scoped and matched on the exact key — and keep their
conflict. Nothing here retries the transition; the recovery reads a row, and
`test_lifecycle_concurrency.py` asserts from the source that no exception handler re-invokes
the move.

### 8b. A conflict is one refusal, and says nothing else

A stale state, a stale revision, an instance that does not exist and an instance in another
tenant all produce the same error with the same message. A refusal that distinguished them
would answer "does this identifier exist outside this tenant", which is the question tenant
isolation exists to refuse.

Two things were needed to make that true, and both were found by measurement rather than by
reading:

- **One raise site in the database.** The first version raised the conflict from two places
  — "not found" and "zero rows updated". The messages were identical and psycopg renders a
  plpgsql exception's `CONTEXT`, which names the **line number** that raised. A line number
  is a branch identifier. The function now falls through to a single `RAISE`.
- **The Python translation drops the database's text.** This is the one translation in
  `db/lifecycle.py` that does, and for the same reason: the message is written here as a
  constant rather than assembled from whatever the server said.

A third ordering defect came out of the same test. With the graph checked *before* the
expectation, a caller that lost a race and re-read after the winner committed asked "is my
target an edge from the state the winner left?" — and for `draft -> active` raced against
itself the answer was "no, `active -> active` is not an edge". An ordinary lost race reported
an *invalid transition*, and whether it did so depended on whether the loser's read landed
before or after the winner's commit. The expectation is now compared first.

And the same defect had a second half, one step further on. Comparing only the **state**
first left a caller holding a stale *revision* — whose state happened to have come back
around a cycle — being told its instance was terminal or its edge was invalid. That is a
diagnosis about the current row given to a caller whose request was simply out of date, and
it tells that caller something about a state it did not ask about. **Both** the expected
state and the expected revision are now compared before any graph question, so the graph is
only ever asked about a row the caller has described correctly, and a missing, cross-tenant,
wrong-state or wrong-revision request all receive the same non-oracular conflict.

**Malformed definitions are distinguished from stale transitions**, internally and in the
error type: `LifecycleDefinitionError` says a machine version is unregistered or has no
initial state. That is safe to be specific about because machines are **global** — nothing
about any tenant is revealed — and it is a deployment problem with a different owner than a
conflict has.

### 9. Instances start where the machine says, and cannot be created otherwise

`firmbatch.create_lifecycle_instance(machine_key, machine_version)` takes no tenant and no
starting state. The tenant is the authenticated one; the initial state and revision zero are
written by a `BEFORE INSERT` trigger that overwrites whatever arrives, so a direct writer
cannot start an instance half-way through its own lifecycle. `created_at` and `updated_at` are
`clock_timestamp()` for the reason ADR 0006 gives about `occurred_at`: `now()` is
transaction-*start* time, so a caller that opened its transaction early could otherwise date a
row into the past by supplying nothing at all.

Creation writes one audit event **and one outbox intent** (`<machine>.created`), and requires
`mutation:execute` alongside the machine's create capability. It originally announced
nothing, on the grounds that creation is not a *transition*; that left one kind of lifecycle
state change with no durable event, which is the ambiguity decision 8c exists to remove. The
rule is uniform: no call changes lifecycle state without writing every artifact.

### 10. Idempotency composes with Milestone 2.2, on M2.2's table and by M2.2's rules

Every accepted transition commits exactly one outbox intent. There are two supported shapes
and they differ only in whether a claim is written alongside it:

- `transition_lifecycle_instance` — the internal transition. One **unlinked** event, which is
  exactly the case ADR 0005 decision 7a built the optional causation link for: a controller, a
  reconciler or a validator committing an event with the state change that caused it.
- `execute_idempotent_lifecycle_transition` — the API transition. The same database call, told
  **one idempotency key**, so the claim, one **linked** event and the provenance that ties
  them are written by it — claim first, so the link exists at insert time.

**This path does not go through `execute_idempotent_mutation`, and decision 8d says why:**
the event must be written by the database function, an outbox row is append-only so the link
cannot be added afterwards, and a claim's result is not known until the move has happened.
The generic primitive writes its claim *after* the mutation it wraps, which is the one order
that cannot work here.

What *is* reused is everything that carries meaning: the same `idempotency_records` table,
the same unique index as the serialisation point, the same key validator, the same
`IdempotencyConflict` as the outcome a caller sees. The generic primitive is untouched, and
every non-lifecycle mutation behaves exactly as it did.

What is **not** reused, and deliberately, is `request_fingerprint`: decision 8e moved that
into PostgreSQL, because a fingerprint Python computes is a fingerprint a caller can supply.
The generic primitive keeps its own, over a request identity its caller genuinely owns.

Neither shape is a second way to change state: both call the same database function, and
nothing about the transition — or about the claim — is decided in Python. The request
descriptor is the move being requested, so "the same key" means "the same move" to the
fingerprint and to the caller alike.

A transition requires the machine's transition scope **and** `mutation:execute`, checked
inside the database, because committing the framework records is part of the transition
rather than an optional extra. A credential that could move an instance without recording
that it moved would be able to change state silently, which is what the outbox exists to
prevent.

**One narrowly scoped Milestone 2.2 change, and it is a narrowing.** `MutationUnitOfWork`
gained an explicit zero-argument `in_transaction()`, and every generated forwarder was
rebuilt to close over its target name. The old forwarders bound the name as a *default
parameter* — `def forward(self, *args, _name=name, **kwargs)` — which made `_name` a keyword
the caller could supply: `unit_of_work.add(row, _name="connection")` returned the raw
connection the class exists to withhold, and the same trick reached `rollback`,
`get_transaction` and every refusal in `_REFUSED_OPERATIONS`. That was a defect in M2.2
rather than in this milestone, and closing it removes capability rather than adding any.

### 11. The history is append-only and its order is the revision

`lifecycle_transitions` carries a `SELECT` policy and an `INSERT` policy and no others, so
`UPDATE` and `DELETE` reach no row for any role including the owner under `FORCE` — the same
arrangement as the M2.2 and M2.3 append-only tables, and it is in `APPEND_ONLY_TABLES` so the
existing parametrised tests cover it.

`UNIQUE (tenant_id, lifecycle_instance_id, to_revision)` is what makes the history a total
order rather than a bag: two rows claiming revision 4 would be two accounts of the same
moment. Reads order by `to_revision` and not by `occurred_at`, because two rows written in
the same microsecond are indistinguishable by clock.

There is deliberately no delivery state, no hash chain and no retention operation. The first
two are ADR 0006 decision 6c's position, unchanged; the third is a decision no milestone has
taken, and neither table carries a `DELETE` policy at all.

### 12. Errors name the field, the rule and the position, and never the value

The whole non-echo discipline of ADR 0006 decision 8 applies unchanged, and one thing is new
enough to state: **the identifier grammar a state name satisfies accepts an all-lowercase
Firmbatch bearer credential**. `fbk_` followed by 43 lowercase characters matches
`^[a-z][a-z0-9_]{0,62}$`. A state name reaches a stored history row and a `jsonb` audit
document, so the secret-shape test runs before the format test on machine keys, state names
and reasons alike — in Python and again in the database, through the one shared
`firmbatch.secret_shape`.

The bounded-metadata policy is **shared rather than copied**: the transition function calls
`firmbatch.audit_require_acceptable_details`, which is the same implementation the audit trail
uses. One known wording limit follows and is recorded rather than papered over: a raw-SQL
caller whose details are refused sees a message that says "audit details", because that is the
function's name. The rule is the same rule; only the noun is imprecise, and the supported
Python path names it correctly.

### 13. Five custom SQLSTATEs, and why standard ones were wrong

`FB001` (conflict), `FB002` (transition not allowed), `FB003` (definition problem), `FB004`
(the key was claimed for a different request) and `FB005` (a claim with no verifiable
transition behind it). A user-defined class rather than a borrowed standard one, and the
borrowing is what that avoids:

- `23514` (check violation) arrives as an `IntegrityError`, which `db/idempotency.py` catches
  and re-reads as a possibly-lost idempotency race;
- `40001` (serialization failure) is the code every retry helper in every framework retries
  automatically, and a lifecycle conflict is precisely the thing that must **not** be retried
  without re-reading the instance first.

PostgreSQL accepts any five-character alphanumeric SQLSTATE and defines no class `FB`. The
codes are mirrored in `db/lifecycle.py`, which translates them, and a test asserts the copies
agree. `FB004` becomes the Milestone 2.2 `IdempotencyConflict` on the way out, because it is
the same outcome and a caller should not have to learn a second name for it; `FB005` becomes
`LifecycleProvenanceError`, which an ordinary caller cannot produce.

## What this does not claim

**It does not claim exactly-once external delivery.** Unchanged from ADR 0005: the outbox
records durable intent, no dispatcher exists, and when one does it will deliver at least
once.

**It does not protect against a compromised migration-owner credential's DDL, and the
triggers do not bind a superuser.** Since decision 8h the schema owner's *DML* is bound like
everybody else's: its direct `INSERT` and its own `SECURITY DEFINER` functions are refused
every lifecycle-derived write, because the guards ask for the lifecycle writer and the owner
is not it. What remains outside is DDL: that role owns the trigger functions and the tables,
so it can redefine a guard, `ALTER TABLE ... DISABLE TRIGGER`, or drop a writer-owned
function inside its schema (which makes `lifecycle_writer_role()` NULL and closes every guard
rather than opening one); and a superuser can do anything, including grant itself the writer.
Those are deliberate, DDL-shaped acts by a role already trusted with the definitions
themselves, retained as the explicit trusted-administrator limitation. `db/principal.py`
refuses to let a runtime connection be, or reach, either the owner or the writer. What the
guards buy is that no accident, no ordinary statement and no ordinarily-owned function
reaches a lifecycle-derived row.

**It does not claim that moving an instance is possible without reading it.** The transition
function resolves the instance with an ordinary `SELECT`, and row security is `FORCE`d, so
that resolve is subject to the machine's **read** policy even though the function runs as the
schema owner. A context holding a machine's transition capability and not its read capability
therefore cannot move an instance — it gets the ordinary conflict, because the row is not
there as far as the function is concerned.

That is the right answer rather than a gap: you cannot move what you cannot see, and a
resolve that bypassed row security would be a read path around the isolation boundary inside
the one function that writes state. The consequence for a definition author is that a machine
wanting "may move, may not read" declares the same scope for both; the two fields are
separate because a machine may want reading to be *wider* than moving, which this supports.

**It does not claim that the fingerprint survives a change of PostgreSQL's `jsonb` text
form.** The descriptor is canonical *within* a database: `jsonb` normalises key order and
duplicates, so two spellings of one request hash alike, which is the property replay needs.
It is not a stable identifier across implementations, and nothing compares one across
databases or persists one as an external contract. If a future PostgreSQL changed how a
`jsonb` value renders, previously stored claims would stop matching new requests and the
retries would be refused as conflicting reuses rather than replayed — a visible, bounded
failure rather than a wrong replay, and one worth stating before somebody discovers it.

**It no longer carries the "no chosen identifier" caveat.** The previous amendment recorded
that an event linked to a claim whose random UUID a caller already knew could be probed
through the one-event-per-claim constraint. Decision 8g closes that: a generic link to a
claim this context may not read — hidden, absent, another tenant's, or a lifecycle claim's —
is refused before the foreign key and the unique index are evaluated, with one message,
including through `INSERT ... ON CONFLICT`. What is claimed now is the stronger thing: no
constraint on the framework tables answers a generic writer's question about a row the read
policies hide.

**It does not model any product lifecycle.** There is no job, no window offer, no attempt and
no lease here, and no machine is registered. Target invariants 4, 5, 6, 7, 8, 9 and 10 remain
Milestone 5 and 6 work; this kernel is the mechanism those milestones will express part of
their invariants *with*, and it establishes none of them.

**It does not bound what a definition means.** The kernel enforces that a graph is
well-formed. Whether `admitted -> cancelled` should exist in the job machine is a commercial
question, and registering a wrong edge would produce a perfectly valid state machine with the
wrong contract in it.

**It is not VERIFIED LIVE.** Implemented and tested on a locally provisioned PostgreSQL 16
server, in a database created and destroyed by the run. No artifact under `docs/evidence/`
captures it, nothing is deployed, and the test count is not deployment proof.

## Consequences

- Milestone 2's declared implementation scope is complete, subject to review and merge. The
  milestone gate — cross-tenant reads and writes failing closed, duplicate mutations
  producing one contractual effect — was already met; the remaining scope item was this one.
- Milestone 5 and Milestone 6 gain a mechanism they must use rather than reinvent, and a
  shape their definitions have to fit: an explicit state set, one initial state, explicit
  edges, and a capability chosen from the existing catalogue.
- The two runtime roles are no longer symmetric. Provisioning receives no lifecycle authority
  of any kind, and `RevisionPlan` grew an `application_functions` field to express that.
- `db/roles.py` now carries three revision plans, and the protected-table list for each
  revision is written out rather than derived from head — deriving it is what made role
  wiring fail after a rollback in Milestone 2.3, and it would have failed the same way here.
- A schema revision id must fit `alembic_version.version_num` (`varchar(32)`). The intended
  file name `0004_lifecycle_state_machine_foundation` is 39 characters and failed **after**
  applying its DDL, which is the worst shape a migration failure can have. The revision is
  `0004_lifecycle_state_machines`, and the existing
  `test_every_revision_fits_the_version_column` is what catches the next one earlier.
- Every future tenant-owned table that wants a lifecycle gets it by pointing at an instance,
  not by growing a `status` column. That is the discipline this milestone exists to install.
- The two Milestone 2.2 framework tables gained two derived columns and a narrower read
  policy. Generic behaviour is unchanged — an untagged claim or event is exactly what it was
  — but a future migration adding a writer of those tables has to leave the tag alone, and a
  future *reader* of them has to expect rows it cannot see.
- Registering a definition now has an ordering contract: insert, then publish, in one
  transaction. A later milestone's migration that registers the job machine must do both, and
  the publication trigger refuses if it does not.
- **`audit_events` gained the same derived tag**, one milestone after the other two, and the
  same narrower read policy. `audit:read` still reads the trail; reading a *lifecycle* row
  additionally needs the machine's read scope. A future reader of the trail has to expect
  rows it cannot see, and a future writer of a `lifecycle.`-prefixed action has to go through
  the lifecycle append rather than the generic one.
- **Two operation namespaces are now reserved in the database**: `lifecycle.` on a claim's
  operation and on an audit row's action. A later milestone that wants a claim or an audit
  row under that prefix has to write it from trusted database code, because the check
  constraint ties the prefix to a tag only the schema owner can set.
- **`lifecycle_claim_provenance` is a fifth protected relation**, so `PROTECTED_TABLES`, the
  head revision plan and `db/principal.py`'s refusal all cover it. A runtime connection
  holding any privilege on it — table or column, direct or one `SET ROLE` away — is refused at
  connect time.
- **The application role's `INSERT` on the two framework tables is column-level.** The reach
  is the same for every legitimate write and strictly narrower for one thing: the row's
  identifier. A later milestone that adds a column to `idempotency_records` or `outbox_events`
  and expects the runtime to write it has to add it to `_M2_4_APPLICATION_COLUMN_GRANTS` —
  which is the right amount of friction for a column a caller may name.
- **The idempotent lifecycle entry point takes one key and nothing else.** Callers written
  against the previous signature passed an `operation`; there is no operation parameter now,
  and the operation a claim lands under is derived from the machine. Nothing outside this
  milestone had such a caller yet, which is the cheapest moment to make the change.
- **There are four per-run roles, and role wiring has a fifth step that needs the
  administrator.** The lifecycle writer is created and dropped with the other three, and
  `db/roles.py`'s `RevisionPlan` grew four fields describing what it owns and holds at each
  revision (nothing before `0004`). Installing it — `roles.install_lifecycle_writer()` —
  requires the owner connection to be able to `SET ROLE` to the writer for that one call,
  which the bootstrap's `temporary_set_membership` provides and takes back; every place that
  re-wires a database after a migration goes through `bootstrap.wire_roles()` rather than
  the four `roles` calls. An operator runbook has to do the same: grant, install, revoke.
- **The ACL sanitiser's function loops skip functions the schema owner does not own**,
  because the owner cannot `REVOKE` on them. The writer-owned entry points are sanitised by
  the writer itself, under `SET ROLE`, as part of its installation. The ownership-aware body
  lives in `db/roles.py` and in the function `0004` installs and drops; a later migration
  calls that function rather than carrying a copy, and `0003` keeps its original block.
- **A generic writer's outbox link is an authorization check, and it can be refused.** The
  generic primitive never meets it — it links the claim it just wrote — but a caller of
  `append_outbox_event` naming a claim it may not link now gets `OutboxLinkRefused`
  (SQLSTATE `FB006`) rather than a constraint error, and a cross-tenant link is refused
  before the foreign key rather than by it. `test_outbox_isolation.py`'s two constraint-shaped
  assertions were rewritten to say so.

## Rejected alternatives

### A machine tag as the whole of a replay's authorization

Rejected, and it is what the previous correction shipped. The tag decides *who may read* a
framework row, which is the question it was introduced to answer. It says nothing about
*what the row stands for* — so a claim carrying a plausible lifecycle `result` and a valid
tag would have replayed as a transition that may never have happened, and an untagged generic
claim with the same key would have been in the same uniqueness domain to begin with. The
provenance relation answers the second question, and the reserved namespace stops the first
one arising.

### Computing the lifecycle fingerprint in Python and passing it in

Rejected. It is how every other fingerprint in this schema is computed, and for the generic
primitive it is right: the caller owns the request identity and the digest is a summary of
something it told us. For a lifecycle transition the fingerprint summarises what the
*database* did, and a value the caller supplies for that is a value the caller can choose —
move instance A, store the fingerprint of a request about B, and the next genuine request for
B replays A. Deriving it in PostgreSQL also removes the parity problem the alternative
creates: two implementations of "the same request" that must agree on key order, NULLs,
Unicode and number spelling forever.

### One lifecycle operation name for every machine

Rejected, and it was the first shape. `lifecycle.transition` for every machine put one
tenant's machines in one key space, so presenting a key already taken by a machine you cannot
read failed — and success versus failure is the oracle. Renaming the error does not help.
Deriving the operation from the machine gives each one its own uniqueness domain, which
removes the question rather than answering it more carefully.

### A `NULLS NOT DISTINCT` unique index over the tag columns

Rejected as the way to separate the two uniqueness domains. Widening
`uq_idempotency_records_tenant_id_operation_idempotency_key` to include the tag would have
worked on PostgreSQL 15+, and it would have changed the identity of the constraint every
Milestone 2.2 recovery path matches by name. The namespace reservation achieves the same
separation without touching the index M2.2 serialises on.

### Composing the outbox event in Python after the database call

Rejected, and it is the shape the first version of this milestone had. The database function
wrote the state change, the history row and the audit event; Python appended the outbox
intent afterwards. An application role executing arbitrary SQL could call the function and
skip the append, producing a committed lifecycle move with nothing announcing it — through
the supported grant, with no privilege needed. "Every supported transition produces every
artifact" cannot be a property of one caller.

### A caller-supplied idempotency claim identifier

Rejected. It is the obvious way to let the database link the event it writes, and it would
have required validating that the claim belongs to this tenant, this identity, this
operation, this request and this transaction — five checks standing where one design decision
would do. The function creates the claim instead, from the authenticated context, with a
result it computed itself. There is nothing for a caller to point at.

### Deferring the outbox foreign key so the event could be written first

Rejected, and it was the near-miss. Making
`fk_outbox_events_idempotency_record_id_tenant_id` `DEFERRABLE INITIALLY DEFERRED` would have
let the function write the event before the claim existed, with the constraint verified at
`COMMIT`. It preserves the constraint, and it destroys the *validation*: a claim id that does
not exist yet cannot be checked against anything. Writing the claim first — which means the
function writes it — keeps both.

### Revoking framework-table `SELECT` and exposing narrow read functions

Rejected as the way to stop `mutation:execute` reading lifecycle records. It works, and it
changes generic Milestone 2.2 behaviour for every caller, including ones with no lifecycle
anywhere near them. A derived tag plus a narrower read policy leaves untagged rows exactly as
they were, which is what "preserve the generic behaviour" has to mean.

### A Python check on the replay path instead of a row policy

Rejected. A replay is a read of somebody's stored result, and a check in
`execute_idempotent_lifecycle_transition` holds only for callers that go through it — a
caller composing `SELECT result FROM idempotency_records` is exactly the case that matters.
Row-level security enforces it wherever the row is read, and the replay path then
reauthorizes by construction: a claim a context may not read is a claim it cannot be handed.

### Letting a lifecycle-tagged row be tagged by its writer

Rejected. A caller that could set the tag could label its own row with a machine it may read;
one that could clear it could untag a real row so that reading it needed no machine
capability. Either way the read policy would decide nothing. The tag is written by the two
entry points, which execute as the lifecycle writer; a trigger refuses a non-NULL value from
every other writer, and the application role holds no column privilege on it at all, so the
ordinary refusal is a permission error one layer before the trigger.

### Checking `current_user = schema owner` as proof of the transition boundary

Rejected by the third review, and it was the defect. Owning the schema is not having produced
the transition: the schema owner's direct `INSERT` and every `SECURITY DEFINER` function it
owns run as the schema owner, so all of them passed a check written that way. The correction is
an identity that only the entry points can have — a `NOLOGIN` role that owns them and nothing
else — and a guard that asks the catalogue who that is (decision 8h).

### A GUC, a transaction variable, a temporary object or a token as proof of origin

Rejected. Each is settable by whoever can run a statement on the connection, which is exactly
the population the guard has to refuse; `pg_trigger_depth()` says only that a trigger fired
something, not who. `current_user` inside a `SECURITY DEFINER` body is the one value the
caller cannot set, and the owner of the function is the one value the schema owner cannot
forge without a membership it does not hold.

### Rewriting the constraint errors so that a hidden and an absent claim read alike

Rejected. The oracle was success versus failure as much as one message versus another — with
`ON CONFLICT DO NOTHING` a hidden claim's id simply succeeded — and a message rewritten after
a constraint fired would still have let the foreign key find the hidden row. The check has to
run before either constraint is evaluated, as an authorization decision under the writer's
own row-security view (decision 8g).

### A `SECURITY DEFINER` outbox-link trigger, or a definer helper that reads the provenance

Rejected. A definer trigger owned by the schema owner would look the claim up as the owner
and decide visibility for the caller, which is a read path around row security inside the one
place that must not have one; a definer helper answering "does this claim have provenance",
granted to the application role, would itself be the oracle. The trigger runs as the invoker,
and "untagged" stands in for "unprovenanced" because the provenance guard refuses a row for an
untagged claim.

### Keeping the publication rules inside `publish_lifecycle_machine()`

Rejected, and it is what the previous correction shipped. A function is a path: the rules
applied to callers who chose to come through it, and the schema owner — the only identity
that can reach these tables — could publish an arbitrary graph with a plain `UPDATE`, or
insert a row that was published on arrival. A `BEFORE UPDATE` trigger is on the one place a
row's publication column can change, so there is no second path to keep in step.

### Reading `published_at` without locking the machine row

Rejected once it was measured against the sequence in decision 4d. A value read is not a
value decided on while another transaction may change it, and the child trigger's read and
its decision were two statements apart. Both sides take `FOR UPDATE` on the machine row now,
which is also the cheapest possible lock discipline: one object, one order, nothing to
deadlock against.

### Locking the state rows an edge refers to, rather than the machine

Rejected. It is the lock that looks natural for an edge — those are the rows the foreign keys
name — and it conflicts with nothing publication does: publication validates the *machine*
and takes no lock on a state row. An edge's parent is the machine, so that is what it locks.

### Publishing a definition in a later transaction than the one that wrote it

Rejected. It reads as harmless — the rows are there, publication is a flag — and it means a
definition whose pieces became durable independently. A machine whose states committed in one
transaction and whose edges committed in another was, for a while, a publishable definition
that no single rollback could take back. Publication requires every row to carry the current
transaction's `xmin`.

### Refusing `AUTOCOMMIT` in Python only

Rejected as sufficient. The driver flag is worth reading, because it gives a clear error
before anything is written — but it is a property of the client, and the property that matters
is a property of the rows. The `xmin` comparison is what holds; the Python check is the
courtesy in front of it.

### Application-only validation of transitions

Rejected. It is exactly what v0 does — `set_job_status` writes whatever it is given — and it
holds only for callers that went through the application. A second control-plane process, a
migration, an operator with `psql`, or a future definer function would each be outside it.
The trigger and the composite foreign keys hold for every writer, including the owner.

### An unconditional `UPDATE` after a read

Rejected, and it is the specific failure the milestone is named after. Between the read and
the write there is a window; two callers that both read revision 3 would both write revision
4, and the second would silently overwrite the first — with a legal move, so nothing would
look wrong afterwards. The compare-and-swap has no window because the check and the write are
one statement.

### Event sourcing: the history is the state

Rejected as the *only* state. Reconstructing the current state by folding a transition log
means every read replays a history whose length grows without bound, and it makes the
compare-and-swap harder rather than easier: the condition becomes "no row exists with a later
revision", which is an insert-time uniqueness check that cannot also carry the graph.

The history is kept, append-only and totally ordered by revision, and the current state is a
column. That is the arrangement where "what is it now" is one row and "how did it get here"
is a scan, rather than both being a scan.

### A customer-editable workflow DSL

Rejected outright, and not only for this milestone. A configurable graph turns "what may a
customer's workflow do?" into a question this system has to answer, and every honest answer
is a sandbox: expressions need an evaluator, edges need side effects, side effects need a
capability model, and a capability model that a customer authors is a second authorization
system beside the closed catalogue.

It also collides with what the product sells. The job lifecycle carries contractual events —
an accepted quote is immutable, an honoured window earns the premium — and those are not
things a customer may re-draw. Firmbatch's machines are Firmbatch's.

### Per-tenant machine definitions

Rejected. It is the same thing as the DSL wearing a smaller hat: two tenants running
different `job` graphs is two products. The definition tables are global for the same reason
the certification registry is (§3.1), and instances pin a version so a new one changes
nothing that is already running.

### A `status` column with a check constraint on each domain table

Rejected. It is the arrangement most systems reach for, and it cannot express the two things
that matter: which *moves* are legal (a check constraint sees one row's new value, not the
old one) and who moved it. Every domain table would then grow its own ad-hoc guard, and the
guards would drift.

### Deriving the state set from the edges

Rejected. A state with no edges is a legitimate part of a graph — a terminal state has none
by construction, and a state that a later version will connect may have none yet — so a
derived set would make both unrepresentable. The explicit set also gives the foreign key
something to point at.

### Requiring every machine to be acyclic

Rejected. `offered -> accepted -> revoked -> offered` is in the target architecture §12.1 and
re-leasing a shard is in §10. A kernel that assumed acyclicity would have to be argued with
by every domain that needs a cycle, and the argument would be won by weakening the kernel.

### An `UPDATE` policy that encodes the graph

Rejected, because it cannot be written. A row-level-security policy's `USING` clause sees the
old row and its `WITH CHECK` clause sees the new one, and no policy sees both — so "this pair
is a declared edge" is not expressible as a policy at all. That is why the graph is a
`BEFORE UPDATE` trigger, which does see both, with the policies carrying the tenant and the
capability.

### Granting the runtime `INSERT`/`UPDATE` on instances and relying on the trigger

Rejected. The trigger would still hold the graph, but a direct `INSERT` could start an
instance in any declared state and a direct `UPDATE` could move it along a legal edge without
writing the history row, the audit event or the outbox intent — a state change with no record
of who made it. `SELECT` and nothing else is what makes the hardened function the only way
in, which is the same correction ADR 0006 decision 6e made for the audit trail.

### An `in_progress` or `pending` transition record

Rejected, for exactly the reason ADR 0005 decision 2 rejects a two-phase claim: a durable
half-finished record needs a recovery system to interpret it, and there is none. A transition
that does not reach `COMMIT` leaves nothing.

### A `lifecycle:read` / `lifecycle:transition` scope pair

Rejected. It would be a second, parallel authorization vocabulary that has to be kept in step
with the first: a credential that may write a job would also need a scope to move one, and the
two would drift the first time somebody granted one without the other. A machine reusing an
existing customer capability keeps "who may move this job" the same question as "who may write
this job".

### Retrying a conflict inside the primitive

Rejected. A conflict means the caller's revision is stale; retrying with the same revision
either fails identically forever or — if the state happens to come back around a cycle —
applies a move the caller never decided on. A caller that means to proceed must re-read and
decide again, and `test_lifecycle_concurrency.py` asserts from the source that nothing in the
module loops.

### Standard SQLSTATEs for the kernel's own refusals

Rejected under decision 13. `23514` would be caught by the idempotency primitive's
`IntegrityError` handler and `40001` invites exactly the blind retry the paragraph above
rules out.

### Seeding the job lifecycle from target architecture §5.1

Rejected under decision 2. The diagram establishes intent and is not edge-complete, a
registered version is immutable, and the graph is a contract rather than a data structure.
Milestone 5 registers it alongside the job tables, with the cancellation and failure edges
its own gate requires.
