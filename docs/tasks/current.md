# Current tasks

Active work and open questions. Updated at the end of each task, alongside `docs/STATE.md`.

Last updated: 2026-09-05, `main` merge commit `b028f21` (Milestone 2.2, PR #5), plus
Milestone 2.3 on `feat/milestone-2-3-auth-audit-secrets`, **implemented, tested, reviewed
and awaiting merge**, after a fourth security correction pass. Milestone 1 merged at
`6b4f341`; M2.1 merged at `712b51a` (implementation
commit `521870b`, plus the bootstrap trust-boundary correction `78eae1d`); M2.2 merged at
`b028f21` (implementation commit `d362717`).

**M2.3 is at implementation commit `89fbdd9`.** Nothing has been pushed or merged; the
human pushes and merges.

---

## Active — Milestone 2, shared product foundation

Milestones 0 and 1 are complete; Milestone 1 merged at `6b4f341`. Milestone 2 is now the active
milestone. It has four slices; the first two are merged, the third is implemented, tested
and reviewed at commit `89fbdd9` and awaiting merge, and the fourth is not started.
Milestone 2 remains active until M2.4 is completed.

### M2.1 — PostgreSQL and tenant-isolation spine — **merged at `712b51a` (PR #4)**

Delivered by PR #4: the configuration boundary, Alembic migrations into a dedicated
`firmbatch` schema, the `tenants`/`workspaces` spine, forced row-level security with a
transaction-local tenant context, three separated roles with a verified runtime principal,
minimal typed repositories, a disposable-cluster attestation, and a **382-check** pytest suite
against real PostgreSQL 16 wired into `scripts/verify-repository.sh` and CI. See
`docs/STATE.md` for what it does, and `docs/adr/0004-postgresql-tenant-isolation-foundation.md`
for why.

**Six review rounds found fifty-eight issues in total; fifty-seven were corrected and one was reclassified.** The first round found fifteen, the second ten, the third eight, the fourth ten, the fifth ten, the sixth five. The fifth-round "blocker" was PostgreSQL 16's creator-ADMIN membership row, which a non-superuser cannot revoke; it is **not a defect** but the boundary the architecture draws, and the bootstrap assertion built on it had to be withdrawn after it made CI fail. See "M2.1 CI correction" below, ADR 0004 section 8f, and `control_plane/tests/test_admin_escalation.py`. Six were
security or destructive-safety defects reproduced against a real server before being fixed:
temporary-table shadowing, inherited tenant context, ORM identity-map leakage, an unverified
runtime principal, a teardown that trusted its handle (which dropped a real database during
testing), and a generated password reaching exception text. Each now has a regression test.
The table in `docs/STATE.md` lists what was demonstrated and what closed it.

Order for the human at the time (all of it is now done; PR #4 merged at `712b51a`):

1. Review `docs/adr/0004-postgresql-tenant-isolation-foundation.md`, in particular the
   "What this does not claim" section — RLS bounds a query given a context; it does not yet
   bind the context to an authenticated credential.
2. Review the five protected-file changes: `AGENTS.md` (roadmap authority),
   `.agents/skills/milestone/SKILL.md` (canonical milestone + §17 invariants),
   `.agents/skills/verify/SKILL.md` (the pass is no longer side-effect free; attestation
   prerequisite), `scripts/verify-repository.sh` (thirteenth and fourteenth gates, no existing gate weakened),
   `.github/workflows/ci.yml` (PostgreSQL 16 service, hash-pinned lock, explicit attestation
   step, one script call).
3. Attest the local cluster once, if it is not already marked — and **only** if it holds
   nothing you would miss:

   ```bash
   cd "$(git rev-parse --show-toplevel)/.."
   FIRMBATCH_ENV=test python3 -m firmbatch.control_plane.testing.attestation --check
   ```

4. Run `./scripts/verify-repository.sh` with `FIRMBATCH_TEST_DATABASE_URL` set. Expect
   **14 gates, 0 failed**.
5. If promoting M2.1 to **VERIFIED LIVE**, capture the foundation-suite run with
   `/record-evidence` under `docs/evidence/m2/`. Otherwise retain the current
   **implemented and tested** classification.
6. Human commits the reviewed branch and merges PR #4 after all required checks pass.

### M2.1 CI correction — the bootstrap administrator is trusted, not isolated

PR #4 failed CI on the very first thing it did:

```
DisposableDatabaseError: the shared admin can still reach the per-run owner
(pg_has_role reports SET and USAGE)
```

`bootstrap._require_no_set_reachability()` refused to return a handle unless
`pg_has_role(admin, owner, 'SET')` and `(..., 'USAGE')` were both false. CI's bootstrap
administrator is the `postgres` **superuser** of an ephemeral `postgres:16` service
container, and a superuser satisfies `pg_has_role` for every role in the cluster by
definition. The assertion was unsatisfiable there — and it was asserting a property the
accepted test-infrastructure boundary never promised.

The mismatch was in the assertion, not in the architecture. Stated consistently now in
`bootstrap.py`, ADR 0004 §8f, `docs/STATE.md` and here:

- the bootstrap administrator is **trusted**;
- **CI** uses a superuser inside an ephemeral PostgreSQL service container;
- **local verification** uses an explicitly attested disposable cluster;
- PostgreSQL administrative reachability is **accepted only inside that boundary**;
- **customer and runtime roles remain untrusted and separated**.

`_require_no_set_reachability()` is replaced by `_require_temporary_membership_released()`:
the same catalogue reads, with the `pg_has_role` questions removed. The one-statement `SET`
grant is still taken and still given back in a `finally`, and an explicit `set_option` or
`inherit_option` row left where PostgreSQL permits revoking it still fails bootstrap —
which is a real property on either kind of admin.

`control_plane/tests/test_admin_escalation.py` now tests **containment** rather than the
escalation. The test that asserted the administrator could re-acquire the owner role and
perform an owner-only operation is removed; a passing test whose subject is a working
escalation proves nothing the product sells. In its place: bootstrap completes under either
kind of administrator; no revocable membership row or path carries `SET` or `INHERIT`; the
three per-run roles hold no administrative attribute, gain no route into the administrator,
and (for the runtime pair) none into the migration owner; the administrator's credentials
appear in no runtime URL. The PostgreSQL 16 `CREATEROLE` `ADMIN OPTION` limitation stays
asserted for a non-superuser administrator, and the two owner-only-refusal assertions that
are meaningless for a superuser now `skip` with a stated reason instead of silently
`continue`ing.

**Skip counts differ by cluster shape, and both are expected.** Locally: 1 skip (granting
`REPLICATION` needs a superuser). On CI: that test runs, and the two non-superuser-only
assertions skip instead.

### Blocking requirement carried out of M2.1 — `AUTH-BOUND-TENANT-CONTEXT`

M2.1 gives **structural** isolation: forced RLS, fail-closed transactions, no leakage
through pooled connections or ORM identity maps, separated application and migration
credentials. The application service remains a *trusted setter* of tenant context.

It does **not** protect against arbitrary SQL run with a compromised runtime credential:
the runtime role can `set_config('app.tenant_id', <any uuid>, true)` and RLS will evaluate
faithfully against whatever it was told. No partial mechanism was attempted here — a
convention or a second GUC would look like the property without being it.

**Customer-facing deployment is blocked** until tenant context is derived from an
authenticated, unforgeable capability rather than a caller-supplied workspace UUID. Tracked
as `AUTH-BOUND-TENANT-CONTEXT` in Milestone 3 of `docs/firmbatch-v1-roadmap.md`, with five
adversarial completion tests. ADR 0004 §8g and `docs/STATE.md` carry the detail.

Nothing in this repository asserts the limitation as a passing test; it is tracked in
prose, deliberately, so that it is fixed rather than deleted.

**Status at M2.3.** The database/GUC portion is closed: the limitation above no longer
holds, and completion cases 1 to 4 -- arbitrary context, a leaked runtime credential, SQL
injection, and replay or forgery -- are met and tested adversarially. Case 5, an
authenticated user with no membership in a workspace, needs memberships and is Milestone
3's. **The task stays open until both halves do, and customer-facing deployment stays
blocked.** The prose above was the tracking and is left standing; nothing had to be deleted
when the capability landed, which is what that paragraph was for.

### M2.2 — idempotent mutations and the transactional outbox — **merged at `b028f21` (PR #5)**

Delivered by PR #5, implementation commit `d362717`. Migration
`0002` adds two tenant-scoped, append-only tables — `idempotency_records` and
`outbox_events` — behind the same forced row-level security as the spine.
`control_plane/db/idempotency.py` is the typed primitive that claims a key scoped by
tenant and operation, fingerprints the request identity, replays an identical retry,
rejects a conflicting reuse, runs the mutation once, and commits the business state, the
completed claim and exactly one linked outbox event together.

**Two review correction passes were applied before that commit, and they changed the
design in the places below.** Read this list before the code:

- **The mutation callback no longer receives the caller's `Session`, and a commit reached
  around it is refused before it happens** (merge blocker, corrected twice).
  `Session.commit()` in SQLAlchemy 2.x commits the *outermost* transaction even inside an
  open `begin_nested()` SAVEPOINT, so a callback could have persisted its business row
  before the claim and the event were written. It now receives a `MutationUnitOfWork` that
  forwards ORM work and refuses `commit`, `rollback`, `close`, `begin`, `begin_nested`,
  `connection`, `get_bind`, `expunge_all` and the legacy bulk API.

  The first fix stopped there and re-checked the transaction *after* the callback. That was
  not enough: the real session is one `object_session(row)` away, and a check after `COMMIT`
  is too late — the business row is already committed with no claim and no event, and a
  retry collides with a row nothing explains. So a `before_commit` listener is now attached
  to the real session **for the duration of the callback only**, raising ahead of the flush
  a commit performs, and removed in a `finally` before the primitive releases its SAVEPOINT
  and before the caller commits. `_require_intact_boundary` stays as secondary detection of
  a rollback or other boundary destruction, and is no longer described as preserving
  atomicity.

  Unflushed ORM state at entry is also rejected, because `begin_nested()` flushes pending
  rows *before* opening the SAVEPOINT. That check covers pending state only; a write the
  caller already flushed cannot be detected and is outside the SAVEPOINT, so the rule is a
  contract: every business write for the operation goes inside `mutate`, and the primitive
  is called before any DML for that operation. ADR 0005 decisions 4a and 4b.
- **The payload-plane claim was overstated and is corrected** (merge blocker). The
  parameter is now `request_identity` — bounded metadata validated *before* the mutation
  runs — and the test that passed a raw prompt and an API key and treated hashing them as
  compliance is gone, replaced by an S3 manifest/object-reference example. The key denylist
  matches **whole names** rather than substrings, so `input_manifest_id`,
  `output_object_key` and `artifact_digest` are accepted. Three false claims were removed
  from the repository: that the absence of `bytea` prevents storing payload bytes, that a
  256-character string cannot be payload, and that bounded JSONB proves the absence of
  secrets or content. M2.2 proves that the primitive **persists only a fingerprint and
  bounded metadata**; the data-flow proof is Milestone 5's.
- **The outbox is decoupled from API idempotency.** `idempotency_record_id` is nullable and
  is an optional *causation* link, so the controller, reconciler, validator and lifecycle
  work of later milestones can commit an event with a state change without manufacturing a
  claim nobody can retry against. `append_outbox_event` is the one writer, and the
  primitive calls it. No dispatcher, SQS integration, delivery state, global events or
  fan-out was built.

The suite is **512 checks (511 passed, 1 skipped locally)**, up from 382, across three new
modules. `docs/STATE.md` has the property-to-test map;
`docs/adr/0005-idempotent-mutations-and-transactional-outbox.md` has the reasoning.

Seven things worth a reviewer's attention, in descending order of consequence:

1. **No durable "in progress" record, deliberately.** A two-phase claim needs a reaper to
   decide when a `pending` row is abandoned, and M2.2 does not build one. Everything
   commits together instead, so a process killed before `COMMIT` leaves nothing and the
   retry is an ordinary first attempt. ADR 0005 decision 2.
2. **The mutation contract is enforced by the handle and by a scoped pre-commit guard,
   not by a docstring.** See the correction list above. The known escape — the real
   `Session` behind a mapped row — is refused before the commit, so no partial state is
   created. It is still a guardrail and not a sandbox: a callback that opens its own
   engine or connection, drops to the DBAPI, or issues `COMMIT` as raw SQL is outside this
   transaction and outside anything the module can see.
3. **The loser of a race executes its mutation and has it rolled back to a savepoint.**
   Only one mutation *commits*; both may run. A `mutate` function must therefore confine
   itself to rollback-safe DML — no mail, no spend, no provider call, no session-scoped
   advisory locks. That is what the outbox is for.
4. **`READ COMMITTED` is required and anything stricter is refused.** The recovery path
   re-reads a row another transaction has just committed. Under `REPEATABLE READ` that
   read returns nothing and the caller is told a taken key is free — a wrong answer, so
   the level is checked rather than assumed.
5. **Append-only is enforced twice**: the application role holds `SELECT, INSERT` only, and
   the tables carry no `UPDATE`/`DELETE` policy at all, so even the owner reaches no row
   under `FORCE`. The one route left open by design is a tenant delete cascading, and no
   runtime role holds `DELETE` on `tenants`.
6. **"Exactly one event" is a property of the primitive, not of the constraint.** The
   unique constraint on `(tenant_id, idempotency_record_id)` enforces **at most one**
   linked event; a uniqueness constraint cannot require existence. The primitive writes
   exactly one, atomically with the claim, and the PostgreSQL tests count both after a real
   commit. A deferred constraint trigger would have made it a database fact and was
   deliberately not built — machinery to preserve a sentence is the wrong trade.
7. **Exactly-once delivery is not claimed anywhere.** The outbox records intent. A later
   dispatcher may deliver at least once.

Three existing tests were changed rather than added to, and all three were strengthened:
`test_there_is_exactly_one_head` now expects `0002`;
`test_every_tenant_scoped_table_has_an_isolation_policy` now handles both policy shapes
(the spine's `FOR ALL`, and the append-only read/append pair) **and** asserts `USING` and
`WITH CHECK` independently, where the first version's `qual or with_check` read only
`qual` for a `FOR ALL` policy and would have passed with a dropped or mis-scoped
`WITH CHECK`; and the binary-column test now says what it establishes (a shape check)
rather than what it does not (a payload-plane proof). No gate was removed, weakened,
renamed or duplicated.

Review is complete and the work merged at `b028f21`. What was reviewed, for the record: `docs/adr/0005-idempotent-mutations-and-transactional-outbox.md` — in
particular "What this does not claim" — and the one protected-file change,
`scripts/verify-repository.sh`, which gains six entries in `REQUIRED_FILES` (73 now, from
67) and **no new gate**, because the foundation-suite gate already runs the whole
`control_plane/tests` directory. Nothing else under `AGENTS.md`'s ask-first list was
touched.

All of that is now done and merged. M2.2 remains **implemented and tested** rather than
VERIFIED LIVE: no evidence artifact was captured for it, and merging is not evidence.

Deliberately deferred out of M2.2, and each one is somebody's later milestone: the outbox
**dispatcher** and SQS publishing (M6), delivery state, global (non-tenant) events and
fan-out (M6), idempotency-record **expiry** (pruning needs a `DELETE` policy these tables
deliberately lack), HTTP endpoints and `Idempotency-Key` header handling (M3), and the
**payload-plane data-flow proof** (M5) — M2.2 shows only that the primitive persists a
fingerprint and bounded metadata. Mutable delivery state, when it arrives, belongs in a
separate table so the event content stays immutable.

Known limits carried out of this slice, in prose rather than as passing tests:

- the mutation unit of work and the commit guard are a guardrail, not a sandbox: they do
  not bound arbitrary Python, an independently opened connection, or raw `COMMIT` (item 2
  above);
- business writes flushed before the primitive is called are outside its SAVEPOINT and
  cannot be detected; the rule that closes that is a contract, not a check;
- the metadata denylist and size bounds are defense in depth and prove nothing semantic —
  `TEXT` and `JSONB` hold text, so an encoded payload fits;
- the contention test depends on `pg_stat_activity` showing a blocked backend, so on a
  server where that view is restricted it fails rather than silently degrading.

### M2.3 — authenticated context, authorization, audit, secrets — **implemented and tested at `89fbdd9`, reviewed, awaiting merge**

On `feat/milestone-2-3-auth-audit-secrets`, at implementation commit `89fbdd9`. It closes
the piece M2.1 deliberately left open: tenant context is now resolved from an authenticated
credential rather than accepted from a caller-set setting. `docs/STATE.md` has what it does and the property-to-test map;
`docs/adr/0006-authenticated-authorization-audit-and-secrets.md` has why.

**The one sentence that matters.** A transaction no longer chooses its tenant. It presents
a 244-bit credential to a hardened `SECURITY DEFINER` function, which hashes it, looks the
digest up in a table no runtime role can read or write, and — if the binding is known,
unrevoked and unexpired — writes one row into a protected relation no runtime role can
read, write, delete from or clear. Every policy reads that. `app.tenant_id` is read by
nothing, and `firmbatch.app_current_tenant_id()` is dropped.

(244 bits and not 256: PostgreSQL generates the value from two `gen_random_uuid()` values,
122 random bits each. The standalone Python generator uses 32 random bytes and is 256 bits.
Both share one 43-character format, and the 43 is a rendering rather than a measurement.)

Eight things worth a reviewer's attention, in descending order of consequence:

1. **The transaction context is a protected permanent relation, not a setting and not a
   temporary table, and the reason is worth reading before the code.** Any custom GUC is
   writable by the role holding the connection, so a settings-based scheme is either
   forgeable or circular. `firmbatch.auth_transaction_context` is an unlogged table in the
   pinned schema, keyed by the backend pid and carrying the `xid8` of the transaction that
   wrote it; it is read back only when that id equals `pg_current_xact_id_if_assigned()`.
   No runtime role holds any privilege on it, so nothing but the `SECURITY DEFINER` writer
   can touch it, and there is no clearing operation anywhere — none is needed, because an
   uncommitted row is invisible to every other transaction and a committed one can never
   match a future transaction's id. ADR 0006 decision 2.
2. **The first version put this in `pg_temp` and that was wrong**, which is recorded here
   rather than quietly replaced. `DISCARD TEMP` is legal for any role, needs no privilege,
   and drops every temporary table in the session including one owned by somebody else — so
   the context vanished and a *second* credential could be bound in the same transaction.
   Measured against a real server. There was no privilege to revoke and no check to add,
   which is why the design changed rather than being hardened. ADR 0006 decision 2 records
   the measurement; the rejected alternative is kept at the end of that ADR.
3. **ADR 0004's position on `SECURITY DEFINER` in a policy predicate is deliberately
   reversed**, and the reasoning is in ADR 0006 decision 3a. The 2.1 helper read a value
   the caller could write; the 2.3 reader reads a relation the caller cannot read, which is
   the entire point. Every definer function is owned by the schema owner, pins
   `search_path`, revokes `PUBLIC`, is granted minimally, contains no dynamic SQL and
   resolves no object by name at runtime — five properties, five separate tests.
3a. **Revoking from `PUBLIC` is not stating the access control**, and the review was right
   that it was all the first version did. `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>` grants
   at object-creation time, so the grant is on `auth_bindings` before the migration's next
   statement runs. The migration now sanitises every relation, function and type in the
   schema; `db/roles.py` runs the identical block before its grants; and `db/principal.py`
   refuses a connection that holds any privilege on protected state. Three measures, because
   a default-privilege rule outlives a migration and a database can be migrated without
   being wired. ADR 0006 decision 3b.
3b. **The bind refuses any isolation level but `READ COMMITTED`, in the database.** Under a
   stricter level the registry lookup reads a snapshot older than the statement, so a
   revocation committed in between is invisible. Expiry is compared against
   `clock_timestamp()` rather than `now()` for the same family of reason, and the
   linearisation point is stated and tested. ADR 0006 decision 3c.
4. **Provisioning can no longer name a tenant, including an existing one.**
   `begin_tenant_provisioning()` takes no arguments and generates the id itself. This is
   strictly narrower than M2.1, where the provisioning role could set context to any tenant
   and read or amend that row. **Registration takes no credential either**, for the same
   family of reason: a caller that could submit a candidate could learn from the outcome
   whether it already existed in another tenant. The database generates it and returns it
   once. ADR 0006 decision 7b.
5. **Appending an audit event requires no scope, and the cost is named rather than
   hidden.** An `audit:append` capability would make it possible to issue a credential that
   acts without leaving a trail. The price is that a credential with no scopes can write
   bounded, tenant-scoped, immutable audit rows. ADR 0006 decision 6a. **`occurred_at` is
   written by a trigger from `clock_timestamp()`**, not defaulted from `now()`: a caller
   backdates an event by opening its transaction early, without supplying anything, and a
   policy comparing against `now()` would have agreed with it.
6. **Authentication itself is not audited, and cannot be.** A failed bind has no tenant to
   scope a row to and aborts the transaction that would have written one; a successful bind
   happens per request. Credential registration and revocation are audited. Failure belongs
   in the application log, which is Milestone 8's. ADR 0006 decision 6d.
7. **`INSERT ... RETURNING` applies `SELECT` policies**, so a write-only credential cannot
   insert through the ORM. That is PostgreSQL behaving correctly; it is why the `tenants`
   read rule includes the provisioning scope, why the audit insert carries no `RETURNING`,
   and it is asserted as documented behaviour rather than left to be discovered.
8. **Four of the five `AUTH-BOUND-TENANT-CONTEXT` completion cases are met.** The fifth —
   an authenticated user with no membership in a workspace — needs memberships, which are
   Milestone 3's. The task is not closed here and this branch does not close it.

Deliberately deferred, and each is somebody's later milestone: signup, login, accounts,
memberships, invitations and portal UI (M3); product API credential CRUD and browser
sessions (M3); HTTP endpoints and an API framework (M3); jobs, quotes, billing and
lifecycle state machines (M2.4, M4, M5); S3 and the payload plane (M5); the outbox
dispatcher and SQS (M6); Secrets Manager and KMS adapters (M8); provider credentials and
execution (M6); the operator agent (M6, separate software).

Known limits carried out of this slice, in prose rather than as passing tests:

- a compromised **migration owner** credential defeats all of it, because that role owns
  the functions and the policies. `db/principal.py` refuses to let a runtime connection be
  or reach that role, and `test_ownership_boundary.py` asserts it — that is the boundary,
  not an absence of one;
- on authentication the raw credential travels to PostgreSQL once as a bound parameter, and
  on registration it comes back once in a result row. psycopg sends parameters out of line,
  so neither is in the query text or in `pg_stat_activity`, but a server configured to log
  parameters — or a client that logged result sets — would capture one exactly as it would
  a password. Deployment property, Milestone 8;
- the context costs **one upsert per authenticated transaction** and a primary-key lookup
  per policy evaluation. That is the cost the temporary-table design was avoiding, and the
  property it bought instead was not real. If the read ever matters the fix is a
  per-transaction cache, not a weaker check;
- `clock_timestamp()` is the *server's* clock. A wrong server clock produces wrongly dated
  audit events and nothing here detects that; what is excluded is a caller choosing the
  time;
- the secret-shape rules and the metadata bounds are defense in depth and prove nothing
  semantic, exactly as ADR 0005 decision 9 says of the denylist they extend. `hunter2` is a
  valid reference name and a valid metadata key, and there is a passing test whose subject
  is that limit.

One protected-file change, and only one: `scripts/verify-repository.sh` gains **thirteen**
entries in `REQUIRED_FILES` (86 now, from 73) and **no new gate**, because the
foundation-suite gate already runs the whole `control_plane/tests` directory. Nothing else
under `AGENTS.md`'s ask-first list was touched, and **none of the three security correction
passes changed either file again** — they added no files, so the manifest is unchanged
from the first pass. `scripts/check-runtime-imports.py` — which
is not on that list — gains seven entries in its `RUNTIME_MODULES` manifest so the new
runtime modules are covered by the import-boundary check; no gate logic changed, and the
change strengthens the check rather than relaxing it.

Order for the human, from here:

1. Review `docs/adr/0006-authenticated-authorization-audit-and-secrets.md`, in particular
   "What this does not claim" and the rejected alternatives.
2. Review the one protected-file change and the `RUNTIME_MODULES` manifest entry above.
3. `./scripts/verify-repository.sh` was run with `FIRMBATCH_TEST_DATABASE_URL` set at
   `89fbdd9`: **14 gates passed, 0 failed**, and the PostgreSQL foundation suite **1,314
   passed, 1 skipped** — the one skip is the pre-existing REPLICATION skip. Skip counts
   differ by cluster shape; see the M2.1 CI correction above.
4. Push the branch, open the pull request, and merge after all required checks pass.
5. If promoting M2.3 to **VERIFIED LIVE**, capture the foundation-suite run with
   `/record-evidence` under `docs/evidence/m2/`. Otherwise retain the
   **implemented and tested** classification — no evidence artifact has been captured, so
   M2.3 is not VERIFIED LIVE today.

### The M2.3 security correction passes — twenty-three findings, all closed

Four independent reviews of the M2.3 implementation found twenty-three issues between
them, ten of them P1. Every one was confirmed against a real server before being fixed.
`docs/STATE.md` has the four tables of what was demonstrated and what closed it; the ones
worth a reviewer's attention here are the ones that changed the design rather than hardening
it.

1. **`DISCARD TEMP` defeated the temporary-table context** (P1). One statement, legal for
   any role, no privilege required: it drops every temporary table in the session including
   one owned by somebody else. The context vanished and a **second** credential could then
   be bound in the same transaction. The temporary table is gone; the context is an
   unlogged protected table keyed by the transaction's `xid8`, and there is no clearing
   operation anywhere. This is the architecture change, and ADR 0006 decision 2 records it
   as one.
2. **Default privileges could grant the credential registry to the runtime role** (P1).
   `REVOKE ... FROM PUBLIC` never touched a grant `ALTER DEFAULT PRIVILEGES` applied at
   object-creation time. Three measures now: the migration sanitises the whole schema, the
   role wiring sanitises again before granting, and the runtime principal check refuses a
   connection holding protected privileges.
3. **Registration took the credential as an argument** (P2), which made success-versus-
   failure a cross-tenant existence oracle. The database generates it now and returns it
   once.

From the second review:

4. **The principal check followed inheritance, and `SET ROLE` does not** (P1).
   `has_table_privilege` and `has_function_privilege` answer about *effective* privilege, so
   `GRANT other TO firmbatch_app WITH INHERIT FALSE, SET TRUE` left both saying "no" while
   one `SET ROLE` reached everything `other` held. Measured: the connection was certified
   safe and read the credential registry a statement later. Every reachable role is now
   enumerated with `pg_has_role(..., 'MEMBER')` and every object test runs against that set
   — and a runtime principal may hold **no membership at all**.
5. **`credential:manage` decided what the credentials it minted could do** (P1). A leaked
   credential holding nothing else could mint itself a successor holding `workspace:write`.
   Delegation is now bounded in the database: delegable scopes only, and never more than the
   issuer holds. There is no wildcard, and `tenant:provision` is delegable by nobody.
6. **Role wiring assumed the head schema** (P1/P2). After a controlled rollback to `0002`,
   provisioning failed with `UndefinedTable` on its first statement. `db/roles.py` is now
   revision-aware, with an explicit plan per supported revision and a refusal for anything
   else. Application code at head supports schema `0002` **only** for controlled rollback
   and provisioning — never for runtime operation.
7. **The audit metadata policy was bypassable** (P2). The application role held `INSERT` on
   the trail, and the table's constraints bound a document's size and shape and nothing
   about its content. The privilege is gone; `firmbatch.append_audit_event()` is the only
   way in and applies the whole policy inside the database.
8. **Authenticated work needs a writable primary** (P2), because acquiring a context writes
   a row. That is now a deliberate, named refusal rather than an unexplained write error,
   and it is a stated limitation: **read-replica routing is Milestone 8**.

The other four -- stale-snapshot revocation and `now()`-based expiry, echoed reference
identifiers, transaction-start audit timestamps, and echoed metadata keys -- are corrected
in the same pass and are covered in `docs/STATE.md`.

From the third review, three more:

9. **Column-level ACLs bypassed the protected-state boundary entirely** (P1). As the
   migration owner, `GRANT SELECT (backend_pid), UPDATE (tenant_id) ON
   firmbatch.auth_transaction_context TO <application role>` — and the hardened checkout
   accepted the connection. The application could then authenticate as tenant A, rewrite
   its own context row's `tenant_id` to tenant B, and read tenant B's rows. Column grants
   live in `pg_attribute.attacl`; the principal check asked `has_table_privilege` and both
   ACL sanitisers took their grantee list from `pg_class.relacl`, where a column-only
   grantee never appears. Both are corrected, and the column check is **independent** of
   the table check rather than folded into `has_column_privilege`, which conflates them.

   Worth recording because the review's diagnosis was not quite the defect: the report said
   `REVOKE ALL ON TABLE` does not remove a column grant. It does — measured. What never
   happened was the enumeration, so the `REVOKE` was never issued.
10. **Python `\s` and PostgreSQL `[[:space:]]` are different sets** (P2), so the metadata
    policy's two implementations disagreed on real values: a U+00A0 before `Bearer example`
    was refused at the boundary and accepted by the database, which is the half that holds
    when a runtime role writes the call itself. Confirmed and wider than reported — U+0085,
    U+00A0, U+2007, U+202F **and** the ASCII information separators U+001C–U+001F all
    diverge on this server. Whitespace is now an enumerated code-point set folded to ASCII
    by both implementations before any pattern runs, and the patterns say `[ ]`/`[^ ]` in
    both languages. Ordinary Unicode letters are untouched and stay valid.
11. **The standby diagnostic was unreachable on a standby** (P2). `auth_transaction_context`
    is `UNLOGGED`, and PostgreSQL refuses to *plan* a query against an unlogged relation
    during recovery — so the context read every entry path began with failed before the
    deliberate `auth_require_writable_primary()` guard could speak. A preflight naming
    nothing in the schema now runs first on every entry path, and the database guard is the
    first executed statement of both entry functions so raw-SQL callers fail safely too.
    **Authenticated reads remain primary-only; read-replica routing is Milestone 8**, and no
    live standby has been tested or claimed.

The suite is **1315 checks (1,314 passed, 1 skipped locally)**: 805 after the first
correction pass, 934 after the second, 1122 after the third, and 1314 after the fourth,
which added 192. Nothing was weakened to make any of them pass — the four tests whose subject was a mechanism that no
longer exists were rewritten to assert the property that replaced it, and each says so in
its docstring. Every test added by the third and fourth passes was run against the pre-fix
code and seen to fail for the intended reason.

### The case-fold half of finding 10 — closed in a fourth pass

Fixing whitespace left the identical defect one clause over, and the review that found it
was right that it is a defect rather than a design question: it is fixed, not deferred.

`re.IGNORECASE` on `str` is Unicode case folding; PostgreSQL's `~*` is locale case folding.
Measured on this server, with the whitespace fix already in:

| value | `looks_like_secret` | `firmbatch.secret_shape` |
| --- | --- | --- |
| U+017F + `ecret=x` (LATIN SMALL LETTER LONG S) | refused | **accepted** |
| `api` + U+212A + `ey=x` (KELVIN SIGN) | refused | **accepted** |

The direction is the dangerous one: the database is the half with no Python in front of it.

**The correction.** One pipeline in both implementations — fold the 29 enumerated whitespace
code points to an ASCII space, fold `A`–`Z` to `a`–`z`, then match **case-sensitive**
lowercase patterns. Nothing consults a locale or a Unicode table: `str.translate` here,
nested `translate()` there, and no `str.lower()`, `str.casefold()`, `lower()`, `upper()`,
`~*` or `(?i)` anywhere. `\b`/`\y` went the same way, replaced by an explicit
`(?<![0-9a-z_])`, because they are the same locale question in other clothes.

With every construct either engine has to look up removed, the pattern text itself is now
**identical in both places**, and a test compares it character for character rather than
comparing answers on samples somebody chose. Every caller inherits it: there are exactly two
implementations of the rule and everything goes through one of them.

**The limitation it buys, and it is a real one.** A Unicode homoglyph of a marker is now
recognised by *neither* implementation, where before it was caught by one. That is the
honest cost of an ASCII fold and the right trade — a Unicode fold cannot be reproduced by
`translate()`, so keeping it leaves the layer a caller can walk around stricter than the
layer that actually holds. The denylist is defense in depth against a credential pasted
where a reference belongs; it does not claim to detect a semantic secret and does not claim
to survive a homoglyph. Both homoglyphs sit in the **accepted** corpus so the limitation is
a test somebody has to change on purpose. See ADR 0006 decision 8c.

One behaviour change worth knowing: because the word boundary is ASCII-explicit now, a
non-ASCII letter counts as a boundary, so `ıtoken=x` is recognised where `\b` and `\y` both
used to say nothing. Stricter, and both implementations say it together.

### `AUTH-MEMBERSHIP-BOUND-IDENTITY` — Milestone 3, and it blocks launch — PLANNED

The successor to the identity half of `AUTH-BOUND-TENANT-CONTEXT`, recorded under its own
name because the old one now describes a gap that is closed. Naming the remainder after the
closed thing is how a finished piece of work gets re-litigated and an unfinished one gets
overlooked.

**What must become true.** An authenticated customer identity must be **proven to be an
active member of the selected workspace and tenant** before a browser session or an account
credential is issued for it.

Today a credential *is* the membership: a binding names one tenant, and the database will
not issue a context for any other. That is sufficient while credentials are provisioned out
of band and there are no user accounts. It stops being sufficient the moment a person can
sign in and choose a workspace, because something then has to decide which workspaces that
person may choose from — and nothing does.

**Why M2.3 could not close it.** There are no users, no memberships, no invitations and no
sessions in this repository. The old completion case 5 asks what happens to an
authenticated non-member; with no membership model there is no such person to test, and
building a partial one here would be the half-built capability ADR 0004 §8g argues against.

**Completion gate.** Adversarial tests, against real PostgreSQL 16, each failing closed:

1. A verified account with no membership in a workspace cannot obtain a session or a
   credential scoped to it, by any route the API exposes.
2. Revoking a membership stops the identity acting in that workspace, on the same
   linearisation terms the credential path already states.
3. An invitation accepted for one tenant grants nothing in another.
4. A session and an API credential remain distinct, and neither can be exchanged for the
   other.

**Customer-facing deployment remains blocked** until Milestone 3 supplies identity,
membership and credential lifecycle together.

### M2.4 — explicit lifecycle state machines — PLANNED

The next planned Milestone 2 slice. Conditional, persisted transitions that invalid
transitions cannot race through. Not started.

**Milestone 2's completion gate is met and Milestone 2 is still open.** The gate is
cross-tenant reads and writes failing closed in automated tests **and** duplicate mutations
producing one contractual effect; M2.1 delivered the first half, M2.2 the second, and M2.3
re-established the first on a mechanism a compromised runtime cannot drive. The milestone's
declared scope is wider than its gate — of the items listed under Milestone 2 in the
canonical roadmap, audit events, tenant-scoped authorization and the secrets and encryption
model are now built, and **explicit lifecycle state machines are not**. Do not close the
milestone on the gate sentence.

Do not implement execution, customer billing, or the portal opportunistically inside this
milestone.

---

## Environment note — running the foundation suite

The developer's WSL environment has no Docker, so the suite runs against **native**
PostgreSQL 16 (16.15 observed). CI uses a `postgres:16` service container. Both reach the same
`scripts/verify-repository.sh`.

Environment facts worth writing down, because none is obvious and each cost a debugging
round:

- The admin role needs `CREATEDB` and `CREATEROLE`. Locally a **non-superuser** admin is
  preferable: it cannot accidentally read through the policies while investigating. CI's
  admin is the `postgres` **superuser** of an ephemeral service container, and that is
  accepted — the bootstrap administrator is trusted inside an attested disposable
  cluster. Nothing may require the admin to be a non-superuser; see ADR 0004 section 8f.
- Roles created by the bootstrap **cannot** authenticate over the unix socket under the default
  Debian/Ubuntu `local all all peer` line in `pg_hba.conf`. The bootstrap therefore builds the
  application and provisioning URLs against the server's TCP endpoint (`SHOW port` on loopback)
  even when the admin URL is a socket. Do not "simplify" that to reuse the admin URL host.
- **`FIRMBATCH_TEST_DATABASE_URL` now needs an explicit port**, and an explicit user, host
  and database. A URL that used to work without `&port=5432` is refused: the port it was
  silently using came from `PGPORT` or a compiled-in default. Multi-host failover URLs are
  refused for the same reason.
- The server needs the disposable-cluster marker before anything can be created or dropped
  (`attestation.py --mark`, once per cluster). The local WSL cluster was marked on 2026-09-03
  after confirming it held only `postgres`, `template0`, `template1` and zero user tables.
- `inet_server_port()` returns **NULL** over a unix socket, so it cannot be used to check that
  two URLs point at the same server. The bootstrap records the endpoint at creation and compares
  against that instead. This was a real defect that dropped a live test database.
- **Teardown does not use `DROP DATABASE ... WITH (FORCE)`, and must not be changed to.**
  This note previously said the opposite, and it was wrong in a way worth spelling out.
  `FORCE` needs the privileges of the roles whose backends it terminates, so adopting it
  means *broadening* the role that performs teardown rather than narrowing it — the exact
  move ADR 0004 §8e argues against, and the exact move that would undo the per-run owner
  being a restricted identity. The implementation carries no `FORCE` anywhere, and a test
  asserts that on the source.
- What happens instead, in this order: the per-run owner revalidates the target on its own
  connection (attestation, cluster, endpoint, database name, OID, provenance, live owner),
  then revokes `CONNECT`, then terminates the remaining backends, then drops. Every one of
  those statements runs as the owner, so PostgreSQL's ownership check — evaluated against
  whatever object exists at that instant — is what actually guards them. The owner can
  terminate the runtime roles' backends because it is granted membership in them at
  bootstrap, which is a narrower grant than `FORCE` would require.
- If the connections cannot be disposed of, the database is **left in place and reported**
  as a cleanup failure. That is the designed outcome, not a bug to route around: an
  operator must not widen teardown authority to make cleanup pass. Dispose application
  engines before teardown and the situation does not arise.
- PostgreSQL 16 splits the `SET` option out of `ADMIN` on role membership. A `CREATEROLE`
  creator gets `ADMIN` but not `SET`, so `CREATE DATABASE ... OWNER <role>` and
  `ALTER TABLE ... OWNER TO <role>` both need an explicit
  `GRANT <role> TO CURRENT_USER WITH SET TRUE` first. The bootstrap takes that grant for
  exactly one statement and gives it back in a `finally`.
- Give that grant `INHERIT FALSE, ADMIN FALSE` as well. Granted without them,
  `REVOKE SET OPTION FOR ...` leaves an **inheriting** membership row behind, so the admin
  holds the owner's privileges without being able to name the role. Verified both ways
  round against a real server.
- `pg_has_role(..., 'MEMBER')` is the wrong probe for "can this role become that one". In
  PostgreSQL 16 it stays true for the implicit `ADMIN` grant a `CREATEROLE` creator
  receives, even when `SET ROLE` is refused. `'SET'` (may become it) and `'USAGE'`
  (inherits it) are the two that describe real reach.
- **But `pg_has_role` is the wrong question to ask of the bootstrap administrator at all.**
  It folds in superuser authority, which no revoke changes, so requiring it to be false
  made bootstrap unsatisfiable on CI. Assert the **catalogue** instead —
  `pg_auth_members.set_option` / `.inherit_option`, direct rows and a recursive walk —
  which asks what grant was left behind rather than who could get in. That property is
  true of a superuser and a non-superuser admin alike.
- `ALTER DATABASE ... OWNER TO` requires the *current* owner to hold `CREATEDB`, and
  `ALTER <object> OWNER TO` requires the *incoming* owner to hold `CREATE` on the schema.
  Both are why the ownership tests are shaped the way they are.
- After bootstrap a **non-superuser** admin genuinely cannot drop the disposable database:
  it gets "must be owner of database". A superuser admin can, and that is accepted. Tests
  that deliberately break the normal teardown path use `conftest.drop_disposable_objects`,
  which re-acquires `SET` through the `ADMIN` option a non-superuser still holds. That
  says something true about the threat model rather than working around it
  — the per-run owner is protected from a concurrent process, not from the
  administrator that created it.
- Releasing a savepoint does **not** undo a `SET LOCAL` made inside it; only rolling the
  savepoint back does. That is why tenant switches inside a savepoint are refused outright
  rather than unwound.
- A non-superuser with `CREATEROLE` cannot set a custom GUC as a role or database default
  (`ALTER ROLE ... SET app.tenant_id` is refused), so that particular poisoning route is not
  reachable locally. It is reachable in CI, where the admin is a superuser, and is covered by
  the connect-time clear plus the per-transaction baseline.

---

## Resolved during repository initialization and the R0 audit

### 1 · Ruff findings in existing v0 code — frozen as per-file exceptions

`ruff check .` reported **21 findings, all in pre-existing v0 code**, none introduced by the
repository-initialization pass:

| Rule | Count | Where | Nature |
| --- | --- | --- | --- |
| `E702` multiple statements on one line (semicolon) | 16 | `fb.py:211–251` | The argparse block's deliberate compact style |
| `E401` multiple imports on one line | 3 | `demo/make_requests.py:4`, `fb.py:179`, `tests/test_recovery.py:6` | Deliberate terse imports |
| `E741` ambiguous variable name `l` | 1 | `fb.py:52` | `[json.loads(l) for l in open(a.file)]` |
| `F841` local variable `e` assigned but never used | 1 | `fb.py:172` | `except Exception as e:` where `e` is unused |

Resolved with narrowly scoped `[tool.ruff.lint.per-file-ignores]` in `pyproject.toml`. No
source file was modified, no rule was weakened globally, and nothing was auto-fixed. The
breakdown was re-verified during the R0 audit and is exact.

**These are frozen v0 exceptions, not conventions for new code.** Any file not named in that
table gets the full rule set. Do not extend the list to new modules; when one of these three
files is genuinely rewritten under the roadmap, delete its entry rather than growing it.

### 2 · Claude resolves the `.claude/skills/` symlinks — confirmed

`verify` and `record-evidence` appear in the session skill listing, resolved through the
symlinks. `milestone` is absent from the model-facing listing only because it sets
`disable-model-invocation: true`, which is intended — it is user-triggered. The Claude
`PreToolUse` hook is also confirmed loaded and blocking: an attempted `.env` read was denied
with the `credential-read` rule name intact.

`scripts/verify-repository.sh` now gates the symlinks structurally, so a future replacement
of a link by a copy fails verification rather than drifting silently.

### 3 · Guard hardening — the R0 accident paths

The R0 audit found the guard's enforcement claim false for several forms an aligned agent
plausibly types. Each is now covered by a synthetic test asserting the *invariant*, written
before the fix. `.agents/policy/test_guard.py` is at **247 checks**.

Closed: `git -C` / `git -c` and other valued global options hiding the subcommand; `gh`
equivalents of commit, push, and merge; `env`/`nohup`/`timeout`/`nice`/`stdbuf`/`command`
prefixes; `cd X && ...` changing what a relative path means; unparseable input failing open;
wrapper-depth exhaustion falling through; argparse-abbreviated provider selection
(`--prov verda`) and unprovable provider values; recursive deletion of an ancestor of
`docs/evidence`; source as well as destination operands for `cp`/`mv`/`install`/`ln`/`rsync`;
in-place archivers (`gzip`, `xz`); `sed --in-place`; credential reads through `Read`, `Grep`,
`Glob`, and ordinary shell readers beyond the twelve-name list.

A **second** review round then found eleven more, all of which were ALLOWED by the first
round of hardening and all of which are ordinary shapes. Closed: a multi-line bash block
being classified only by its first command word (`shlex` treats a newline as whitespace,
so `SEPARATORS` containing `\n` was dead code — this was the largest hole); `rm -rf *`
and `rm -rf docs/*`, where a glob operand skipped the evidence-ancestor rule; `mv docs
/tmp/old` and `rsync --delete`; `gh -R o/r pr merge` and `aws --region x ec2
terminate-instances`, which repeated the `git -C` positional bug; `bash --norc -c`, where
a letter-membership test matched the wrong flag and recursed on the wrong token;
`timeout 5m` and `env -u NAME`, where a non-numeric option value stopped prefix
stripping; a leading `(` making a visible `rm` unclassifiable; `git restore <file>`;
`.env.local` and the rest of the `.env.*` family; and an unrecognised tool name carrying
a command or patch, which failed open.

One of those was a **regression this remediation introduced**: adding `pushd` to the
directory tracker without `popd` turned a previously correct deny into an allow, because
the parser then believed the shell was somewhere it had already left. `cd -` and `||`
were wrong for related reasons. All three now have tests.

**Deliberately left open**, and documented as outside the guarantee in `AGENTS.md` and
`.codex/README.md`: interpreters (`python3 -c`, `perl -e`, `awk`), `sudo`, `xargs`,
`busybox`, subshells, command substitution, `eval`, here-documents. Closing these would buy
an argument against an adversary that cannot be won at this layer.

**Deliberately not locked:** the guard does not protect its own configuration. Human approval
before changing `AGENTS.md`, `CLAUDE.md`, `.agents/policy/`, `.claude/settings.json`, or
`.codex/hooks.json` is an `AGENTS.md` rule, not a hook rule.

### 4 · `docs/current-state.md` — resolved in favour of `docs/STATE.md`

The roadmap previously named `docs/current-state.md` as a required artifact while the
repository had `docs/STATE.md`. Resolved by amending the roadmap (six references) to name
`docs/STATE.md`, which is cited by `AGENTS.md`, all three skills, both reviewer sets, the ADR,
and the policy tests. **There is one state document. Do not create a second.**

### 5 · Verification — one entry point

`scripts/verify-repository.sh` replaces three commands run across two working directories.
Twelve gates at R0; **fourteen** since Milestone 2.1 added the runtime import closure check and the PostgreSQL foundation suite. That suite creates and drops one disposable database and three per-run roles, and leaves exactly one role behind on purpose: the persistent `firmbatch_disposable_test_cluster` attestation marker.
`AGENTS.md`, the `verify` skill, and `.github/workflows/ci.yml` all invoke it.

**Milestone 2.2 added no gate**, and that is the correct outcome rather than an omission:
the foundation-suite gate runs the whole `control_plane/tests` directory, so new test
modules are already inside the authoritative path. What M2.2 added is six entries to
`REQUIRED_FILES` (73 now, from 67), so that deleting one of the new canonical files fails
the layout gate instead of quietly shrinking the suite.

### 6 · `.codex/hooks.json` resolves the guard from the repository root

Codex previously invoked the relative `.agents/policy/guard.py`. From any cwd other than
the repository root, `python3` would exit 2 on the missing file — which the Codex adapter
contract reads as *block*, so it failed closed rather than open, but it then blocked
**everything**, silently, with no signal that the guard was not actually running.

It now uses the supported form, which is symmetrical with the Claude side's
`$CLAUDE_PROJECT_DIR`:

```
/usr/bin/python3 "$(git rev-parse --show-toplevel)/.agents/policy/guard.py" --adapter codex
```

Exercised by hand from `docs/evidence/v0/` — a `git push --force` payload blocks with the
rule name at exit 2, and `git status` allows at exit 0 — but **no artifact records this**,
so it is asserted, not VERIFIED. The matcher, `timeout: 10`, `synchronous`, and `blocking`
are unchanged. The absolute
interpreter is the system `/usr/bin/python3` (3.12.3 here) rather than the conda
environment's, which is deliberate: `guard.py` is stdlib-only, and a hook must not depend
on which environment happens to be activated.

**The fix is partial, and the residue is recorded rather than hidden.** `git rev-parse`
is a function of the working directory, so this is narrower than the Claude side's
harness-supplied `$CLAUDE_PROJECT_DIR`. Measured behaviour of the new form:

| Hook cwd | Result |
| --- | --- |
| repository root | blocks correctly, exit 2 |
| any subdirectory (`docs/evidence/v0/`) | blocks correctly, exit 2 — this is what the fix bought |
| outside any work tree, incl. `/home/chams/src` | empty substitution → blocks **everything**, empty stdout, exit 2 |
| `git` not on `PATH` | blocks everything |
| exec'd without a shell | `$(...)` stays literal → blocks everything |
| repository path with spaces or quotes | blocks correctly (the substitution is double-quoted) |

Every degraded case fails **closed**, which is the right direction, but the symptom is a
Codex session where nothing works and nothing says why — and the most likely operator
response to that is to disable the guard. Two things would close it properly: a
Codex-supplied project-directory variable if one exists, or a content gate in
`scripts/verify-repository.sh` asserting the Codex hook command invokes `guard.py` with
`--adapter codex`, matching the gate the Claude side already has. Neither was in the
approved scope of this correction.

Two further limits worth knowing. The degraded cases signal only through the exit code,
with empty stdout; if Codex keys its block on the JSON body rather than the status, they
fail **open** instead — which makes open item 8 below load-bearing for more than
discovery. And `/usr/bin/python3` missing gives exit 127, the canonical
hook-could-not-run signal, which is the state the Claude adapter documents as fail-open.

### 7 · CI — observed externally, evidence artifact pending

`.github/workflows/ci.yml` now calls the verification script instead of duplicating its
commands, adds `permissions: contents: read`, and no longer installs
`requirements-v0-lock.txt` — none of the gates need it (all three are stdlib-only plus ruff),
so it was a failure surface with no coverage benefit, and the lock is incomplete anyway
(`anyio` needs `sniffio`, unpinned).

The fragile part is unchanged and deliberate: `tests/test_recovery.py` does
`from firmbatch.control import db`, so the workflow checks out with `path: firmbatch` and the
script runs the property tests from the **parent** directory. Do not "simplify" it.

Push and pull-request checks passed for PR #2 on 2 September 2026. Because the repository's
VERIFIED LIVE taxonomy requires an immutable artifact under `docs/evidence/`, this remains an
external observation until the run identity and output are captured with the evidence procedure.

---

## Open — verification the tooling still needs

### 8 · Confirm Codex discovers `.codex/hooks.json` and `.codex/agents/*.toml`

Both adapter protocols pass synthetic tests over the full stdin/stdout/exit-code contract,
but nothing has yet observed Codex *loading* these files in a live session. Until it has, the
Codex-side guard is declared, not proven.

To confirm: open a Codex session in this repository and attempt a blocked action, e.g.
`git push --force` or editing `docs/evidence/v0/local-demo-001-report.txt`. Expect a block
carrying the rule name. Capture the result with `/record-evidence` as
`docs/evidence/r0/codex-hook-discovery.txt`. If the hook does not fire, the schema in
`.codex/hooks.json` is wrong and the fix is there — not in `guard.py`, whose protocol is
tested.

Manual protocol check, which does pass today:

```bash
echo '{"tool_name":"shell","input":{"command":"git push --force"}}' \
  | python3 .agents/policy/guard.py --adapter codex; echo "exit=$?"   # expect block, exit=2
```

### 9 · Reviewer tool declarations were not honoured in this session

Two of the three reviewers dispatched during the R0 remediation reported a toolset that
did not match their definition: one had `Bash` available and `Glob` missing, the inverse
of its `tools: Read, Grep, Glob` line. Both used the shell read-only and disclosed it.
Until this is explained, **treat reviewer read-only as an instruction the reviewer
follows, not a constraint the harness imposes**, and do not rely on it to bound a
reviewer's effects. `scripts/verify-repository.sh` gates the declaration, which is all a
static check can do. To settle: dispatch a reviewer and have it report its own toolset.

Related: one reviewer's loaded instructions matched the **pre-remediation** file on disk,
so a definition change does not reach an already-running session. Expect a lag of one
session after editing `.claude/agents/` or `.codex/agents/`.

### 10 · Claude-side fail-open under hook crash or timeout

The adapters now deny on an unexpected exception, and that is covered by tests. What remains
unobserved is the harness end: whether Claude Code proceeds with a tool call when the hook
process exits non-zero with empty stdout, or when the 10s timeout expires. The guard can no
longer produce that state on its own, but a missing `python3` or an unset
`$CLAUDE_PROJECT_DIR` still can. Needs a live hook invocation to settle.

---

## Milestone 1 result and diagnostic backlog

The canonical audit gate was satisfied by `docs/architecture/v0-to-v1-migration-audit.md` and
merged at `6b4f341`. The following experiments remain useful diagnostics against frozen v0.
They are not permission to launch billable capacity, they were not prerequisites for the
Milestone 1 gate, and they are not prerequisites for Milestone 2.

### 11 · Reproduce the real preemption path locally

The v0 baseline claimed three SIGKILLed workers; no artifact shows one. The corrected
`--chaos` procedure in the `verify` skill now isolates the port, waits for readiness, traps
cleanup, and says explicitly that **stdout must be captured**, because the kill is visible
nowhere else. Run it with `--chaos-after` past the scale-down window so the preemption path,
not scale-down, reclaims the shards, and assert `no_heartbeat` appears.

### 12 · Preserve the D1 failing case for the target regression suite

Claim a shard with `lease_secs=1`, `reap()`, re-claim as a second worker, then POST
`/w/results` with `done: true` as the first worker. Assert the shard is not `done` and the
second worker's remaining requests are still issuable. It fails conceptually under v0 and must
become a passing target-attempt test in Milestone 6.

### 13 · Make reconciliation reports reproducible

No script currently generates `local-demo-001-reconciliation.json`. Any new diagnostic run must
commit or capture the exact read-only reconciliation query set without rewriting historical evidence.

### 14 · Align protected agent instructions after explicit approval — **RESOLVED**

`AGENTS.md` and `.agents/skills/milestone/SKILL.md` named the superseded pilot roadmap. With
explicit human approval, both were narrowly corrected during Milestone 2.1:

- `AGENTS.md` now states the authority order — `docs/firmbatch-v1-roadmap.md` canonical,
  `docs/architecture/v1-target-architecture.md` the implementation specification with its §17
  invariants, `docs/STATE.md` for what the code does now, and the pilot roadmap explicitly
  superseded. The working contract's items 1 and 4 now cite the canonical roadmap and §17
  rather than the pilot roadmap's §7 and §5.
- `.agents/skills/milestone/SKILL.md` inspects the canonical milestone and §17 first, and names
  the migration audit as a required input. Its inspect → gap → bounded plan → implementation →
  verification → durable-state workflow and its approval requirement are unchanged.

No guard, hook, reviewer, or other agent-configuration change was made.
