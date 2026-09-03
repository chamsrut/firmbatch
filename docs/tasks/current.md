# Current tasks

Active work and open questions. Updated at the end of each task, alongside `docs/STATE.md`.

Last updated: 2026-09-03, `main` merge commit `6b4f341`, plus Milestone 2.1 on
`feat/milestone-2-foundation` at `521870b` and the uncommitted CI correction to the
bootstrap administrator's trust boundary (PR #4).

---

## Active — Milestone 2, shared product foundation

Milestones 0 and 1 are complete; Milestone 1 merged at `6b4f341`. Milestone 2 is now the active
milestone. It has four slices, and only the first is built.

### M2.1 — PostgreSQL and tenant-isolation spine — **current slice, awaiting review**

Delivered in the working tree: the configuration boundary, Alembic migrations into a dedicated
`firmbatch` schema, the `tenants`/`workspaces` spine, forced row-level security with a
transaction-local tenant context, three separated roles with a verified runtime principal,
minimal typed repositories, a disposable-cluster attestation, and a **382-check** pytest suite
against real PostgreSQL 16 wired into `scripts/verify-repository.sh` and CI. See
`docs/STATE.md` for what it does, and `docs/adr/0004-postgresql-tenant-isolation-foundation.md`
for why.

**Six review rounds found fifty-eight issues in total; fifty-two are corrected and one has been reclassified.** The first round found fifteen, the second ten, the third eight, the fourth ten, the fifth ten, the sixth five. The fifth-round "blocker" was PostgreSQL 16's creator-ADMIN membership row, which a non-superuser cannot revoke; it is **not a defect** but the boundary the architecture draws, and the bootstrap assertion built on it had to be withdrawn after it made CI fail. See "M2.1 CI correction" below, ADR 0004 section 8f, and `control_plane/tests/test_admin_escalation.py`. Six were
security or destructive-safety defects reproduced against a real server before being fixed:
temporary-table shadowing, inherited tenant context, ORM identity-map leakage, an unverified
runtime principal, a teardown that trusted its handle (which dropped a real database during
testing), and a generated password reaching exception text. Each now has a regression test.
The table in `docs/STATE.md` lists what was demonstrated and what closed it.

Order for the human:

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
5. Capture the foundation-suite run with `/record-evidence` into `docs/evidence/m2/` — until
   that exists, the isolation properties are asserted-and-tested, not VERIFIED LIVE.
6. Human reviews and commits.

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

### M2.2 — idempotent mutations and the transactional outbox — PLANNED

Idempotency records keyed per tenant; a duplicate identical mutation returns one effect and a
conflicting reuse is rejected; state change and outbox event committed in one transaction.
Migration audit section 10 lists the required tests. Not started.

### M2.3 — audit events, tenant-scoped authorization, secrets model — PLANNED

Includes the piece M2.1 deliberately left open: resolving tenant context from an authenticated
credential rather than accepting a caller-set setting. Not started.

### M2.4 — explicit lifecycle state machines — PLANNED

Conditional, persisted transitions that invalid transitions cannot race through. Not started.

**Milestone 2's completion gate is not satisfied by M2.1 alone.** The gate is cross-tenant
reads and writes failing closed in automated tests **and** duplicate mutations producing one
contractual effect; M2.1 delivers the first half.

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
