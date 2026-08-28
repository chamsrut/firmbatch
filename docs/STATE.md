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

Last updated: 2026-08-28, at commit `d0aeee2` plus the uncommitted R0 working tree, branch
`repo-init/agentic-foundation`.

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

CI now exists (`.github/workflows/ci.yml`, added by R0), but has never been executed by a
runner.

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
| `scripts/verify-repository.sh` | The one verification entry point. Twelve gates. Invoked identically by the human, the `verify` skill, and CI. |
| `.agents/skills/` | `verify`, `record-evidence`, `milestone`. Symlinked into `.claude/skills/`; single body each. |
| `.agents/policy/guard.py` | Shared deterministic policy engine, `--adapter claude` and `--adapter codex`. An accident-prevention guardrail, **not** a sandbox or security boundary. |
| `.agents/policy/test_guard.py` | 241 synthetic checks. |
| `.claude/settings.json` | Blocking `PreToolUse` hook over `Write\|Edit\|MultiEdit\|NotebookEdit\|Bash\|Read\|Grep\|Glob`. |
| `.codex/hooks.json` | Synchronous blocking `PreToolUse` hook over `shell\|local_shell\|apply_patch\|Edit\|Write`. Resolves the guard via `git rev-parse --show-toplevel`, so it works from any directory **inside** the work tree rather than only from its root. It is not fully cwd-independent: from outside the tree — including `/home/chams/src`, the parent directory `AGENTS.md` tells every command to run from — the substitution is empty and the hook blocks every action with empty stdout. See `docs/tasks/current.md`. |
| Reviewers | `distributed-systems-reviewer`, `test-evidence-reviewer`, `security-operations-reviewer`, defined for both agents. **Declared** read-only: `tools: Read, Grep, Glob` on Claude (Bash removed), `read_only = true` on Codex — though Codex is also granted `shell` and must honour the flag itself. Whether either harness enforces the declaration is NOT VERIFIED; see below. |
| `pyproject.toml` | Ruff config only — no packaging table, deliberately. Frozen per-file ignores for the three v0 files. |
| `.github/workflows/ci.yml` | Calls `scripts/verify-repository.sh`. Checks out into `firmbatch/`; `permissions: contents: read`; installs only pinned ruff 0.16.5. |

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

True at the time of writing and re-checkable in one command, but with **no captured
artifact**, so **NOT VERIFIED** under this repository's own standard. Evidence for these is
deliberately deferred until the R0 files are committed: capturing now would cite `d0aeee2`,
a commit that does not contain them.

| Claim | How to settle it |
| --- | --- |
| All twelve gates in `scripts/verify-repository.sh` pass: layout, agent configuration, hygiene, property tests 14/14, `ruff check .` clean under the frozen per-file ignores, policy tests 241/241. | `/record-evidence` → `docs/evidence/r0/gates.txt`, after the R0 commit. |
| The shared policy engine denies the R0 accident classes across both adapter protocols — multi-line blocks classified line by line, `git -C`/`git -c`, `gh` and `aws` global options, `env`/`timeout` prefixes, `cd`/`cd -`/`pushd`/`popd`/`||` sequences, subshell grouping, argparse-abbreviated provider selection, evidence-tree ancestors including glob and `mv` forms, source and destination operands, in-place archivers, `git restore`/`checkout` over a path, credential reads on every surface including the `.env.*` family, wrapper- and prefix-depth exhaustion, unparseable input, unknown tool names carrying a payload, and engine exceptions. 241 synthetic checks pass. | `/record-evidence` → `docs/evidence/r0/policy-tests.txt`, after the R0 commit. |

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
- **Any CI run.** `.github/workflows/ci.yml` has never been executed by a runner. It remains
  NOT VERIFIED until GitHub actually runs it.
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

The v1 roadmap, `docs/firmbatch-pilot-roadmap.md`. **R0 (repository operating foundation)** is
the prerequisite section before Milestone 1; this remediation is its implementation. It is **in
progress, not complete**: its gate additionally requires the deferred evidence artifacts *and*
at least one CI run by a real runner, which has not happened.

Milestone 1 (characterize v0 and define the v0 → v1 migration boundary) is in progress and
**not** complete. Of its required artifacts, the reproducible local chaos commands and a
reconciliation report exist, and the defect register above is a first pass at one required
input. Still missing —

- a v0 architecture and data-flow snapshot;
- the retain/harden/replace/delete migration matrix;
- the provider qualification report with dated raw observations;
- the minimal real-GPU run report;
- linking every register entry above to the numbered v1 milestone that closes it;
- an ADR defining the cutover strategy and when v0 code may be deleted.
