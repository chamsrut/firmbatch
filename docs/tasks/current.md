# Current tasks

Active work and open questions. Updated at the end of each task, alongside `docs/STATE.md`.

Last updated: 2026-08-28, commit `d0aeee2` plus the uncommitted R0 working tree, branch
`repo-init/agentic-foundation`.

---

## Immediate — the R0 commit

The R0 files are **untracked**. Evidence must not be captured until they are committed:
an artifact captured now would carry `commit=d0aeee2`, which does not contain them, and a
provenance header that describes the wrong tree is worse than no header.

Order:

1. Human reviews and commits the R0 working tree.
2. `/record-evidence` → `docs/evidence/r0/gates.txt` (the full
   `scripts/verify-repository.sh` output) and `docs/evidence/r0/policy-tests.txt`.
3. Move the two rows in `docs/STATE.md` "Asserted — artifact pending" into VERIFIED LIVE,
   citing those artifacts.
4. Push, so CI runs for the first time (see item 3 below).

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
before the fix. `.agents/policy/test_guard.py` is at **241 checks**.

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
Twelve gates. `AGENTS.md`, the `verify` skill, and `.github/workflows/ci.yml` all invoke it.

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

### 7 · CI — rewritten, still unrun

`.github/workflows/ci.yml` now calls the verification script instead of duplicating its
commands, adds `permissions: contents: read`, and no longer installs
`requirements-v0-lock.txt` — none of the gates need it (all three are stdlib-only plus ruff),
so it was a failure surface with no coverage benefit, and the lock is incomplete anyway
(`anyio` needs `sniffio`, unpinned).

The fragile part is unchanged and deliberate: `tests/test_recovery.py` does
`from firmbatch.control import db`, so the workflow checks out with `path: firmbatch` and the
script runs the property tests from the **parent** directory. Do not "simplify" it.

**Not yet observed: an actual CI run.** Nothing has been pushed. CI is NOT VERIFIED.

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

## Open — roadmap Milestone 1

Milestone 1 is **not** complete. Missing required artifacts are listed at the end of
`docs/STATE.md`. The most load-bearing:

### 11 · Reproduce the real preemption path

The v0 baseline claimed three SIGKILLed workers; no artifact shows one. The corrected
`--chaos` procedure in the `verify` skill now isolates the port, waits for readiness, traps
cleanup, and says explicitly that **stdout must be captured**, because the kill is visible
nowhere else. Run it with `--chaos-after` past the scale-down window so the preemption path,
not scale-down, reclaims the shards, and assert `no_heartbeat` appears.

### 12 · A failing test for D1 (stale-worker settlement)

Claim a shard with `lease_secs=1`, `reap()`, re-claim as a second worker, then POST
`/w/results` with `done: true` as the first worker. Assert the shard is not `done` and the
second worker's remaining requests are still issuable. This test does not exist and would
fail today — see the defect register in `docs/STATE.md`.

### 13 · Retain / harden / replace / delete matrix

Every v0 component needs an explicit disposition before the milestone gate can pass. The
component inventory and defect register in `docs/STATE.md` are the starting point.

### 14 · Make the reconciliation report reproducible

`local-demo-001-reconciliation.json` satisfies a Milestone 1 required artifact, but no script
in the repository generates it and the database it derives from is gitignored. Commit the
script or the exact query set.
