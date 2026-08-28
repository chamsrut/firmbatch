# ADR 0001 — Agentic repository operating model

- **Status:** Accepted
- **Date:** 2026-08-28
- **Commit at decision:** `d0aeee2`, branch `repo-init/agentic-foundation`

## Context

Firmbatch v0 is a ~1,400-line prototype that the v1 roadmap intends to characterize and largely
replace. (It is described as ~900 lines in `README.md`; that figure was never counted.) The roadmap (§7) already specifies how it wants to be executed with GPT-5.6 and
Claude: inspect first, state the gap, propose a bounded plan, preserve the §5 invariants,
close with a structured report, and mark a milestone complete only when its gate passes with
saved evidence.

Two agents work in this repository — Claude Code and Codex. Before this pass there was no
`CLAUDE.md`, no `AGENTS.md`, no durable state document, and no mechanical enforcement of any
of it. The roadmap's discipline lived only in a document neither agent was obliged to read.

Two specific risks motivated the mechanical part:

1. **Evidence drift.** The repository's value rests on captured evidence. The commit
   `Correct v0 baseline evidence and record interrupted job` shows an artifact already being
   corrected in place. An agent that edits an evidence file destroys the record of what
   actually happened.
2. **Irreversible and billable actions.** `fb run --provider verda` launches spot instances
   billed in pre-paid 10-minute increments; `--max-workers` is the only ceiling. Destructive
   git and filesystem operations are similarly one-way.

## Decision

### 1 · `AGENTS.md` is canonical; `CLAUDE.md` imports it

Shared instructions live in `AGENTS.md`. `CLAUDE.md` is `@AGENTS.md` plus the Claude-only
surfaces (skills, subagents, the hook, plan mode). Codex reads `AGENTS.md` directly. A rule
has one home.

### 2 · Skills have one body, symlinked

Canonical bodies live in `.agents/skills/<name>/SKILL.md`. `.claude/skills/<name>` is a
relative symlink to the canonical directory. Duplicated skill bodies drift; symlinks cannot.

Three skills: `verify` (runs `scripts/verify-repository.sh`), `record-evidence` (capture an
artifact with the standard provenance header), `milestone` (execute a roadmap subtask under
§7, user-triggered only).

### 2b · One verification entry point

`scripts/verify-repository.sh` is the only place the gates are spelled out. The human, the
`verify` skill, and `.github/workflows/ci.yml` all invoke that same file. The alternative --
CI re-listing the commands a skill also lists -- guarantees the two drift, and the drift is
invisible until a gate has quietly stopped running.

### 3 · One policy engine, two adapters

`.agents/policy/guard.py` is a single stdlib-only decision function with three entry points:
`--adapter claude`, `--adapter codex`, and `--check` for tests and manual use. Each adapter
parses that agent's actual stdin schema and emits that agent's blocking response — Claude
gets a `permissionDecision: deny` at exit 0; Codex gets `{"decision":"block"}` plus exit 2
and the reason on stderr.

Rules are shared. Adding one changes both agents; there is no second copy to keep in sync.

Deny classes: evidence immutability, evidence deletion, destructive git (including commit,
push, and merge — the human commits), destructive filesystem operations, credential files
and protected config trees, cloud mutations, and billable provider launches.

**It is a guardrail, not a boundary.** The guard exists to stop an aligned agent from
reaching an irreversible action by accident. It is not a sandbox and not a security control,
and it does not resist an agent that is deliberately working around it. Interpreters
(`python3 -c`, `perl -e`, `awk`), `sudo`, `xargs`, `busybox`, subshells, command
substitution, `eval`, and here-documents are outside its guarantee by decision: closing them
would buy an argument at this layer that cannot be won there, at the cost of implying it had
been. The rules in `AGENTS.md` are the boundary; the hook is their cheapest enforcement, and
a silent allow is not permission.

**It does not lock its own configuration.** An agent that cannot edit the guard also cannot
fix it, and a self-locking guard makes a boundary claim this design does not make. Human
approval before changing `AGENTS.md`, `CLAUDE.md`, `.agents/policy/`, `.claude/settings.json`,
or `.codex/hooks.json` is an `AGENTS.md` instruction, deliberately not a hook rule.

Four properties are deliberate:

- **Bash is covered as well as the file tools.** `echo x > docs/evidence/f.txt` would route
  straight around a file-path-only guard, so redirection targets, `tee`, `sed -i`, `cp`,
  `mv`, and `rm` arguments are all checked.
- **Wrapper shells are re-parsed.** `bash -lc '<command>'` hides an entire command inside one
  token. The parser re-enters on the payload, to a depth of four; exhausting that depth denies
  rather than falling through. This was found by the synthetic tests, not by review — the
  first implementation had the bypass.
- **`cd` is followed.** `AGENTS.md` requires every command to run from the parent directory,
  which makes a stale resolution base the likeliest way an agent reaches a protected path by
  accident. `cd X && rm y` resolves `y` against `X`. The R0 audit found that the one existing
  test covering `cd` had passed only because the guard ignored it — the test encoded the bug.
- **Paths are resolved before comparison,** collapsing `..` and symlinks, and it fails closed:
  malformed JSON, a missing tool name, an empty command, or a write payload with no path all
  block, with a reason.

Allow is expressed on the Claude side by staying silent, so the guard is additive to the
normal permission flow rather than a blanket pre-approval.

### 4 · Three read-only reviewers, defined for both agents

`distributed-systems-reviewer`, `test-evidence-reviewer`, `security-operations-reviewer` —
`.claude/agents/*.md` and `.codex/agents/*.toml`. Read-only in **declaration**, not only in prose — but a declaration is not an
observation; see the open item in `docs/STATE.md` on whether either harness enforces it: `tools: Read, Grep, Glob` on Claude (Bash was removed during R0 -- it is not a
read-only tool and made "read-only" an instruction rather than a constraint), `read_only = true`
on Codex. They report, they never fix.
Their bodies are the one place duplication was accepted, because the two formats differ
structurally (YAML frontmatter + Markdown vs. TOML with an `instructions` string). They are
reviewed as a pair when changed.

### 5 · Durable state lives in the repository

`docs/STATE.md` is **the** state document -- CURRENT / PLANNED / VERIFIED LIVE / HISTORICAL /
NOT VERIFIED. The roadmap was amended to reference it by name rather than a second
`docs/current-state.md`, which never existed. Alongside it: `docs/tasks/current.md` (active
work and open questions), `docs/adr/` (decisions). Both agents read them at the start of a task and
update them at the end. This is what makes a handoff between agents — or between sessions —
survive a context window.

### 6 · Lint is a gate, not a rewrite

`pyproject.toml` carries ruff configuration and no packaging table: the repository is run as
`python3 -m firmbatch.fb` from its parent directory, and a `[project]` table would invite an
install that breaks that import path. `line-length = 140` accommodates the longest existing
line (136). `ruff format` is disabled and `--fix` is never used. Lint runs at explicit
verification, not after every edit.

## Consequences

**Accepted:**

- The parent-directory import requirement is enforced in one place --
  `scripts/verify-repository.sh`, which resolves its own root and runs the property tests from
  the parent -- and explained in `AGENTS.md`, because it silently breaks CI.
- The guard will occasionally block something legitimate. The cost of a false block is a
  sentence to the human; the cost of a false allow is a destroyed evidence record or a bill.
- Two reviewer definitions per role must be kept in step by hand.

**Covered by synthetic tests** (241 checks in `.agents/policy/test_guard.py`, all passing; no
destructive command is executed): both adapter protocols, each deny class in the spellings
named there, wrapper-shell smuggling and depth exhaustion, path traversal into the evidence
tree, `cd`-relative resolution, and fail-closed behaviour on malformed input and on an
unexpected exception in the engine itself.

This is coverage of the accident paths, not proof of a boundary. The R0 acceptance audit
found that the first implementation's tests pinned the *implemented parse* rather than the
invariant, which is why `git -C . push` passed review and then passed tests while remaining
allowed. Tests added since assert the invariant — "no push reaches the shell" — and the
classes listed as outside the guarantee above are outside it deliberately and remain so.

**Not verified, and not claimed:** that the guard resists a deliberate bypass. It does not.

**Not verified — recorded as open in `docs/tasks/current.md`:**

- `.codex/hooks.json` and `.codex/agents/*.toml` are project-scoped Codex locations, and the
  adapter contract they invoke is tested. Codex *loading* them in a live session has not been
  observed. Until it is, the Codex-side enforcement is declared, not proven.
- ~~Whether Claude Code's skill loader follows the `.claude/skills/` symlinks at session start.~~
  **Resolved by the R0 audit:** it does. `verify` and `record-evidence` appear in the session
  skill listing; `milestone` is absent only because it sets `disable-model-invocation: true`.

**Resolved after the decision was drafted:** ruff reported 21 findings, all in pre-existing
v0 code. Rather than weaken the rule set globally or rewrite v0, they were frozen as narrowly
scoped `per-file-ignores` for `fb.py`, `demo/make_requests.py`, and `tests/test_recovery.py`,
documented in `pyproject.toml` as frozen v0 exceptions rather than conventions for new code.
No source file was modified. With all three gates then passing locally,
`.github/workflows/ci.yml` was written: it checks out into a directory named `firmbatch`, runs
the property tests from the parent, and pins ruff to 0.16.5. No CI run has been observed.
