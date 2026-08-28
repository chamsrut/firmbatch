# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this
repository.

The instructions below are shared with Codex and are canonical. Read them first.

@AGENTS.md

## Claude-specific surfaces

Everything above applies unchanged. These are the Claude-only entry points to it.

**Skills** (`.claude/skills/<name>` are symlinks to the canonical bodies in
`.agents/skills/<name>` — there is no second copy, so edit the file the link points at):

- `/verify` — runs `./scripts/verify-repository.sh`, the one verification entry point. Run
  before reporting any change complete. `--chaos` is a separate, explicit, destructive
  experiment.
- `/record-evidence` — capture a run into a new `docs/evidence/<phase>/` artifact with the
  standard provenance header.
- `/milestone <N> <subtask>` — run a roadmap subtask under the §7 contract. User-triggered
  only, via `disable-model-invocation`, so it will not appear in the model-facing skill list.

**Reviewers** (`.claude/agents/`, all genuinely read-only — `tools: Read, Grep, Glob`, no
Bash — dispatch with the Task tool):

- `distributed-systems-reviewer` — leases, ownership, idempotency, completion accounting.
  Use after changes under `control/`, `controller.py`, `worker/`, `providers/`, `fb.py`.
- `test-evidence-reviewer` — whether claims are actually backed by captured evidence.
  Use before marking work complete or a milestone gate satisfied.
- `security-operations-reviewer` — credentials, tenant isolation, provider data boundary,
  policy-engine bypasses, unbounded spend. Use after changes under `providers/`,
  `worker/agent.py`, `control/app.py`, `controller.py`, `fb.py`, `.agents/policy/`.

**Policy hook** — `.claude/settings.json` registers `.agents/policy/guard.py --adapter claude`
as a blocking `PreToolUse` hook over `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Bash`,
`Read`, `Grep`, and `Glob`. A denial arrives as a `permissionDecision: deny` with the rule
name and reason.

It is an accident-prevention guardrail for an aligned agent — **not a sandbox and not a
security boundary**; see "The guardrail and its limits" in AGENTS.md for what sits outside
its guarantee. Treat a block as the answer, not an obstacle, and treat a silent allow as
nothing more than the absence of a block: the boundaries in AGENTS.md bind either way.
Changing `AGENTS.md`, `CLAUDE.md`, `.agents/policy/`, `.claude/settings.json`, or
`.codex/hooks.json` requires the human's explicit approval first.

**Plan mode** — the working contract's "propose a bounded plan before editing" maps onto plan
mode. Use it for milestone subtasks rather than describing a plan in prose and then editing
anyway.
