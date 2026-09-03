---
name: milestone
description: Run one roadmap milestone subtask under the working contract in AGENTS.md, against the canonical docs/firmbatch-v1-roadmap.md. Takes a milestone number and subtask name. User-triggered only.
disable-model-invocation: true
---

# Roadmap milestone subtask

Arguments: `$ARGUMENTS` — a milestone number and a subtask name, e.g. `2 postgres-spine`.

The working contract in `AGENTS.md` defines this process. This skill executes it; it does
not invent a different one.

## 1 · Inspect before proposing

Read, in this order, before writing anything:

- `docs/firmbatch-v1-roadmap.md` — **the canonical implementation sequence**. Read the
  named milestone and its completion gate.
- `docs/architecture/v1-target-architecture.md` — **the implementation specification**.
  Read §17 (non-negotiable implementation invariants) first: those are the acceptance
  criteria carried into every milestone. Then read the sections the subtask touches.
- `docs/STATE.md` — the one state document: CURRENT, PLANNED, VERIFIED LIVE, HISTORICAL,
  NOT VERIFIED, and the v0 defect register;
- `docs/tasks/current.md` — what is already queued or blocked;
- `docs/adr/` — decisions already taken;
- `docs/architecture/v0-to-v1-migration-audit.md` — the retain/harden/replace/delete
  destination for any v0 component the subtask touches;
- the code and tests the subtask touches.

`docs/firmbatch-pilot-roadmap.md` is superseded historical context. Do not take milestone
numbering, sequencing, or acceptance criteria from it.

## 2 · State the gap

Before proposing work, state in plain terms:

- what the repository does **today**, from reading it — not from documentation;
- the exact gap between that and the subtask's acceptance criteria;
- which §17 invariants the subtask touches.

If the roadmap and the code disagree, the code is the fact and the disagreement is a
finding. Record it.

## 3 · Propose a bounded plan, then stop

Propose the smallest ordered set of changes that ends in a reviewable, tested repository
state. Name any work that belongs to a later milestone and is being pulled in as a
prerequisite. **Wait for approval before editing.** Editing a protected file
(`AGENTS.md`, `CLAUDE.md`, `.agents/policy/`, `.claude/settings.json`, `.codex/hooks.json`,
`scripts/verify-repository.sh`, `.github/workflows/`, `.agents/skills/`, `.claude/agents/`)
needs that approval to be explicit and specific to the file.

## 4 · Implement

- Preserve every §17 invariant. If a change appears to require breaking one, stop and say so.
- Build beside frozen v0 (ADR 0003). Do not evolve v0 tables or endpoints in place.
- Add or update tests for normal behaviour, duplicated delivery, stale ownership, partial
  failure, and tenant isolation wherever those apply.
- Do not implement later-milestone work opportunistically.
- Do not refactor or reformat v0 code you are not otherwise changing.

## 5 · Verify and report

Run `/verify` (which runs `./scripts/verify-repository.sh`). Then close with the report:

- files changed;
- decisions made;
- tests and results;
- remaining risks;
- whether this subtask's acceptance criteria are met;
- what remains before the milestone is complete.

Capture evidence with `/record-evidence` for anything you are calling VERIFIED. Passing
tests establish implemented and tested behaviour; they are not VERIFIED LIVE, which needs
a captured artifact under `docs/evidence/`.

## 6 · Update durable state

Update `docs/STATE.md` (CURRENT / PLANNED / VERIFIED LIVE / HISTORICAL / NOT VERIFIED) and
`docs/tasks/current.md`. There is one state document — never add a second.
Write an ADR under `docs/adr/` for any decision a future reader would otherwise have to
reverse-engineer.

A milestone is complete only when its **entire** completion gate passes with saved
evidence. Partial completion is reported as partial.
