---
name: milestone
description: Run one roadmap milestone subtask under the working contract in docs/firmbatch-pilot-roadmap.md §7. Takes a milestone number and subtask name. User-triggered only.
disable-model-invocation: true
---

# Roadmap milestone subtask

Arguments: `$ARGUMENTS` — a milestone number and a subtask name, e.g. `1 v0-inventory`.

The roadmap defines its own contract for this work in §7. This skill executes it; it does
not invent a different process.

## 1 · Inspect before proposing

Read, in this order, before writing anything:

- `docs/firmbatch-pilot-roadmap.md` — the named milestone, plus §5 (non-negotiable
  invariants) and §4 (service contract vocabulary);
- `docs/STATE.md` — the one state document: CURRENT, PLANNED, VERIFIED LIVE, HISTORICAL,
  NOT VERIFIED, and the v0 defect register;
- `docs/tasks/current.md` — what is already queued or blocked;
- `docs/adr/` — decisions already taken;
- the code and tests the subtask touches.

## 2 · State the gap

Before proposing work, state in plain terms:

- what the repository does **today**, from reading it — not from documentation;
- the exact gap between that and the subtask's acceptance criteria;
- which of the §5 invariants the subtask touches.

If the roadmap and the code disagree, the code is the fact and the disagreement is a
finding. Record it.

## 3 · Propose a bounded plan, then stop

Propose the smallest ordered set of changes that ends in a reviewable, tested repository
state. Name any work that belongs to a later milestone and is being pulled in as a
prerequisite. Wait for approval before editing.

## 4 · Implement

- Preserve every §5 invariant. If a change appears to require breaking one, stop and say so.
- Add or update tests for normal behaviour, duplicated delivery, stale ownership, partial
  failure, and tenant isolation wherever those apply.
- Do not implement later-milestone work opportunistically.
- Do not refactor or reformat v0 code you are not otherwise changing.

## 5 · Verify and report

Run `/verify` (which runs `./scripts/verify-repository.sh`). Then close with the §7 report:

- files changed;
- decisions made;
- tests and results;
- remaining risks;
- whether this subtask's acceptance criteria are met;
- what remains before the milestone is complete.

Capture evidence with `/record-evidence` for anything you are calling VERIFIED.

## 6 · Update durable state

Update `docs/STATE.md` (CURRENT / PLANNED / VERIFIED LIVE / HISTORICAL / NOT VERIFIED) and
`docs/tasks/current.md`. There is one state document — never add a second.
Write an ADR under `docs/adr/` for any decision a future reader would otherwise have to
reverse-engineer.

A milestone is complete only when its **entire** completion gate passes with saved
evidence. Partial completion is reported as partial.
