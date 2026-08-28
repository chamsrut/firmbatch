# AGENTS.md

Canonical instructions for any agent working in this repository. Claude Code reads this
through `CLAUDE.md`; Codex reads it directly. Tool-specific surfaces are the only thing that
lives elsewhere — a rule belongs here.

## What this repository is

A persistent batch job that survives its machines. The customer buys one durable obligation:
this quantity of accepted output, by this deadline, for this price. Underneath, machines are
rented, used, killed and replaced. That property is the entire product.

`README.md` explains the system and how to run it. `docs/firmbatch-pilot-roadmap.md` is the
plan from the v0 prototype to a pilot-ready v1, and is authoritative over the README where
they differ.

## Running anything

`firmbatch` is imported as a **package** (`from firmbatch.control import db`). Every command
runs from the repository's **parent** directory, and the repository directory must be named
`firmbatch`:

```bash
cd "$(git rev-parse --show-toplevel)/.."   # the PARENT of the repo
python3 -m firmbatch.fb serve
python3 -m firmbatch.tests.test_recovery
```

Running from inside the repository fails on the import. There is no `pytest` suite and no
`Makefile`; `tests/test_recovery.py` is a script that prints PASS/FAIL and exits non-zero on
failure. Conda environment: `firmbatch-v0` (Python 3.11).

## Verifying anything

One command, run from anywhere:

```bash
./scripts/verify-repository.sh
```

It resolves its own repository root and runs each gate from the directory that gate needs —
layout, agent configuration, repository hygiene, property tests, `ruff check`, and the agent
policy tests. It prints PASS/FAIL per gate, runs them all even after one fails, and exits
non-zero if any did.

**This script is the only verification entry point.** The human, the `verify` skill, and
`.github/workflows/ci.yml` all invoke this same file, so all three provably run the same
gates. Do not re-spell its commands by hand and do not duplicate them into CI: a gate that
exists in only one of the three places is a gate that quietly stops being true. Add checks
to the script.

## Working contract

From roadmap §7. Apply it to every non-trivial task.

1. **Inspect first.** Read the roadmap section, `docs/STATE.md`, `docs/tasks/current.md`,
   `docs/adr/`, and the code the task touches — before proposing anything.
2. **State the current behaviour and the exact gap**, from reading the code, not the
   documentation. Where the two disagree, the code is the fact and the disagreement is a
   finding worth recording.
3. **Propose a bounded plan before editing**, and wait for approval. The smallest ordered set
   of changes that ends in a reviewable, tested repository state.
4. **Preserve every invariant** in roadmap §5. If a change appears to require breaking one,
   stop and say so rather than working around it.
5. **Do not implement later-milestone work** opportunistically. If a prerequisite must be
   pulled forward, name it explicitly.
6. **Close with the report**: files changed; decisions made; tests and results; remaining
   risks; whether the acceptance criteria are met; what remains.

Use the `verify`, `record-evidence`, and `milestone` skills — they carry the detail.

## Evidence

No new behaviour may be labelled **VERIFIED** unless you either:

- **(a)** ran it and saved reproducible output under `docs/evidence/<phase>/` with the
  standard `captured_at` / `database` / `python` / `commit` / `uname` header, or
- **(b)** cite existing captured evidence.

Evidence from an older commit is **HISTORICAL** unless you confirm the relevant code is
unchanged since. Documentation, comments, and expected behaviour are not evidence.

Existing artifacts under `docs/evidence/` are immutable. Correct a wrong artifact by
capturing a new one and explaining the correction in `docs/STATE.md` — never by rewriting
the old record. The policy engine blocks the ordinary ways of reaching one (the file tools,
shell redirection, `rm`, `mv`, `cp`, `ln`, `gzip`, `sed -i`, and a recursive delete of any
directory containing the tree), but see "The guardrail and its limits" below: the rule is
the instruction, and the hook is only its cheapest enforcement.

**The v0 artifacts predate this standard.** Five of the six files under `docs/evidence/v0/`
carry no provenance header, because they were captured before the header was defined. They
are HISTORICAL evidence and are cited as such — they are not invalid, and they are not to be
rewritten to add a header, which would fabricate provenance. Everything captured from R0
onward carries the full header.

Roadmap Milestone 1 is explicit that no v0 result may be presented as pilot-ready customer
proof. A local echo-engine chaos run is diagnostic evidence about durability under process
kill — nothing more.

## Boundaries

- **Never commit, push, or merge.** Stage if asked; the human commits.
- **Never launch billable capacity.** `fb run --provider verda` starts spot instances.
  A provider launch is a deliberate human-run action.
- **Never modify historical evidence** under `docs/evidence/`.
- **Never touch `.env`**, or any credential file. `.env.example` is the template.
- **Never mass-format or refactor v0.** Its terse style (compact imports, semicolon-joined
  argparse, short files) is deliberate and the code is on its way out under the roadmap. Lint
  applies to code you wrote or modified; a finding in untouched v0 code gets reported to the
  human, never auto-fixed. `ruff check --fix` and `ruff format` are not used here.
- **Never change product behaviour** while doing repository or tooling work.

### Ask before changing the agent configuration

These files decide how every later session behaves. Propose the change and **wait for the
human's explicit approval** before editing any of them:

- `AGENTS.md` or `CLAUDE.md`;
- anything under `.agents/policy/`;
- `.claude/settings.json`;
- `.codex/hooks.json`;
- `scripts/verify-repository.sh` — deleting a gate, appending `|| true`, or trimming
  `REQUIRED_FILES` silently weakens every later verification;
- `.github/workflows/` — the same gates, on the CI side;
- `.agents/skills/` and `.claude/agents/` — these define how work and review are done.

This is deliberately an instruction rather than a hook rule. An agent that cannot edit the
guard also cannot fix it, and a guard that locks its own configuration is making a boundary
claim this design does not make. The check is you.

### The guardrail and its limits

`.agents/policy/guard.py` runs as a blocking pre-tool hook for both agents. It is an
**accident-prevention guardrail for an aligned agent — not a sandbox, and not a security
boundary.** It exists to stop an agent that is trying to do the right thing from reaching an
irreversible one by reflex: a `git push`, an `rm -rf docs`, a `--prov verda` that spends
money. It cannot stop an agent that is deliberately working around it, and it is not designed
to try.

Outside its guarantee, by decision rather than oversight: interpreters (`python3 -c`,
`perl -e`, `awk` programs), `sudo`, `xargs`, `busybox`, subshells, command substitution,
`eval`, here-documents, and anything a process it allowed goes on to do. Do not read a
silent allow as permission — the boundaries above are the rule, and they bind whether or not
the hook happens to catch a given spelling.

One cost worth knowing: a command the shell lexer cannot parse is denied outright, so a
heredoc or a quoting shape it chokes on gets blocked even when it is harmless. Write it
to a script file and run that. This is the intended trade — an unparseable command is a
command the guard cannot claim to have inspected.

If the guard blocks you, it is telling you the rule. Do not look for a way around it; say so
to the human instead. A false block costs one sentence. A false allow costs a destroyed
evidence record or a bill.

## Git

Commit subjects are short, imperative, one line, no body, no trailers — matching the existing
history (`Record first v0 local chaos baseline`). Work happens on a topic branch;
`repo-init/agentic-foundation` is the current one. You do not commit.

## Layout of the agent tooling

| Path | Purpose |
| --- | --- |
| `AGENTS.md` | this file — canonical for both agents |
| `CLAUDE.md` | imports this file, plus Claude-only surfaces |
| `.agents/skills/` | canonical skill bodies, shared |
| `.agents/policy/guard.py` | the one policy engine, both agents |
| `.claude/skills/` | symlinks to `.agents/skills/` — no second copy |
| `.claude/agents/`, `.codex/agents/` | the three read-only reviewers |
| `scripts/verify-repository.sh` | the one verification entry point — human, agent, and CI |
| `docs/STATE.md` | CURRENT / PLANNED / VERIFIED LIVE — **the** state document |
| `docs/tasks/current.md` | active work and open questions |
| `docs/adr/` | decisions a future reader would otherwise reverse-engineer |
