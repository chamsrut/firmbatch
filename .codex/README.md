# Codex configuration for firmbatch

Codex and Claude Code share one set of instructions and one policy engine. Nothing in this
directory holds its own copy of a rule.

| Concern | Canonical location | How Codex reaches it |
| --- | --- | --- |
| Instructions | `AGENTS.md` (repository root) | read directly |
| Skills | `.agents/skills/<name>/SKILL.md` | read directly |
| Policy engine | `.agents/policy/guard.py` | `hooks.json` → `--adapter codex` |
| Reviewers | `.codex/agents/*.toml` | this directory |

## Policy hook

`hooks.json` registers a **synchronous, blocking** `PreToolUse` hook over `shell`,
`local_shell`, `apply_patch`, `Edit`, and `Write`. It invokes the same engine Claude uses:

```bash
/usr/bin/python3 "$(git rev-parse --show-toplevel)/.agents/policy/guard.py" --adapter codex
```

The guard is resolved through `git rev-parse --show-toplevel` rather than a relative path,
so the hook works from any directory **inside** the work tree instead of only from its
root. The interpreter is the absolute system `python3` on purpose: `guard.py` is
stdlib-only, and a blocking hook must not depend on which environment is activated.

**This is not equivalent to `$CLAUDE_PROJECT_DIR`, and it has a known limit.** That
variable is harness-supplied and genuinely cwd-independent; a command substitution is a
function of the working directory. From *outside* any work tree, `git rev-parse` fails,
the substitution is empty, the command becomes `/usr/bin/python3 "/.agents/policy/guard.py"`,
and every action is blocked with empty stdout and no explanation — the same silent
block-everything symptom the relative path had, just in a narrower set of cases. The
reachable one is `/home/chams/src`, the parent directory `AGENTS.md` tells every command
to run from, which is not itself a repository. If a Codex session ever behaves as though
everything is denied, check this first. Two further assumptions are untested: that Codex
evaluates the hook command through a shell at all (if it `exec`s the string, `$(...)` stays
literal and the same symptom appears), and that `/usr/bin/python3` exists on the host.

The adapter reads the hook payload as JSON on stdin and responds:

- allowed → `{"decision": "allow"}` on stdout, exit **0**
- blocked → `{"decision": "block", "reason": "[rule] explanation"}` on stdout, the reason
  on stderr, exit **2**

It fails closed: unparseable JSON, a missing tool name, an empty command, or a write payload
with no path all block. Field names are accepted as a superset (`tool_name`/`tool`/`name`,
`tool_input`/`input`/`arguments`/`params`, `command`/`cmd`/`script`, `file_path`/`path`/`file`),
and a `command` given as an argv list is re-joined and re-parsed — so a payload-shape
mismatch blocks rather than silently passing.

Verify the wiring by hand at any time:

```bash
echo '{"tool_name":"shell","input":{"command":"git push --force"}}' \
  | /usr/bin/python3 "$(git rev-parse --show-toplevel)/.agents/policy/guard.py" \
      --adapter codex; echo "exit=$?"
```

Expect a `block` decision and `exit=2`.

## What this is, and what it is not

The guard is an **accident-prevention guardrail for an aligned agent — not a sandbox and not
a security boundary.** It stops an agent that is trying to do the right thing from reaching
an irreversible one by reflex. It cannot stop an agent deliberately working around it, and it
is not designed to try. The rules in `AGENTS.md` are the actual boundary; the hook is their
cheapest enforcement. A silent allow is not permission.

## What the guard catches

Evidence immutability (existing files under `docs/evidence/`, and any recursive delete of a
directory containing the tree, through the file tools, shell redirection, `rm`, `mv`, `cp`,
`ln`, `install`, `rsync`, `gzip`/`xz`, and `sed -i`), destructive git (commit, push, merge,
rebase, hard reset, clean -f, branch -D, reflog expire, and `restore`/`checkout` over a
path) including behind `git -C` and `git -c`, the `gh` equivalents (`pr merge|create|
comment|review`, `release create`, `repo delete`, `secret set`, `workflow run`, and
`api` with a write method or a field),
destructive filesystem operations, credential files, writes into `~/.claude`, `~/.codex`,
`~/.aws`, `~/.ssh`, cloud mutations
(`aws` mutating verbs, `terraform apply|destroy|state rm`), and billable provider launches —
including argparse abbreviations such as `fb run --prov verda`, since only a *provably* local
provider is allowed to run unattended.

Each line of a multi-line block is classified on its own — a newline separates commands,
and `shlex` would otherwise fold the whole block into one segment classified by its first
command word. `cd`, `cd -`, `pushd`, and `popd` are followed when resolving later paths,
because `AGENTS.md` requires every command to run from the parent directory; after `||`
the preceding `cd` is assumed not to have run. Grouping parens are stripped before
classification. A glob operand resolves to its parent, so `rm -rf docs/*` and `rm -rf *`
hit the same ancestor rule as `rm -rf docs`.

Wrapper shells are re-parsed to a depth of four, and stacked command prefixes to the same
depth; exhausting **either** denies rather than falling through. Unparseable input and an
unexpected exception inside the engine both deny. An unrecognised tool name that still
carries a command or a patch denies, because Codex's real tool names are an assumption
until a live session confirms them.

## A gap specific to this side

The Claude matcher covers `Read`, `Grep`, and `Glob` as well as the write and shell tools,
so a credential file cannot reach the transcript through a file read. **The Codex matcher
here covers only `shell`, `local_shell`, `apply_patch`, `Edit`, and `Write`**, so on this
side credential protection applies to shell spellings only. `guard.py` already classifies
lowercase `read`/`grep`/`glob` (`READ_TOOLS`), so closing this is a matcher change — but it
needs Codex's real read-tool names, which are unobserved. Until then, a Codex file-read of
`.env` reaches the transcript without touching the guard.

## What is outside the guarantee

By decision, not oversight: interpreters (`python3 -c`, `perl -e`, `awk` programs), `sudo`,
`xargs`, `busybox`, subshells, command substitution, `eval`, here-documents, and anything a
process it allowed goes on to do. Adding rules for these would buy an argument against an
adversary that cannot be won at this layer, at the cost of pretending it had been.

The guard also does **not** lock its own configuration — an agent that cannot edit the guard
cannot fix it. Changing `AGENTS.md`, `CLAUDE.md`, `.agents/policy/`, `.claude/settings.json`,
or `.codex/hooks.json` requires the human's explicit approval, which is an `AGENTS.md` rule
rather than a hook rule.

Rules live in `.agents/policy/guard.py` and are covered by `.agents/policy/test_guard.py`.
Change them there — never by adding a second copy here.

## Runtime discovery status

`.codex/hooks.json` and `.codex/agents/*.toml` are project-scoped Codex locations. Both
adapter protocols are covered by synthetic tests that exercise the full stdin/stdout/exit-code
contract. Those tests pass when run, but **no artifact records it yet** — evidence capture is
deferred until the R0 files are committed, since an artifact captured now would cite a commit
that does not contain them. What has **not** been observed at all is Codex loading these files
at runtime in a live session. See `docs/adr/0001-agentic-repository-operating-model.md` and the
open item in `docs/tasks/current.md`.
