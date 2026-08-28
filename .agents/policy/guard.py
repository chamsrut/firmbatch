#!/usr/bin/env python3
"""Shared deterministic policy engine for Firmbatch agent tooling.

One decision function, three entry points:

    guard.py --adapter claude    Claude Code PreToolUse hook   (stdin JSON -> permissionDecision)
    guard.py --adapter codex     Codex PreToolUse hook         (stdin JSON -> block decision)
    guard.py --check --tool Bash --command "..."               internal API, used by the tests

Both agents share this file. A rule added here takes effect for both; there is no
second copy to keep in sync.

WHAT THIS IS, AND WHAT IT IS NOT
===============================

This is an accident-prevention guardrail for an *aligned* agent. It is not a sandbox
and not a security boundary. It stops an agent that is trying to do the right thing
from reaching an irreversible one by accident -- a `git push` typed on reflex, an
`rm -rf docs`, a `--prov verda` that spends money. It does not, and cannot, stop an
agent that is deliberately trying to get around it.

Concretely OUTSIDE the guarantee, by decision rather than oversight:

  * interpreters -- `python3 -c`, `perl -e`, `node -e`, `awk` programs;
  * `sudo`, `xargs`, `busybox`, and arbitrary shell-program composition;
  * subshells, command substitution, `eval`, and here-documents that build a
    command at runtime;
  * anything a process it allows goes on to do.

A rule here is worth adding when it closes a path an aligned agent plausibly takes
by accident. It is not worth adding to win an argument against an adversary; that
argument cannot be won at this layer, and pretending otherwise is the actual risk.
See AGENTS.md, "The guardrail and its limits".

Design notes that matter:

  * Bash is covered as well as Write/Edit, because `echo x > docs/evidence/f.txt`
    would otherwise route straight around a file-path-only guard.
  * Read/Grep/Glob are covered too, or a credential file reaches the transcript
    through the file tools while only its shell spelling is blocked.
  * Each LINE of a multi-line block is tokenized separately. `shlex` treats a newline
    as whitespace, so a whole block would otherwise collapse into one segment and be
    classified by its first command word alone -- the ordinary two-line bash block was
    the single largest hole the second audit found.
  * `cd`, `cd -`, `pushd`, and `popd` are all followed, because AGENTS.md requires every
    command to run from the PARENT directory, which makes a stale base the likeliest
    accident here. After `||` the preceding `cd` is assumed NOT to have run.
  * Grouping punctuation is stripped, so one leading paren cannot make a plainly
    visible `rm` unclassifiable.
  * A glob operand is resolved to its parent directory, so `rm -rf docs/*` and
    `rm -rf *` are caught by the same ancestor rule as `rm -rf docs`.
  * `gh` and `aws` scan adjacent non-flag pairs rather than indexing a position, so a
    global option (`gh -R o/r`, `aws --region x`) cannot shift the verb out of view --
    the same bug as `git -C`, which is why all three are written the same way.
  * Paths are resolved (`..` and symlinks collapsed) before any comparison, so
    `docs/../docs/evidence/x` and a symlink into the evidence tree are caught.
  * Unparseable input, exhausted wrapper nesting, and an unexpected exception in the
    engine itself all fail CLOSED with a reason.
  * Evidence immutability means *existing* files only, and extends to ancestors of
    the tree: `rm -rf docs` takes the record with it. Capturing a NEW artifact is the
    intended workflow and stays allowed.
  * The guard does NOT lock its own configuration. An agent that cannot edit the
    guard cannot fix it. Human approval for those files is an AGENTS.md rule.
"""

import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_DIR = REPO_ROOT / "docs" / "evidence"

# Writes into these trees are never allowed: they hold agent and cloud credentials
# and configuration that no repository task needs to change.
PROTECTED_HOME_DIRS = (".claude", ".codex", ".aws", ".ssh", ".gnupg")

# Files that hold real secrets. Templates are exempted separately.
CREDENTIAL_NAMES = frozenset({
    ".env", ".netrc", ".pgpass", "auth.json", "credentials", "id_rsa", "id_dsa",
    "id_ecdsa", "id_ed25519", "secrets.json", "service-account.json",
})
CREDENTIAL_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")

# Commands that read file contents; used to catch credential exfiltration.
READERS = frozenset({"cat", "bat", "less", "more", "head", "tail", "strings", "xxd", "od", "base64", "nl"})

# Trivial "run this command" wrappers. Stripped so the real command word is found.
# Deliberately NOT including sudo, xargs, busybox, or interpreters -- see the
# "Outside the guardrail" note in AGENTS.md.
PREFIX_COMMANDS = frozenset({"env", "nohup", "timeout", "nice", "stdbuf", "command", "ionice"})
# `timeout 5m`, `timeout 30s`, `timeout 1.5h` -- a duration is a wrapper value, not a command.
DURATION_RE = re.compile(r"^\d+(\.\d+)?[smhd]?$")

# Commands that replace a file in place, destroying the original.
INPLACE_MUTATORS = frozenset({"gzip", "gunzip", "bzip2", "bunzip2", "xz", "unxz", "zstd", "compress"})

# `git <opt> <value> <subcommand>` -- these consume the following token, which would
# otherwise be mistaken for the subcommand.
GIT_VALUE_OPTS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"})

GIT_DENIED = {
    "commit": "commits are the human's call in this repository",
    "push": "pushing is the human's call in this repository",
    "merge": "merging is the human's call in this repository",
    "rebase": "history rewriting is not an agent action",
    "filter-branch": "history rewriting is not an agent action",
    "cherry-pick": "history rewriting is not an agent action",
}

# `gh` reaches the same outward-facing effects as git, over the API rather than the
# remote. Keyed on "<noun> <verb>" where a verb alone is ambiguous.
GH_DENIED = {
    ("pr", "merge"): "merging a pull request is the human's call",
    ("pr", "create"): "opening a pull request is an outward-facing action",
    ("pr", "close"): "closing a pull request is an outward-facing action",
    ("pr", "edit"): "editing a pull request is an outward-facing action",
    ("release", "create"): "publishing a release is an outward-facing action",
    ("release", "delete"): "deleting a release is irreversible",
    ("repo", "delete"): "deleting a repository is irreversible",
    ("repo", "create"): "creating a repository is an outward-facing action",
    ("issue", "create"): "opening an issue is an outward-facing action",
    ("issue", "close"): "closing an issue is an outward-facing action",
    ("pr", "comment"): "commenting on a pull request is an outward-facing action",
    ("pr", "review"): "reviewing a pull request is an outward-facing action",
    ("pr", "reopen"): "reopening a pull request is an outward-facing action",
    ("pr", "ready"): "marking a pull request ready is an outward-facing action",
    ("issue", "comment"): "commenting on an issue is an outward-facing action",
    ("workflow", "run"): "triggering a workflow run is an outward-facing action",
    ("repo", "fork"): "forking a repository is an outward-facing action",
    ("gist", "create"): "publishing a gist is an outward-facing action",
    ("secret", "set"): "writing a secret to GitHub is never an agent action",
    ("secret", "delete"): "deleting a GitHub secret is irreversible",
}
GH_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

AWS_MUTATING_PREFIXES = (
    "delete", "terminate", "create", "put", "update", "modify", "remove", "run-instances",
    "stop", "start", "reboot", "attach", "detach", "associate", "disassociate", "register",
    "deregister", "import", "restore", "invalidate", "cancel", "purchase", "release",
)


class Decision:
    """Result of a policy evaluation."""

    def __init__(self, allowed, rule="", reason=""):
        self.allowed = allowed
        self.rule = rule
        self.reason = reason

    def __repr__(self):
        return f"Decision(allowed={self.allowed}, rule={self.rule!r})"


ALLOW = Decision(True)


def deny(rule, reason):
    return Decision(False, rule, reason)


# --------------------------------------------------------------------------- paths


def resolve(raw, cwd=None):
    """Resolve a path argument to an absolute, symlink-free, `..`-free path.

    Works for paths that do not exist yet: only the existing prefix is followed.
    """
    if raw is None:
        return None
    text = str(raw).strip().strip("'\"")
    if not text:
        return None
    base = Path(cwd) if cwd else REPO_ROOT
    p = Path(os.path.expanduser(text))
    if not p.is_absolute():
        p = base / p
    return Path(os.path.realpath(str(p)))


def under(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def is_credential_path(path):
    name = path.name
    if name.endswith(CREDENTIAL_TEMPLATE_SUFFIXES):
        return False
    if name in CREDENTIAL_NAMES:
        return True
    # .env.local, .env.production, .env.verda ... scripts/verify-repository.sh already
    # treats the whole family as credentials; the two must not disagree.
    if name.startswith(".env."):
        return True
    home = Path(os.path.realpath(os.path.expanduser("~")))
    return any(under(path, home / d) for d in (".aws", ".ssh", ".gnupg"))


def is_protected_config_path(path):
    home = Path(os.path.realpath(os.path.expanduser("~")))
    return any(under(path, home / d) for d in PROTECTED_HOME_DIRS)


# --------------------------------------------------------------------------- file rules


GLOB_CHARS = ("*", "?", "[")


def is_evidence_ancestor(path):
    """True if deleting this path recursively would take the evidence tree with it.

    A glob operand is never expanded by this parser -- the shell does that. So the
    effective target of `rm -rf docs/*` is the DIRECTORY `docs`, and of `rm -rf *` the
    working directory itself. Comparing the literal `docs/*` would miss both.
    """
    if any(ch in path.name for ch in GLOB_CHARS):
        path = path.parent
    return under(EVIDENCE_DIR, path)


def check_write(path, cwd=None, deleting=False, recursive=False):
    """Policy for creating, modifying, or deleting one file."""
    p = resolve(path, cwd)
    if p is None:
        return deny("malformed-path", "empty or unparseable file path; failing closed")

    if recursive and deleting and is_evidence_ancestor(p):
        return deny(
            "evidence-immutable",
            f"{p} contains the captured evidence tree ({EVIDENCE_DIR}). A recursive delete here "
            "destroys the record of runs that happened; evidence is corrected by capturing a new "
            "artifact, never by removing the old one.",
        )

    if under(p, EVIDENCE_DIR):
        if deleting:
            return deny(
                "evidence-immutable",
                f"{p} is captured evidence and may not be deleted. Evidence records a run that happened; "
                "correct it by capturing a new artifact, not by removing the old one.",
            )
        if p.exists():
            return deny(
                "evidence-immutable",
                f"{p} already exists. Captured evidence is immutable — re-capture into a new file "
                "with /record-evidence instead of editing this one.",
            )
        return ALLOW

    if is_credential_path(p):
        return deny("credential-file", f"{p} holds credentials. Use the .example template instead.")

    if is_protected_config_path(p):
        return deny("protected-config", f"{p} is agent or cloud configuration outside this repository's scope.")

    return ALLOW


def check_read(path, cwd=None):
    p = resolve(path, cwd)
    if p is None:
        return ALLOW
    if is_credential_path(p):
        return deny("credential-read", f"{p} holds credentials and must not be read into a transcript.")
    return ALLOW


# --------------------------------------------------------------------------- bash rules

SEPARATORS = frozenset({";", "&&", "||", "|", "&"})
REDIRECTS = frozenset({">", ">>", "1>", "2>", "&>", ">|", "1>>", "2>>", "&>>"})
# Grouping punctuation. Stripped before classification so that one leading paren cannot
# turn a plainly visible `rm docs/evidence/...` into an unrecognised command word.
GROUPING = frozenset({"(", ")", "{", "}"})


def split_segments(tokens):
    """Split a token stream into (separator_before, segment) pairs.

    The separator matters: a segment after `||` runs only if the previous one FAILED,
    so a preceding `cd` cannot be assumed to have taken effect.
    """
    segments, current, sep = [], [], ""
    for tok in tokens:
        if tok in SEPARATORS:
            if current:
                segments.append((sep, current))
            current, sep = [], tok
        else:
            current.append(tok)
    if current:
        segments.append((sep, current))
    return segments


def logical_lines(text):
    """Split a command block into lines, rejoining backslash continuations.

    `shlex` treats a newline as whitespace, so a multi-line block tokenizes into ONE
    stream and every command after the first becomes an argument of the first. Splitting
    here first is what makes each line get classified on its own.
    """
    return str(text).replace("\\\n", " ").split("\n")


def strip_env_assignments(argv):
    """Drop leading `VAR=value` prefixes so the real command word is found."""
    i = 0
    while i < len(argv) and "=" in argv[i] and not argv[i].startswith("-") and "/" not in argv[i].split("=")[0]:
        i += 1
    return argv[i:]


def redirect_targets(argv):
    """File paths this segment writes to via shell redirection."""
    targets = []
    for i, tok in enumerate(argv):
        if tok in REDIRECTS and i + 1 < len(argv):
            targets.append(argv[i + 1])
        elif len(tok) > 1 and tok[0] == ">" and tok != ">>":
            targets.append(tok.lstrip(">|"))
    return [t for t in targets if t and not t.startswith("/dev/")]


SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "fish"})


def strip_command_prefixes(argv):
    """Drop `env`, `timeout 60`, `nice -n 5`, ... so the real command word is found.

    Returns (argv, exhausted). Exhausting the bound must DENY rather than fall through,
    for the same reason wrapper-shell nesting does: a stack of prefixes deep enough to
    run out the parser is a command this engine cannot claim to have inspected.
    """
    for _ in range(4):
        argv = strip_env_assignments(argv)
        if not argv or Path(argv[0]).name not in PREFIX_COMMANDS:
            return argv, False
        rest = argv[1:]
        i = 0
        # Skip the wrapper's own options and their values: `-n 5`, `-oL`, `60`, `5m`,
        # `30s`, and `env -u NAME`. A duration suffix or an option's NAME value used to
        # stop the scan and leave the wrapper itself as the command word.
        while i < len(rest):
            tok = rest[i]
            if tok.startswith("-"):
                # These options take a separate value; consume it too.
                if tok in ("-u", "-n", "-S", "--unset", "--adjustment") and i + 1 < len(rest):
                    i += 2
                    continue
                i += 1
                continue
            if DURATION_RE.match(tok):
                i += 1
                continue
            break
        argv = rest[i:]
    return argv, True


def git_subcommand(args):
    """The real subcommand, with global options and their values consumed."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in GIT_VALUE_OPTS:
            i += 2
            continue
        if a.startswith("--") and "=" in a and a.split("=", 1)[0] in GIT_VALUE_OPTS:
            i += 1
            continue
        if a.startswith("-"):
            i += 1
            continue
        return a
    return ""


def positional_operands(args):
    """Positional arguments, with `-t DIR` / `--target-directory=DIR` pulled in."""
    operands, i = [], 0
    while i < len(args):
        a = args[i]
        if a in ("-t", "--target-directory") and i + 1 < len(args):
            operands.append(args[i + 1])
            i += 2
            continue
        if a.startswith("--target-directory="):
            operands.append(a.split("=", 1)[1])
            i += 1
            continue
        if a.startswith("-"):
            i += 1
            continue
        operands.append(a)
        i += 1
    return operands


def check_bash_segment(argv, cwd, depth=0):
    argv = [a for a in argv if a not in REDIRECTS]
    argv = strip_env_assignments(argv)
    argv, prefixes_exhausted = strip_command_prefixes(argv)
    if prefixes_exhausted:
        return deny(
            "wrapper-depth",
            "this command is wrapped in more command prefixes than the guard will unwrap. "
            "Run the command directly instead of through stacked wrappers.",
        )
    if not argv:
        return ALLOW

    cmd = Path(argv[0]).name
    args = argv[1:]
    words = set(args)

    # `bash -lc "..."` hides a whole command inside one token. Re-enter the parser on
    # the payload, or every rule below can be stepped around with one wrapper.
    if cmd in SHELLS:
        for i, a in enumerate(args):
            # Match the real `-c` or a combined SHORT option containing it (`-lc`).
            # A letter-membership test over any option matched `--norc` and recursed on
            # the wrong token, leaving the payload uninspected.
            is_c_flag = a.startswith("-") and not a.startswith("--") and "c" in a[1:]
            if is_c_flag and i + 1 < len(args):
                if depth >= 4:
                    return deny(
                        "wrapper-depth",
                        "wrapper shells are nested deeper than this guard will parse. "
                        "Run the command directly instead of through nested shells.",
                    )
                return check_bash(args[i + 1], cwd, depth=depth + 1)

    # Any argument naming a credential file is refused before the command-specific
    # rules, except where a later rule produces a more precise verdict.
    if cmd not in ("git", "rm", "rmdir", "shred", "unlink", "truncate", "cp", "mv", "install", "rsync", "tee", "ln"):
        for a in args:
            # `curl -d @.env` and `--data=@.env` both name the file after a sigil.
            candidate = a.split("=", 1)[1] if (a.startswith("-") and "=" in a) else a
            for probe in (candidate, candidate.lstrip("@")):
                if not probe or probe.startswith("-"):
                    continue
                d = check_read(probe, cwd)
                if not d.allowed:
                    return d

    # gh and aws both take global options BEFORE the noun/verb (`gh -R o/r pr merge`,
    # `aws --region x ec2 terminate-instances`). Indexing the first non-flag token
    # reproduces exactly the `git -C` bug this guard was hardened to fix, so both scan
    # every ADJACENT pair of non-flag tokens instead of trusting a position.
    if cmd == "gh":
        nouns = [a for a in args if not a.startswith("-")]
        for noun, verb in zip(nouns, nouns[1:]):
            if (noun, verb) in GH_DENIED:
                return deny("git-destructive", f"`gh {noun} {verb}` is blocked: {GH_DENIED[(noun, verb)]}.")
        if "api" in nouns:
            for i, a in enumerate(args):
                if a in ("-X", "--method") and i + 1 < len(args) and args[i + 1].upper() in GH_WRITE_METHODS:
                    return deny("git-destructive", f"`gh api -X {args[i + 1]}` writes through the GitHub API.")
                if a.startswith("--method=") and a.split("=", 1)[1].upper() in GH_WRITE_METHODS:
                    return deny("git-destructive", f"`gh api {a}` writes through the GitHub API.")
                # gh implies POST as soon as a field is supplied.
                if a in ("-f", "--field", "-F", "--raw-field") or a.startswith(("-f=", "--field=", "--raw-field=")):
                    return deny("git-destructive", "`gh api` with a field implies a write request.")
        return ALLOW

    if cmd == "git":
        sub = git_subcommand(args)
        if sub in GIT_DENIED:
            return deny("git-destructive", f"`git {sub}` is blocked: {GIT_DENIED[sub]}.")
        if sub == "reset" and ("--hard" in words or "--merge" in words):
            return deny("git-destructive", "`git reset --hard` discards working-tree state irreversibly.")
        if sub == "clean" and any(a.startswith("-") and ("f" in a or "d" in a) for a in args):
            return deny("git-destructive", "`git clean -f/-d` deletes untracked files irreversibly.")
        if sub in ("checkout", "restore") and ("." in words or "--" in words):
            return deny("git-destructive", f"`git {sub}` over a path set discards uncommitted work.")
        # `git restore <file>` and `git checkout <existing file>` throw away uncommitted
        # edits just as irreversibly as `reset --hard`, which is already denied.
        if sub in ("checkout", "restore"):
            for a in [x for x in args if not x.startswith("-") and x != sub]:
                if sub == "restore":
                    return deny("git-destructive", f"`git restore {a}` discards uncommitted changes to it.")
                p = resolve(a, cwd)
                if p is not None and p.is_file():
                    return deny("git-destructive", f"`git checkout {a}` discards uncommitted changes to that file.")
        if sub == "branch" and "-D" in words:
            return deny("git-destructive", "`git branch -D` force-deletes a branch.")
        if sub == "tag" and "-d" in words:
            return deny("git-destructive", "`git tag -d` deletes a tag.")
        if sub == "reflog" and "expire" in words:
            return deny("git-destructive", "`git reflog expire` destroys the recovery log.")
        if sub == "gc" and any(a.startswith("--prune") for a in args):
            return deny("git-destructive", "`git gc --prune` destroys unreferenced recovery objects.")
        if sub == "remote" and "set-url" in words:
            return deny("git-destructive", "`git remote set-url` repoints the remote.")
        if sub == "rm":
            for a in args:
                if not a.startswith("-") and a != "rm":
                    d = check_write(a, cwd, deleting=True)
                    if not d.allowed:
                        return d
        if sub == "add":
            for a in args:
                if not a.startswith("-") and a != "add":
                    p = resolve(a, cwd)
                    if p is not None and is_credential_path(p):
                        return deny("credential-file", f"refusing to stage {p}: it holds credentials.")
        return ALLOW

    if cmd in ("rm", "rmdir", "shred", "unlink"):
        recursive = any(x.startswith("-") and ("r" in x.lower() or "f" in x) for x in args)
        for a in args:
            if a.startswith("-"):
                continue
            # The catastrophic roots are reported as fs-destructive, before the
            # narrower evidence rule that would also match them.
            p = resolve(a, cwd)
            if recursive and p is not None and p in (REPO_ROOT, Path(os.path.realpath(os.path.expanduser("~"))), Path("/")):
                return deny("fs-destructive", f"recursive delete of {p} is never a repository task.")
            d = check_write(a, cwd, deleting=True, recursive=recursive)
            if not d.allowed:
                return d
        return ALLOW

    if cmd == "truncate":
        for a in args:
            if not a.startswith("-"):
                d = check_write(a, cwd, deleting=True)
                if not d.allowed:
                    return d
        return ALLOW

    if cmd in ("chmod", "chown", "chgrp") and any(a in ("-R", "--recursive") for a in args):
        return deny("fs-destructive", f"recursive `{cmd}` rewrites permissions across a tree.")

    if cmd == "find" and ("-delete" in words or "-exec" in words or "-execdir" in words):
        return deny("fs-destructive", "`find -delete`/`-exec` is an unbounded destructive operation.")

    if cmd == "dd" and any(a.startswith("of=") for a in args):
        return deny("fs-destructive", "`dd of=` writes raw blocks over a destination.")

    if cmd.startswith("mkfs"):
        return deny("fs-destructive", "filesystem creation is never a repository task.")

    if cmd == "aws":
        nouns = [a for a in args if not a.startswith("-")]
        for service, action in zip(nouns, nouns[1:]):
            if action.startswith(AWS_MUTATING_PREFIXES):
                return deny("cloud-mutation", f"`aws {service} {action}` changes cloud state and must be run by a human.")
            # The s3 high-level verbs are short words no prefix list would catch.
            if service == "s3" and action in ("rm", "mv", "rb", "sync"):
                return deny("cloud-mutation", f"`aws s3 {action}` can delete or overwrite objects; a human runs it.")
        if "s3" in nouns and "--delete" in words:
            return deny("cloud-mutation", "`aws s3 ... --delete` removes objects at the destination.")
        return ALLOW

    if cmd == "terraform":
        sub = next((a for a in args if not a.startswith("-")), "")
        if sub in ("apply", "destroy", "import", "taint", "untaint"):
            return deny("cloud-mutation", f"`terraform {sub}` changes infrastructure and must be run by a human.")
        if sub == "state" and any(a in ("rm", "mv", "push") for a in args):
            return deny("cloud-mutation", "`terraform state` mutation must be run by a human.")
        return ALLOW

    if cmd == "sed" and any(
        a == "-i" or a == "--in-place" or a.startswith("--in-place=") or (a.startswith("-i") and not a.startswith("--"))
        for a in args if a.startswith("-")
    ):
        for a in args:
            if not a.startswith("-") and ("/" in a or a.endswith((".py", ".md", ".txt", ".json"))):
                d = check_write(a, cwd)
                if not d.allowed:
                    return d
        return ALLOW

    # In-place archivers replace their input: the original file ceases to exist.
    if cmd in INPLACE_MUTATORS:
        for a in positional_operands(args):
            d = check_write(a, cwd, deleting=True)
            if not d.allowed:
                return d
        return ALLOW

    # Every operand is checked, in both the source and the destination role. `mv` and
    # `rsync --remove-source-files` destroy their source; `cp -t DIR` and `ln -sf` put
    # the destination somewhere other than the last position.
    if cmd in ("cp", "mv", "install", "rsync", "ln"):
        # `mv docs /tmp/old` walks the whole evidence tree out of the repository, and
        # `rsync --delete` empties the destination. Both are ancestor-destroying even
        # though neither is an `rm`, so they carry recursive=True into check_write.
        removes_source = cmd == "mv" or (cmd == "rsync" and "--remove-source-files" in words)
        destroys_tree = removes_source or (cmd == "rsync" and "--delete" in words)
        for a in positional_operands(args):
            d = check_write(a, cwd, deleting=destroys_tree, recursive=destroys_tree)
            if not d.allowed:
                return d
        return ALLOW

    if cmd == "tee":
        for a in args:
            if not a.startswith("-"):
                d = check_write(a, cwd)
                if not d.allowed:
                    return d
        return ALLOW

    if cmd in READERS:
        for a in args:
            if not a.startswith("-"):
                d = check_read(a, cwd)
                if not d.allowed:
                    return d
        return ALLOW

    # Billable provider launches stay a deliberate human action.
    #
    # argparse abbreviates, so `--prov verda` selects verda just as `--provider` does.
    # Any prefix of `--provider` is therefore treated as the flag, and the launch is
    # allowed only when the value is PROVABLY local -- a value this parser cannot
    # resolve (a variable, a substitution) is billable until shown otherwise.
    joined = " ".join(argv)
    launches = ("firmbatch.fb" in joined or cmd == "fb" or cmd.endswith("fb.py"))
    if launches and "run" in words:
        for value in provider_values(args):
            if value != "local":
                shown = value or "<unset>"
                return deny(
                    "billable-launch",
                    f"`fb run` with provider {shown} may launch billable spot instances. "
                    "A provider launch is a deliberate human-run action; only a provably "
                    "local provider runs unattended.",
                )
    return ALLOW


def provider_values(args):
    """Values given to `--provider` or any argparse abbreviation of it."""
    values = []
    for i, a in enumerate(args):
        flag, inline = (a.split("=", 1) + [None])[:2] if "=" in a else (a, None)
        if not (flag.startswith("--p") and "--provider".startswith(flag)):
            continue
        if inline is not None:
            values.append(inline)
        elif i + 1 < len(args) and not args[i + 1].startswith("-"):
            values.append(args[i + 1])
        else:
            values.append("")
    return values


class DirState:
    """The shell's working directory as this parser understands it.

    Tracks `cd`, `cd -`, `pushd`, and `popd`. Adding `pushd` without `popd` is worse
    than tracking neither: the parser then believes the shell is somewhere it has
    already left, and a protected path stops resolving as protected.
    """

    def __init__(self, cwd):
        # Normalise up front: `cd -` and `popd` need a concrete previous directory, and
        # a None here silently turns both back into no-ops.
        start = str(cwd) if cwd else str(REPO_ROOT)
        self.current = start
        self.previous = start        # for `cd -`
        self.stack = []              # for pushd/popd

    def apply(self, argv):
        argv = strip_env_assignments([a for a in argv if a not in REDIRECTS and a not in GROUPING])
        if not argv:
            return
        cmd = Path(argv[0]).name
        if cmd not in ("cd", "pushd", "popd"):
            return
        operands = [a for a in argv[1:] if not a.startswith("-")]
        dash = any(a == "-" for a in argv[1:])

        if cmd == "popd":
            if self.stack:
                self.previous, self.current = self.current, self.stack.pop()
            return
        if cmd == "pushd":
            self.stack.append(self.current)
        target = None
        if dash and not operands:
            target = self.previous          # `cd -`
        elif operands:
            target = operands[0]
        else:
            target = os.path.expanduser("~")
        resolved = resolve(target, self.current)
        if resolved is not None:
            self.previous, self.current = self.current, str(resolved)


def check_bash(command, cwd=None, depth=0):
    if command is None or not str(command).strip():
        return deny("malformed-input", "empty Bash command; failing closed")

    # `cd X && rm y` changes what `y` means. AGENTS.md requires every command to run
    # from the PARENT directory, so a repository-relative path after a `cd` is the
    # single most likely way an agent reaches a protected path by accident.
    dirs = DirState(cwd)
    for line in logical_lines(command):
        if not line.strip():
            continue
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError as exc:
            # An unparseable command is not a runnable command. Failing closed here costs
            # the human one sentence; failing open cost the R0 audit a live `git push`.
            return deny("malformed-input", f"could not parse this command ({exc}); failing closed")

        for sep, segment in split_segments(tokens):
            # After `||` the previous segment FAILED, so a `cd` in it did not take
            # effect. Fall back to where the shell was before that `cd`.
            base = dirs.previous if sep == "||" else dirs.current
            segment = [t for t in segment if t not in GROUPING]
            if not segment:
                continue
            for target in redirect_targets(segment):
                d = check_write(target, base)
                if not d.allowed:
                    return d
            d = check_bash_segment(segment, base, depth=depth)
            if not d.allowed:
                return d
            dirs.apply(segment)
    return ALLOW


# --------------------------------------------------------------------------- dispatch

WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch", "edit", "write"})
BASH_TOOLS = frozenset({"Bash", "bash", "shell", "run_shell", "local_shell"})
# Read surfaces. Without these a credential file reaches the transcript through the
# file tools while the Bash rules block only the shell spelling of the same act.
READ_TOOLS = frozenset({"Read", "Grep", "Glob", "read", "grep", "glob"})


def decide(tool, path=None, command=None, cwd=None, patch=None):
    """Single policy entry point shared by every adapter."""
    if not tool:
        return deny("malformed-input", "hook payload named no tool; failing closed")
    if tool in BASH_TOOLS:
        return check_bash(command, cwd)
    if tool in WRITE_TOOLS:
        if patch:
            return check_patch(patch, cwd)
        if path is None:
            return deny("malformed-input", f"{tool} payload carried no file path; failing closed")
        return check_write(path, cwd)
    if tool in READ_TOOLS:
        return check_read(path, cwd) if path is not None else ALLOW
    # An unknown tool name that still carries a command or a patch is a tool this
    # engine has never classified. Codex's real tool names are an assumption (see
    # docs/tasks/current.md), so allowing an unrecognised name to pass with a payload
    # would fail OPEN precisely where the schema is least certain.
    if command or patch:
        return deny(
            "malformed-input",
            f"tool {tool!r} is not one this guard classifies, but it carries a command or "
            "patch; failing closed rather than passing an uninspected payload.",
        )
    return ALLOW


def check_patch(patch, cwd=None):
    """Evaluate a Codex apply_patch envelope, one target file at a time."""
    for line in str(patch).splitlines():
        stripped = line.strip()
        for marker, deleting in (("*** Delete File:", True), ("*** Update File:", False), ("*** Add File:", False)):
            if stripped.startswith(marker):
                target = stripped[len(marker):].strip()
                d = check_write(target, cwd, deleting=deleting)
                if not d.allowed:
                    return d
    return ALLOW


# --------------------------------------------------------------------------- adapters


def _first(mapping, *keys):
    for k in keys:
        if isinstance(mapping, dict) and mapping.get(k) not in (None, ""):
            return mapping[k]
    return None


def adapter_claude(raw):
    """Claude Code PreToolUse: stdin JSON in, permissionDecision JSON out.

    Allow is expressed by staying silent so the normal permission flow still runs;
    only a denial is emitted, which is what makes this guard additive rather than
    a blanket pre-approval.
    """
    try:
        event = json.loads(raw)
    except (ValueError, TypeError) as exc:
        return _claude_deny(f"guard could not parse the hook payload ({exc}); failing closed"), 0
    if not isinstance(event, dict):
        return _claude_deny("guard received a non-object hook payload; failing closed"), 0

    tool = event.get("tool_name")
    tool_input = event.get("tool_input") or {}
    cwd = event.get("cwd") or str(REPO_ROOT)
    path = _first(tool_input, "file_path", "notebook_path", "path", "pattern")
    command = _first(tool_input, "command")
    # Grep/Glob narrow with `glob`, which names files just as `path` does.
    extra = _first(tool_input, "glob")

    # Any unexpected exception must arrive as a denial. Without this the process exits
    # non-zero with empty stdout, which Claude Code reads as a non-blocking hook error
    # and the tool call proceeds -- the guard would fail OPEN on its own bug.
    try:
        d = decide(tool, path=path, command=command, cwd=cwd)
        if d.allowed and extra is not None and tool in READ_TOOLS:
            d = check_read(extra, cwd)
    except Exception as exc:  # noqa: BLE001 -- deliberately broad; see above
        return _claude_deny(f"[guard-error] the policy engine raised {type(exc).__name__}: {exc}; failing closed"), 0
    if d.allowed:
        return "", 0
    return _claude_deny(f"[{d.rule}] {d.reason}"), 0


def _claude_deny(reason):
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    })


def adapter_codex(raw):
    """Codex PreToolUse: stdin JSON in, block decision out plus a non-zero exit.

    Codex payload key names are accepted as a superset so the guard blocks rather
    than silently passing if the field layout differs from what was assumed.
    """
    try:
        event = json.loads(raw)
    except (ValueError, TypeError) as exc:
        return _codex_deny(f"guard could not parse the hook payload ({exc}); failing closed"), 2
    if not isinstance(event, dict):
        return _codex_deny("guard received a non-object hook payload; failing closed"), 2

    tool = _first(event, "tool_name", "tool", "name")
    tool_input = _first(event, "tool_input", "input", "arguments", "params") or {}
    if not isinstance(tool_input, dict):
        tool_input = {"command": tool_input}
    cwd = _first(event, "cwd", "working_directory") or str(REPO_ROOT)
    path = _first(tool_input, "file_path", "path", "filename", "file")
    command = _first(tool_input, "command", "cmd", "script")
    patch = _first(tool_input, "patch", "input", "diff")

    if isinstance(command, list):
        command = " ".join(shlex.quote(str(c)) for c in command)

    try:
        d = decide(tool, path=path, command=command, cwd=cwd, patch=patch)
    except Exception as exc:  # noqa: BLE001 -- deliberately broad; a guard bug must block
        return _codex_deny(f"[guard-error] the policy engine raised {type(exc).__name__}: {exc}; failing closed"), 2
    if d.allowed:
        return json.dumps({"decision": "allow"}), 0
    return _codex_deny(f"[{d.rule}] {d.reason}"), 2


def _codex_deny(reason):
    return json.dumps({"decision": "block", "reason": reason})


# --------------------------------------------------------------------------- cli


def main(argv=None):
    ap = argparse.ArgumentParser(description="Firmbatch shared agent policy engine")
    ap.add_argument("--adapter", choices=("claude", "codex"), help="read a hook payload for this agent on stdin")
    ap.add_argument("--check", action="store_true", help="evaluate one action from flags and print the verdict")
    ap.add_argument("--tool", help="tool name, e.g. Bash, Write, Edit, apply_patch")
    ap.add_argument("--path", help="file path, for write tools")
    ap.add_argument("--command", help="command string, for Bash")
    ap.add_argument("--patch", help="apply_patch envelope")
    ap.add_argument("--cwd", help="working directory the action runs in")
    a = ap.parse_args(argv)

    if a.adapter:
        raw = sys.stdin.read()
        handler = adapter_claude if a.adapter == "claude" else adapter_codex
        out, code = handler(raw)
        if out:
            sys.stdout.write(out)
            if code:
                sys.stderr.write(json.loads(out).get("reason", "") + "\n")
        return code

    if a.check:
        d = decide(a.tool, path=a.path, command=a.command, cwd=a.cwd, patch=a.patch)
        print(f"{'ALLOW' if d.allowed else 'DENY'}  {d.rule}  {d.reason}".rstrip())
        return 0 if d.allowed else 1

    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
