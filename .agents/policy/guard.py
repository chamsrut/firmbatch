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
  * Options are parsed by each program's own grammar, never guessed by shape: a
    wrapper's long option is resolved as GNU getopt_long does, by unique prefix
    (`env --ch=DIR`, `timeout --sig KILL`), and an ambiguous prefix is refused; a
    `gh api` short-flag cluster is read letter by letter (`-if` is `-i -f`), with
    a value flag's value never scanned as a flag.
  * `find` and `tree` stay readers, but their write options (`find -fprint`,
    `-fprint0`, `-fprintf`, `-fls`; `tree -o`/`--output`) route the file they
    write through the same write rule as a redirect, and `find -ok`/`-okdir`
    run commands just as `-exec` does.
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
#
# Each wrapper's own grammar: the short options that take a value (`-s KILL`, or attached as
# `-sKILL`), the long options that take one (`--signal KILL`, `--signal=KILL`), every long option
# that takes none, and how many positional operands the wrapper itself consumes before the command
# -- timeout's DURATION. A generic "skip anything that looks like an option" parse left
# `timeout -s KILL 5 terraform apply` classified as the command `KILL`. The flag-only long options
# are listed because getopt_long accepts any UNIQUE prefix of a long option: whether `--ch` is
# `--chdir` depends on every option the program knows, not only on the ones that take a value.
WRAPPER_GRAMMARS = {
    "env": (
        frozenset({"-u", "-C", "-S", "-a"}),
        frozenset({"--unset", "--chdir", "--split-string", "--argv0"}),
        frozenset({
            "--ignore-environment", "--null", "--block-signal", "--default-signal", "--ignore-signal",
            "--list-signal-handling", "--debug", "--help", "--version",
        }),
        0,
    ),
    "timeout": (
        frozenset({"-s", "-k"}),
        frozenset({"--signal", "--kill-after"}),
        frozenset({"--foreground", "--preserve-status", "--verbose", "--help", "--version"}),
        1,
    ),
    "nice": (frozenset({"-n"}), frozenset({"--adjustment"}), frozenset({"--help", "--version"}), 0),
    "stdbuf": (frozenset({"-i", "-o", "-e"}), frozenset({"--input", "--output", "--error"}), frozenset({"--help", "--version"}), 0),
    "ionice": (
        frozenset({"-c", "-n", "-p", "-P", "-u"}),
        frozenset({"--class", "--classdata", "--pid", "--pgid", "--uid"}),
        frozenset({"--ignore", "--help", "--version"}),
        0,
    ),
    "time": (
        frozenset({"-f", "-o"}),
        frozenset({"--format", "--output"}),
        frozenset({"--portability", "--append", "--verbose", "--quiet", "--help", "--version"}),
        0,
    ),
    "exec": (frozenset({"-a"}), frozenset(), frozenset(), 0),
    "nohup": (frozenset(), frozenset(), frozenset(), 0),
    "command": (frozenset(), frozenset(), frozenset(), 0),
}
PREFIX_COMMANDS = frozenset(WRAPPER_GRAMMARS)

# Every spelling of the tools the Terraform and AWS rules restrict. OpenTofu is Terraform for this
# purpose, and `aws2` is the AWS CLI v2's alternative name.
TERRAFORM_PROGRAMS = frozenset({"terraform", "tofu", "opentofu"})
AWS_PROGRAMS = frozenset({"aws", "aws2"})


def program_name(token):
    """The command word as a rule compares it: the last path component, `.exe` removed, lowercased.

    `terraform.exe`, `C:\\tools\\aws.exe` and `/usr/bin/Terraform` all name the tool their rule
    restricts. Lowercasing can only over-match, which costs a false block, never a false allow.
    """
    name = re.split(r"[\\/]", str(token))[-1].lower()
    return name[:-4] if name.endswith(".exe") else name

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
    ("variable", "set"): "writing a GitHub Actions variable changes what a deployment workflow does",
    ("variable", "delete"): "deleting a GitHub Actions variable changes what a deployment workflow does",
    ("run", "rerun"): "re-running a workflow run is an outward-facing action",
    ("workflow", "enable"): "enabling a workflow is an outward-facing action",
}
GH_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# `gh api`'s own value-taking options besides the method and body ones: a short flag's value is the
# rest of its token or the next token, and a long option's value is the next token -- neither is a flag.
GH_API_SHORT_VALUES = frozenset("Hpqt")
GH_API_LONG_VALUES = frozenset({"--header", "--preview", "--jq", "--template", "--hostname", "--cache"})

AWS_MUTATING_PREFIXES = (
    "delete", "terminate", "create", "put", "update", "modify", "remove", "run-instances",
    "stop", "start", "reboot", "attach", "detach", "associate", "disassociate", "register",
    "deregister", "import", "restore", "invalidate", "cancel", "purchase", "release",
)

# Milestone 3.3b (ADR 0012): agents make NO AWS API call -- not a mutating one, and not a
# read-only one either, because a read prints account state, secrets or identity data into a
# transcript. Only commands that never reach AWS pass. A narrowly scoped set may be authorized
# in M3.3d, once the account, role, region and operation are explicitly confirmed.
AWS_LOCAL_ONLY_FLAGS = frozenset({"--version"})

# Terraform subcommands an agent may run: formatting, validation, version and provider
# locking, and `init` only with the backend disabled. `test` runs only through
# infra/terraform/scripts/static-checks.sh, which proves every test file mocks every provider
# before running it. Everything else either changes infrastructure or state or reads state.
TERRAFORM_ALLOWED = frozenset({"fmt", "validate", "version", "providers", "init", "help"})
TERRAFORM_MUTATING = frozenset({
    "plan", "apply", "destroy", "import", "refresh", "taint", "untaint", "force-unlock",
})

# Container registries: an image is never logged in for, or pushed, by an agent.
REGISTRY_CLIENTS = frozenset({"docker", "podman", "buildah", "nerdctl", "finch"})
REGISTRY_VERBS = frozenset({"push", "login", "imagetools"})
REGISTRY_TOOLS = frozenset({"skopeo", "crane", "oras"})
REGISTRY_TOOL_WRITES = frozenset({
    "copy", "cp", "push", "login", "sync", "tag", "delete", "attach", "mutate", "append", "rebase", "flatten", "manifest",
})

# Commands that only read. Any other command naming a path inside the M3.3 staging evidence
# directory -- touch, curl -o, tar -C, unzip -d, git mv -- is refused.
EVIDENCE_READ_ONLY_COMMANDS = READERS | frozenset({"ls", "stat", "grep", "rg", "wc", "file", "test", "diff", "tree", "du", "find"})

# M3.3 AWS staging and deployment evidence is captured only by an authorized M3.3d
# deployment (ADR 0012). Every other evidence location is unaffected.
DEPLOYMENT_EVIDENCE_DIR = EVIDENCE_DIR / "m3" / "aws-staging"


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

    if under(p, DEPLOYMENT_EVIDENCE_DIR) and not deleting:
        return deny(
            "deployment-evidence-deferred",
            f"{p} is M3.3 AWS staging or deployment evidence, which is unavailable until an explicitly "
            "authorized M3.3d deployment captures it (ADR 0012). Evidence for other milestones is unaffected.",
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


def resolve_long_option(name, flag, long_values, long_flags):
    """The long option `flag` names, as getopt_long resolves it: an exact name, or the one option
    it is a unique prefix of. None for an option the wrapper does not know. An ambiguous prefix
    raises ValueError: the program itself refuses it, and guessing either reading could shift the
    command word and fail open."""
    known = long_values | long_flags
    if flag in known:
        return flag
    candidates = sorted(option for option in known if option.startswith(flag))
    if len(candidates) > 1:
        raise ValueError(f"`{name} {flag}` is an ambiguous abbreviation of {', '.join(candidates)}")
    return candidates[0] if candidates else None


def wrapper_command_index(name, rest):
    """Parse one wrapper's own options and operands by its grammar.

    Returns (index of the wrapped command in `rest`, `env -C` directory or None, `env -S` string
    or None). An option that takes a value consumes it whether it is attached (`-sKILL`,
    `--signal=KILL`) or separate (`-s KILL`, `--signal KILL`); a long option is also recognised by
    any unique prefix (`--sig KILL`, `--ch=DIR`); `--` ends the options. An ambiguous long-option
    prefix raises ValueError.
    """
    short_values, long_values, long_flags, operand_count = WRAPPER_GRAMMARS[name]
    values = {}
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == "--":
            i += 1
            break
        if tok == "-" and name == "env":
            i += 1
            continue
        if tok.startswith("--"):
            written, eq, inline = tok.partition("=")
            flag = resolve_long_option(name, written, long_values, long_flags)
            if flag in long_values:
                values[flag] = inline if eq else (rest[i + 1] if i + 1 < len(rest) else "")
                i += 1 if eq else 2
            else:
                i += 1
            continue
        if tok.startswith("-") and len(tok) > 1:
            consumed = 1
            for j in range(1, len(tok)):
                flag = "-" + tok[j]
                if flag in short_values:
                    attached = tok[j + 1:]
                    if attached:
                        values[flag] = attached
                    else:
                        values[flag] = rest[i + 1] if i + 1 < len(rest) else ""
                        consumed = 2
                    break
            i += consumed
            continue
        break
    i = min(i + operand_count, len(rest))
    chdir = values.get("-C", values.get("--chdir"))
    split = values.get("-S", values.get("--split-string"))
    return i, chdir, split


def strip_command_prefixes(argv, cwd=None):
    """Drop `env`, `timeout -s KILL 60`, `nice -n 5`, ... so the real command word is found.

    Returns (argv, exhausted, cwd). `env -C DIR` moves the directory later paths resolve
    against, and `env -S STRING` splits STRING into the command it runs. Exhausting the
    bound must DENY rather than fall through, for the same reason wrapper-shell nesting does:
    a stack of prefixes deep enough to run out the parser is a command this engine cannot
    claim to have inspected. An `env -S` string the shell lexer cannot split raises ValueError.
    """
    for _ in range(4):
        argv = strip_env_assignments(argv)
        if not argv or program_name(argv[0]) not in WRAPPER_GRAMMARS:
            return argv, False, cwd
        name = program_name(argv[0])
        rest = argv[1:]
        index, chdir, split = wrapper_command_index(name, rest)
        argv = rest[index:]
        if chdir:
            resolved = resolve(chdir, cwd)
            cwd = str(resolved) if resolved is not None else cwd
        if split is not None:
            argv = shlex.split(split) + argv
    return argv, True, cwd


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


def gh_api_write_reason(args):
    """Why a `gh api` invocation may write, or "" when it is a plain GET or HEAD.

    Only GET and HEAD with no field and no input are reads. `-XPOST`, `-X=POST`, `-X POST`,
    `--method POST` and `--method=POST` all name a method; `-f`, `-F`, `--field`, `--raw-field`
    and `--input`, attached or separate, all send a body, and gh turns a request with a body
    into a POST. The graphql endpoint is always a POST.

    A single-dash token is a cluster of short flags, read letter by letter as gh's flag parser
    reads it: `-i` takes no value, so `-if state=approved` is `-i -f state=approved`; `-X`, `-H`,
    `-p`, `-q` and `-t` take the rest of the token, or the next token, as their value, which is
    never itself read as a flag.
    """
    body = "`gh api` with a field or an input sends a request body, which gh sends as a write."
    methods = []
    i = 0
    while i < len(args):
        a = args[i]
        following = args[i + 1] if i + 1 < len(args) else ""
        if a == "--method":
            methods.append(following)
            i += 2
            continue
        if a.startswith("--method="):
            methods.append(a.split("=", 1)[1])
        elif a in ("--field", "--raw-field", "--input") or a.startswith(("--field=", "--raw-field=", "--input=")):
            return body
        elif a in GH_API_LONG_VALUES:
            i += 2
            continue
        elif a.startswith("-") and not a.startswith("--") and len(a) > 1:
            takes_next = False
            for j, letter in enumerate(a[1:], start=1):
                rest = a[j + 1:]
                if letter in "fF":
                    return body
                if letter == "X":
                    if rest:
                        methods.append(rest[1:] if rest.startswith("=") else rest)
                    else:
                        methods.append(following)
                        takes_next = True
                    break
                if letter in GH_API_SHORT_VALUES:
                    takes_next = not rest
                    break
            i += 2 if takes_next else 1
            continue
        i += 1
    for method in methods:
        if method.upper() not in ("GET", "HEAD"):
            return f"`gh api` with method {method or '<missing>'} can write through the GitHub API; only GET and HEAD are allowed."
    if "graphql" in [a for a in args if not a.startswith("-")]:
        return "`gh api graphql` is always a POST."
    return ""


FIND_WRITE_ACTIONS = frozenset({"-fprint", "-fprint0", "-fprintf", "-fls"})


def reader_write_targets(cmd, args):
    """The files `find` or `tree` would write, though both are otherwise readers.

    `find -fprint FILE`, `-fprint0 FILE`, `-fprintf FILE FORMAT` and `-fls FILE`; `tree -o FILE`
    (in a flag cluster, with the file attached or next), `--output FILE`, `--output=FILE` and any
    prefix of `--output`. tree's own parser is looser than getopt, so every reading that could name
    the output file is returned: an extra candidate costs a false block, a missed one a false allow.
    """
    targets = []
    for i, a in enumerate(args):
        following = args[i + 1] if i + 1 < len(args) else ""
        if cmd == "find" and a in FIND_WRITE_ACTIONS:
            targets.append(following)
        elif cmd == "tree" and a.startswith("--"):
            flag, eq, inline = a.partition("=")
            if len(flag) > 2 and "--output".startswith(flag):
                targets.append(inline if eq else following)
        elif cmd == "tree" and a.startswith("-") and "o" in a[1:]:
            attached = a[a.index("o", 1) + 1:]
            targets.extend([attached, following])
    return [t for t in targets if t]


def check_bash_segment(argv, cwd, depth=0):
    argv = [a for a in argv if a not in REDIRECTS]
    argv = strip_env_assignments(argv)
    try:
        argv, prefixes_exhausted, cwd = strip_command_prefixes(argv, cwd)
    except ValueError as exc:
        return deny("malformed-input", f"could not parse a command prefix's options ({exc}); failing closed")
    if prefixes_exhausted:
        return deny(
            "wrapper-depth",
            "this command is wrapped in more command prefixes than the guard will unwrap. "
            "Run the command directly instead of through stacked wrappers.",
        )
    if not argv:
        return ALLOW

    cmd = program_name(argv[0])
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

    # find and tree only read -- except through their write options, which write a file as surely
    # as a redirect does. Those files pass the write rule before the reader exemption below.
    if cmd in ("find", "tree"):
        for target in reader_write_targets(cmd, args):
            d = check_write(target, cwd)
            if not d.allowed:
                return d

    # M3.3 staging evidence: any argument naming a path inside the reserved directory, for any
    # command that does not only read.
    if cmd not in EVIDENCE_READ_ONLY_COMMANDS:
        for a in args:
            candidate = a.split("=", 1)[1] if (a.startswith("-") and "=" in a) else a
            if not candidate or candidate.startswith("-"):
                continue
            p = resolve(candidate, cwd)
            if p is not None and under(p, DEPLOYMENT_EVIDENCE_DIR):
                return deny(
                    "deployment-evidence-deferred",
                    f"`{cmd}` names {p}, inside the M3.3 AWS staging evidence directory, which stays empty until an "
                    "explicitly authorized M3.3d deployment (ADR 0012). Evidence for other milestones is unaffected.",
                )

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
            reason = gh_api_write_reason(args)
            if reason:
                return deny("git-destructive", reason)
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

    if cmd == "find" and words & {"-delete", "-exec", "-execdir", "-ok", "-okdir"}:
        return deny("fs-destructive", "`find -delete`/`-exec`/`-ok` is an unbounded destructive operation.")

    if cmd == "dd" and any(a.startswith("of=") for a in args):
        return deny("fs-destructive", "`dd of=` writes raw blocks over a destination.")

    if cmd.startswith("mkfs"):
        return deny("fs-destructive", "filesystem creation is never a repository task.")

    if cmd in AWS_PROGRAMS:
        nouns = [a for a in args if not a.startswith("-")]
        # Only commands that never reach AWS pass: bare `aws`, `aws --version`, and help pages --
        # `aws help`, `aws <service> help`, `aws <service> <operation> help`. With more positional
        # arguments `help` is an ordinary operand (`aws s3 cp s3://b/k help` downloads), so it is not
        # a help page.
        if nouns and nouns[-1] == "help" and len(nouns) <= 3 and not (set(args) - set(nouns)):
            return ALLOW
        if not nouns and set(args) <= AWS_LOCAL_ONLY_FLAGS:
            return ALLOW
        for service, action in zip(nouns, nouns[1:]):
            if action.startswith(AWS_MUTATING_PREFIXES):
                return deny("cloud-mutation", f"`aws {service} {action}` changes cloud state and must be run by a human.")
            # The s3 high-level verbs are short words no prefix list would catch.
            if service == "s3" and action in ("rm", "mv", "rb", "sync"):
                return deny("cloud-mutation", f"`aws s3 {action}` can delete or overwrite objects; a human runs it.")
        if "s3" in nouns and "--delete" in words:
            return deny("cloud-mutation", "`aws s3 ... --delete` removes objects at the destination.")
        return deny(
            "cloud-access",
            "agent-run AWS CLI calls are not authorized in Milestone 3.3b, read-only ones included: "
            "they print account state, secrets or identity data into a transcript. A human runs AWS commands; "
            "M3.3d may authorize a narrowly scoped set once account, role, region and operation are confirmed.",
        )

    if cmd in TERRAFORM_PROGRAMS:
        sub = next((a for a in args if not a.startswith("-")), "")
        if sub in TERRAFORM_MUTATING or (sub == "state" and any(a in ("rm", "mv", "push", "replace-provider") for a in args)):
            return deny(
                "cloud-mutation",
                f"`{cmd} {sub}` plans, changes or unlocks infrastructure or state and must be run by a human.",
            )
        if not sub and set(args) & {"-version", "--version", "-help", "--help", "-h"}:
            return ALLOW
        if sub not in TERRAFORM_ALLOWED:
            return deny(
                "terraform-bounded",
                f"`terraform {sub or ' '.join(args)}` is outside the bounded local operations agents may run "
                "(fmt, validate, version, providers lock, init -backend=false). Run the mocked tests through "
                "infra/terraform/scripts/static-checks.sh; state and outputs are read by a human.",
            )
        backend = [a.split("=", 1)[1] for a in args if a.startswith("-backend=") or a.startswith("--backend=")]
        if sub == "init" and (not backend or backend[-1] != "false" or "-backend" in args or "--backend" in args):
            return deny(
                "terraform-bounded",
                "`terraform init` would configure the real S3 backend; agents run `init -backend=false` only.",
            )
        if sub == "providers":
            rest = [a for a in args[args.index("providers") + 1:] if not a.startswith("-")]
            if rest[:1] != ["lock"]:
                return deny(
                    "terraform-bounded",
                    "`terraform providers` other than `providers lock` can load state from a configured backend.",
                )
        return ALLOW

    # Image registries: no agent logs in to one or pushes to one (ECR included).
    if cmd in REGISTRY_CLIENTS or cmd in REGISTRY_TOOLS:
        verbs = [a for a in args if not a.startswith("-")]
        outputs = [args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-o", "--output")]
        outputs += [a.split("=", 1)[1] for a in args if a.startswith(("--output=", "-o="))]
        if (
            REGISTRY_VERBS & set(verbs)
            or "--push" in words
            or any("type=registry" in o or "push=true" in o for o in outputs)
            or (cmd in REGISTRY_TOOLS and verbs[:1] and verbs[0] in REGISTRY_TOOL_WRITES)
        ):
            return deny("registry-push", f"`{cmd}` registry login or push is not an agent action; image publication is a human step.")
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
    """Evaluate every target in a complete Codex unified apply_patch envelope."""
    if not isinstance(patch, str):
        return deny("malformed-input", "apply_patch payload is not a string; failing closed")
    lines = patch.splitlines()
    if len(lines) < 3 or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        return deny("malformed-input", "incomplete apply_patch envelope; failing closed")

    targets = []
    markers = (("*** Delete File:", True), ("*** Update File:", False), ("*** Add File:", False))
    for line in lines[1:-1]:
        for marker, deleting in markers:
            if line.startswith(marker):
                target = line[len(marker):].strip()
                if not target:
                    return deny("malformed-input", "apply_patch file header has no path; failing closed")
                targets.append((target, deleting))
                break
    if not targets:
        return deny("malformed-input", "apply_patch payload names no files; failing closed")
    for target, deleting in targets:
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
    patch = command if tool == "apply_patch" else _first(tool_input, "patch", "input", "diff")

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
