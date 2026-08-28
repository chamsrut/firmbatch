#!/usr/bin/env bash
#
# The one verification entry point for Firmbatch.
#
# Humans, agents (via the `verify` skill), and CI all run THIS script, so that all
# three are provably running the same thing. If you find yourself typing the
# individual commands, add the gate here instead.
#
#   ./scripts/verify-repository.sh
#
# Every gate prints PASS or FAIL on its own line. The script exits non-zero if any
# gate fails, and it never stops at the first failure -- a run reports the whole
# picture, because a partial answer is what sends an agent round a second time.
#
# This pass is fast, deterministic, and side-effect free. It touches no database and
# writes no evidence artifact. The destructive chaos experiment is NOT here; it is
# explicit, opt-in, and lives in .agents/skills/verify/SKILL.md.

set -euo pipefail

# --- resolve our own repository root, however we were invoked ----------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
REPO_NAME="$(basename -- "${REPO_ROOT}")"
PARENT_DIR="$(dirname -- "${REPO_ROOT}")"

PASSED=0
FAILED=0
FAILED_NAMES=()

pass() { printf '  PASS  %s\n' "$1"; PASSED=$((PASSED + 1)); }
fail() {
  printf '  FAIL  %s\n' "$1"
  [ $# -gt 1 ] && printf '        %s\n' "$2"
  FAILED=$((FAILED + 1))
  FAILED_NAMES+=("$1")
  return 0
}

# Run a command, capture its output, report one gate.
gate() {
  local name="$1"; shift
  local out status
  set +e
  out="$("$@" 2>&1)"
  status=$?
  set -e
  if [ "${status}" -eq 0 ]; then
    pass "${name}"
  else
    fail "${name}" "$(printf '%s' "${out}" | tail -n 15)"
  fi
}

# Same, but from a given directory. A subshell rather than `env -C`, which is
# GNU-only -- the working directory is load-bearing here and must not depend on
# which coreutils the runner happens to ship.
gate_in() {
  local dir="$1" name="$2"; shift 2
  local out status
  set +e
  out="$(cd -- "${dir}" && "$@" 2>&1)"
  status=$?
  set -e
  if [ "${status}" -eq 0 ]; then
    pass "${name}"
  else
    fail "${name}" "$(printf '%s' "${out}" | tail -n 15)"
  fi
}

printf 'firmbatch repository verification\n'
printf '  repository  %s\n' "${REPO_ROOT}"
printf '  python      %s\n' "$(python3 --version 2>&1)"
printf '\nlayout\n'

# --- the package import requirement ------------------------------------------------
# firmbatch is imported as a PACKAGE (`from firmbatch.control import db`), so the
# repository directory must be named `firmbatch` and tests run from its PARENT.
if [ "${REPO_NAME}" = "firmbatch" ]; then
  pass "repository directory is named 'firmbatch' (required by the package import)"
else
  fail "repository directory is named 'firmbatch' (required by the package import)" \
       "found '${REPO_NAME}'; 'from firmbatch.control import db' cannot resolve"
fi

# --- required R0 files -------------------------------------------------------------
REQUIRED_FILES=(
  AGENTS.md
  CLAUDE.md
  README.md
  pyproject.toml
  scripts/verify-repository.sh
  .agents/policy/guard.py
  .agents/policy/test_guard.py
  .agents/skills/verify/SKILL.md
  .agents/skills/record-evidence/SKILL.md
  .agents/skills/milestone/SKILL.md
  .claude/settings.json
  .claude/agents/distributed-systems-reviewer.md
  .claude/agents/test-evidence-reviewer.md
  .claude/agents/security-operations-reviewer.md
  .codex/hooks.json
  .codex/README.md
  .codex/agents/distributed-systems-reviewer.toml
  .codex/agents/test-evidence-reviewer.toml
  .codex/agents/security-operations-reviewer.toml
  .github/workflows/ci.yml
  docs/STATE.md
  docs/tasks/current.md
  docs/firmbatch-pilot-roadmap.md
  docs/adr/0001-agentic-repository-operating-model.md
)
missing=()
for f in "${REQUIRED_FILES[@]}"; do
  [ -e "${REPO_ROOT}/${f}" ] || missing+=("${f}")
done
if [ ${#missing[@]} -eq 0 ]; then
  pass "all ${#REQUIRED_FILES[@]} required R0 files exist"
else
  fail "all ${#REQUIRED_FILES[@]} required R0 files exist" "missing: ${missing[*]}"
fi

# --- skill symlinks ----------------------------------------------------------------
# .claude/skills/<name> must be a symlink into the canonical .agents/skills/<name>.
# A copy here would drift; a broken link would silently remove the skill.
bad_links=()
for skill in verify record-evidence milestone; do
  link="${REPO_ROOT}/.claude/skills/${skill}"
  canonical="${REPO_ROOT}/.agents/skills/${skill}"
  if [ ! -L "${link}" ]; then
    bad_links+=("${skill}: not a symlink")
  elif [ ! -f "${link}/SKILL.md" ]; then
    bad_links+=("${skill}: link does not resolve to a SKILL.md")
  elif [ "$(cd -- "${link}" && pwd -P)" != "$(cd -- "${canonical}" && pwd -P)" ]; then
    bad_links+=("${skill}: resolves outside .agents/skills/")
  fi
done
if [ ${#bad_links[@]} -eq 0 ]; then
  pass "the three .claude/skills symlinks resolve into .agents/skills"
else
  fail "the three .claude/skills symlinks resolve into .agents/skills" "${bad_links[*]}"
fi

# --- agent configuration parses ----------------------------------------------------
printf '\nagent configuration\n'

gate "all agent JSON configuration parses" python3 - "${REPO_ROOT}" <<'PY'
import json, sys, pathlib
root = pathlib.Path(sys.argv[1])
bad = []
for rel in (".claude/settings.json", ".codex/hooks.json"):
    p = root / rel
    if not p.exists():
        bad.append(f"{rel}: missing")
        continue
    try:
        json.loads(p.read_text())
    except Exception as exc:
        bad.append(f"{rel}: {exc}")
if bad:
    print("\n".join(bad)); sys.exit(1)
PY

gate "all agent TOML configuration parses" python3 - "${REPO_ROOT}" <<'PY'
import tomllib, sys, pathlib
root = pathlib.Path(sys.argv[1])
paths = sorted((root / ".codex" / "agents").glob("*.toml"))
if not paths:
    print("no .codex/agents/*.toml found"); sys.exit(1)
bad = []
for p in paths:
    try:
        data = tomllib.loads(p.read_text())
    except Exception as exc:
        bad.append(f"{p.name}: {exc}"); continue
    for field in ("name", "description", "instructions"):
        if field not in data:
            bad.append(f"{p.name}: missing '{field}'")
    if data.get("read_only") is not True:
        bad.append(f"{p.name}: reviewers must declare read_only = true")
if bad:
    print("\n".join(bad)); sys.exit(1)
PY

gate "the Claude hook registration invokes the shared guard" python3 - "${REPO_ROOT}" <<'PY'
import json, sys, pathlib
root = pathlib.Path(sys.argv[1])
cfg = json.loads((root / ".claude/settings.json").read_text())
entries = cfg.get("hooks", {}).get("PreToolUse", [])
problems = []
if not entries:
    problems.append("no PreToolUse hook registered")
REQUIRED = {"Write", "Edit", "MultiEdit", "NotebookEdit", "Bash", "Read", "Grep", "Glob"}
for entry in entries:
    # Split on the alternation rather than substring-testing: "Edit" is a substring of
    # "MultiEdit", so a matcher that dropped the bare Edit tool would have passed.
    covered = {t.strip() for t in entry.get("matcher", "").split("|")}
    missing = REQUIRED - covered
    if missing:
        problems.append(f"matcher does not cover {sorted(missing)}: {entry.get('matcher')!r}")
    for hook in entry.get("hooks", []):
        command = hook.get("command", "")
        if "guard.py" not in command:
            problems.append(f"hook does not invoke guard.py: {command!r}")
        if "--adapter claude" not in command:
            problems.append(f"hook does not pass --adapter claude: {command!r}")
        if hook.get("type") != "command":
            problems.append(f"hook type is not 'command': {hook.get('type')!r}")
if problems:
    print("\n".join(problems)); sys.exit(1)
PY

# Two separate gates, because the two agents give different kinds of assurance and one
# name covering both would claim more than either check performs. The Claude side is
# checked structurally (the granted tool list); the Codex side can only be checked as a
# DECLARATION, since `read_only = true` sits beside a granted `shell` and it is Codex that
# must honour it. Neither gate observes runtime behaviour -- see docs/STATE.md.
gate "Claude reviewers grant only read-only tools" python3 - "${REPO_ROOT}" <<'PY'
import sys, pathlib, re
root = pathlib.Path(sys.argv[1])
problems = []
for p in sorted((root / ".claude" / "agents").glob("*.md")):
    m = re.search(r"^tools:\s*(.+)$", p.read_text(), re.M)
    if not m:
        problems.append(f"{p.name}: no 'tools:' field"); continue
    tools = {t.strip() for t in m.group(1).split(",")}
    # Bash is not a read-only tool. A reviewer reports; it never runs or fixes.
    forbidden = tools - {"Read", "Grep", "Glob"}
    if forbidden:
        problems.append(f"{p.name}: non-read-only tools {sorted(forbidden)}")
if problems:
    print("\n".join(problems)); sys.exit(1)
PY

gate "Codex reviewers declare read_only and grant no write tool" python3 - "${REPO_ROOT}" <<'PY'
import tomllib, sys, pathlib
root = pathlib.Path(sys.argv[1])
WRITE_TOOLS = {"write", "edit", "apply_patch", "patch"}
problems = []
for p in sorted((root / ".codex" / "agents").glob("*.toml")):
    data = tomllib.loads(p.read_text())
    if data.get("read_only") is not True:
        problems.append(f"{p.name}: read_only is not true")
    granted = {str(t).lower() for t in data.get("tools", [])}
    offending = granted & WRITE_TOOLS
    if offending:
        problems.append(f"{p.name}: grants write tools {sorted(offending)} despite read_only")
if problems:
    print("\n".join(problems)); sys.exit(1)
PY

# --- secret and artifact hygiene ---------------------------------------------------
printf '\nrepository hygiene\n'

gate "no credential file, private key, or database is tracked by git" \
  python3 - "${REPO_ROOT}" <<'PY'
import subprocess, sys, pathlib
root = pathlib.Path(sys.argv[1])
try:
    tracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True, text=True, check=True,
    ).stdout.split("\0")
except Exception as exc:
    print(f"could not list tracked files: {exc}"); sys.exit(1)

CRED_NAMES = {".env", ".netrc", ".pgpass", "credentials", "auth.json",
              "secrets.json", "service-account.json"}
KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")
DB_SUFFIXES = (".db", ".sqlite", ".sqlite3")
KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx")

bad = []
for rel in filter(None, tracked):
    name = pathlib.PurePosixPath(rel).name
    if name.endswith(TEMPLATE_SUFFIXES):
        continue
    if name in CRED_NAMES or name.startswith(".env."):
        bad.append(f"credential file tracked: {rel}")
    elif name in KEY_NAMES or name.endswith(KEY_SUFFIXES):
        bad.append(f"private key tracked: {rel}")
    elif name.endswith(DB_SUFFIXES):
        bad.append(f"database tracked: {rel}")
    else:
        # A file whose first bytes are a SQLite header, whatever it is named.
        p = root / rel
        try:
            if p.is_file() and p.open("rb").read(16).startswith(b"SQLite format 3"):
                bad.append(f"SQLite database tracked under another name: {rel}")
        except OSError:
            pass
if bad:
    print("\n".join(bad)); sys.exit(1)
PY

# --- the three functional gates ----------------------------------------------------
printf '\nfunctional gates\n'

# Property tests run from the PARENT directory: `from firmbatch.control import db`.
gate_in "${PARENT_DIR}" "property tests (v0 durability invariants)" \
  python3 -m "${REPO_NAME}.tests.test_recovery"

# Lint. Never --fix, never `ruff format`: v0's terse style is deliberate and its
# findings are frozen as per-file-ignores in pyproject.toml.
if command -v ruff >/dev/null 2>&1; then
  gate_in "${REPO_ROOT}" "ruff check (no --fix)" ruff check .
else
  fail "ruff check (no --fix)" "ruff is not installed; expected the pinned 0.16.5"
fi

gate_in "${REPO_ROOT}" "agent policy tests" python3 .agents/policy/test_guard.py

# --- summary -----------------------------------------------------------------------
printf '\n'
if [ "${FAILED}" -eq 0 ]; then
  printf '  %d gates passed, 0 failed\n' "${PASSED}"
  exit 0
fi
printf '  %d gates passed, %d FAILED: %s\n' "${PASSED}" "${FAILED}" "${FAILED_NAMES[*]}"
exit 1
