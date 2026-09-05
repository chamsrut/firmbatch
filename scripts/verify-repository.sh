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
# This pass is fast, deterministic, and writes no evidence artifact.
#
# It is NOT side-effect free any more. Since Milestone 2.1 the last gate runs the v1
# foundation suite against a real PostgreSQL 16 server, where it creates a disposable
# `firmbatch_test_<random>` database and three throwaway roles and drops them again. It
# touches nothing else: the helpers in control_plane/testing/bootstrap.py refuse any
# database whose name does not match that pattern, refuse to run at all unless
# FIRMBATCH_ENV=test, and issue the final DROP as the per-run database owner so that a
# same-name replacement owned by anybody else survives.
#
# The destructive chaos experiment is still NOT here; it is explicit, opt-in, and lives
# in .agents/skills/verify/SKILL.md.

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

# The pytest gate, reported so a database failure is diagnosable from the output.
#
# `gate_in` tails 15 lines, which for pytest is the short summary -- the part that names
# which tests failed and nothing about why. Runs with --maxfail=1 so the first failure is
# the last thing that happened, prints a window at each end of it, and keeps the full log
# on disk.
gate_pytest() {
  local dir="$1" name="$2"; shift 2
  local raw log status
  raw="${TMPDIR:-/tmp}/firmbatch-foundation-suite.$$.raw"
  log="${TMPDIR:-/tmp}/firmbatch-foundation-suite.$$.log"

  # --- credentials must not survive into a retained file ---------------------------
  #
  # A failing PostgreSQL test carries two kinds of secret into its traceback without
  # anybody choosing to put them there: the privileged admin URL (pytest renders every
  # fixture value at the head of a long traceback, and `environment` holds
  # FIRMBATCH_TEST_DATABASE_URL, which in CI has a real password), and the per-run role
  # passwords psycopg echoes when a CREATE ROLE statement fails.
  #
  # Redacting only the printed excerpt is not enough, and was the earlier mistake: the
  # full log stays on disk at a path the failure message helpfully names. So:
  #
  #   * both files are created 0600, before anything is written into them;
  #   * the RETAINED file is the sanitized one and the raw capture is deleted;
  #   * the two display windows read the sanitized file, so stdout is covered by the same
  #     pass rather than by a second, separately-maintained one.
  ( umask 077; : >"${raw}"; : >"${log}" )

  set +e
  ( cd -- "${dir}" && "$@" ) >"${raw}" 2>&1
  status=$?
  set -e

  if [ "${status}" -eq 0 ]; then
    pass "${name}"
    rm -f "${raw}" "${log}"
    return 0
  fi

  if python3 "${REPO_ROOT}/scripts/sanitize-secrets.py" --in "${raw}" --out "${log}"; then
    rm -f "${raw}"
  else
    # Sanitizing failed, so nothing may be retained or shown: a log that might carry a
    # live credential is worse than no log. Say so, and keep the gate failing.
    rm -f "${raw}" "${log}"
    fail "${name}" "output withheld: it could not be sanitized, and an unsanitized log may carry credentials"
    return 0
  fi

  fail "${name}" "first failure below; sanitized output retained at ${log}"

  # Two windows, because the useful information is at both ends of a pytest failure.
  #
  # The heading and the first frames say WHICH test and in what context. The exception
  # that actually explains it -- `psycopg.errors.InsufficientPrivilege`, an
  # `OperationalError` naming a refused connection -- is at the END of the traceback, after
  # however many frames of SQLAlchemy and pytest wrapper the call took to get there. A
  # window at the top alone routinely shows nothing but wrapper frames.
  #
  # No pipes anywhere. `awk ... | head -n 60` looks harmless and is not: head exits at line
  # 60, awk gets SIGPIPE and dies with 141, `set -o pipefail` promotes that to the pipeline
  # status, and `set -e` then aborts the whole script -- losing the retained-log path, the
  # summary, this gate's result, and the final PASS/FAIL tally, and exiting 141 instead of
  # 1. Reproduced with a 5,000-line failure log. Each awk below reads the log directly and
  # consumes all of it, so there is no upstream process to signal.
  printf '        ---- first failure (context) ----\n'
  awk '/^={5,} (FAILURES|ERRORS) ={5,}/ { found = 1 }
       found && shown < 25 { printf "        %s\n", $0; shown++ }' "${log}"

  printf '        ---- terminal exception ----\n'
  awk -v keep=45 '{ ring[NR % keep] = $0 }
       END { for (i = NR - keep + 1; i <= NR; i++) if (i > 0) printf "        %s\n", ring[i % keep] }' "${log}"
  return 0
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

# --- required repository files -----------------------------------------------------
REQUIRED_FILES=(
  AGENTS.md
  CLAUDE.md
  README.md
  pyproject.toml
  scripts/verify-repository.sh
  scripts/check-runtime-imports.py
  scripts/sanitize-secrets.py
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
  docs/firmbatch-v1-roadmap.md
  docs/architecture/v1-target-architecture.md
  docs/adr/0001-agentic-repository-operating-model.md
  docs/adr/0004-postgresql-tenant-isolation-foundation.md
  docs/adr/0005-idempotent-mutations-and-transactional-outbox.md
  # --- v1 control-plane foundation (Milestone 2.1) --------------------------------
  requirements-v1.txt
  requirements-v1-dev.txt
  # Fully resolved, hash-pinned graphs. CI installs from these, not from the direct pins.
  requirements-v1-lock.txt
  requirements-v1-dev-lock.txt
  control_plane/__init__.py
  control_plane/config.py
  control_plane/migrate.py
  control_plane/alembic.ini
  control_plane/db/base.py
  control_plane/db/models.py
  control_plane/db/engine.py
  control_plane/db/principal.py
  control_plane/db/identity.py
  control_plane/db/roles.py
  control_plane/db/repositories.py
  control_plane/db/migrations/env.py
  control_plane/db/migrations/versions/0001_tenant_workspace_spine.py
  control_plane/testing/attestation.py
  control_plane/testing/bootstrap.py
  control_plane/tests/conftest.py
  control_plane/tests/test_configuration.py
  control_plane/tests/test_migrations.py
  control_plane/tests/test_tenant_isolation.py
  control_plane/tests/test_isolation_hardening.py
  control_plane/tests/test_bootstrap_safety.py
  control_plane/tests/test_connection_identity.py
  control_plane/tests/test_connection_specification.py
  control_plane/tests/test_connection_environment.py
  control_plane/tests/test_admin_escalation.py
  control_plane/tests/test_settings_separation.py
  control_plane/tests/test_version_preflight.py
  control_plane/tests/test_bind_forms.py
  control_plane/tests/test_migration_entry_points.py
  control_plane/tests/test_ownership_boundary.py
  control_plane/tests/test_bootstrap_lifecycle.py
  control_plane/tests/test_destructive_safety.py
  control_plane/tests/test_verification_reporting.py
  control_plane/tests/test_role_privileges.py
  # --- idempotent mutations and the transactional outbox (Milestone 2.2) ----------
  # No new gate: the foundation-suite gate below already runs the whole
  # control_plane/tests directory, so these run with everything else. What is
  # registered here is their existence, so that deleting one fails the layout gate
  # instead of quietly shrinking the suite.
  control_plane/db/idempotency.py
  control_plane/db/migrations/versions/0002_idempotency_and_outbox.py
  control_plane/tests/test_idempotency.py
  control_plane/tests/test_idempotency_concurrency.py
  control_plane/tests/test_outbox_isolation.py
  # --- authenticated context, authorization, audit, secrets (Milestone 2.3) --------
  # Still no new gate, for the same reason: the foundation-suite gate below runs the
  # whole control_plane/tests directory. What is registered here is their existence.
  docs/adr/0006-authenticated-authorization-audit-and-secrets.md
  control_plane/security/__init__.py
  control_plane/security/authorization.py
  control_plane/security/secrets.py
  control_plane/db/auth.py
  control_plane/db/audit.py
  control_plane/db/metadata.py
  control_plane/db/migrations/versions/0003_auth_context_and_audit.py
  control_plane/tests/test_authenticated_context.py
  control_plane/tests/test_authorization.py
  control_plane/tests/test_protected_auth_state.py
  control_plane/tests/test_audit_events.py
  control_plane/tests/test_secrets_model.py
)
missing=()
for f in "${REQUIRED_FILES[@]}"; do
  [ -e "${REPO_ROOT}/${f}" ] || missing+=("${f}")
done
if [ ${#missing[@]} -eq 0 ]; then
  pass "all ${#REQUIRED_FILES[@]} required repository files exist"
else
  fail "all ${#REQUIRED_FILES[@]} required repository files exist" "missing: ${missing[*]}"
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
    for field in ("name", "description", "developer_instructions"):
        if not isinstance(data.get(field), str):
            bad.append(f"{p.name}: '{field}' must be a string")
    if data.get("sandbox_mode") != "read-only":
        bad.append(f"{p.name}: sandbox_mode must equal 'read-only'")
    for field in ("read_only", "instructions"):
        if field in data:
            bad.append(f"{p.name}: obsolete top-level field '{field}' is present")
    if isinstance(data.get("tools"), list):
        bad.append(f"{p.name}: array-valued top-level 'tools' field is present")
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

# The Claude side is checked structurally. Codex reviewers declare their read-only sandbox
# through their TOML schema; the parser gate above also rejects obsolete schema fields and a
# custom array-valued tools declaration. Neither gate observes runtime behaviour -- see
# docs/STATE.md.
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

gate "Codex reviewers declare the read-only sandbox schema" python3 - "${REPO_ROOT}" <<'PY'
import tomllib, sys, pathlib
root = pathlib.Path(sys.argv[1])
problems = []
for p in sorted((root / ".codex" / "agents").glob("*.toml")):
    data = tomllib.loads(p.read_text())
    if data.get("sandbox_mode") != "read-only":
        problems.append(f"{p.name}: sandbox_mode is not 'read-only'")
    if any(field in data for field in ("read_only", "instructions")):
        problems.append(f"{p.name}: declares obsolete reviewer fields")
    if isinstance(data.get("tools"), list):
        problems.append(f"{p.name}: declares an array-valued tools field")
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

# Production code may only import what a PRODUCTION install has. The development lock is a
# superset of the runtime lock, so an import satisfied only by pytest, ruff, or anything
# they drag in would install, import and test cleanly here and fail on first use in
# production. This is the static half; CI runs the same script with --dynamic inside a
# clean virtual environment built from requirements-v1-lock.txt, which additionally catches
# deferred and conditional imports that no parser can see.
gate_in "${REPO_ROOT}" "runtime import closure (production code vs requirements-v1-lock.txt)" \
  python3 scripts/check-runtime-imports.py --static

# --- the v1 PostgreSQL foundation suite ---------------------------------------------
# Milestone 2.1. Runs against a REAL PostgreSQL 16 server: the properties under test are
# row-level security, forced policies, role attributes, referential integrity and
# transaction-local settings, none of which has a faithful in-memory substitute.
#
# It must FAIL, never skip, when the server is absent. A skipped isolation suite reports
# the same green as a passing one, and "cross-tenant access fails closed" is exactly the
# claim this repository's evidence rules say may not rest on an unobserved run.
#
# The suite creates its own disposable `firmbatch_test_<random>` database and throwaway
# roles from the maintenance URL below and drops them again; the helpers refuse any
# database whose name does not match that pattern.
if [ -z "${FIRMBATCH_TEST_DATABASE_URL:-}" ]; then
  fail "PostgreSQL foundation suite (control_plane, real PostgreSQL 16)" \
       "FIRMBATCH_TEST_DATABASE_URL is not set. This gate does not skip: set it to a maintenance
        connection with EVERY field explicit -- user, host, port, database. For example
        postgresql+psycopg://USER@/postgres?host=/var/run/postgresql&port=5432 (local native
        PostgreSQL) or postgresql+psycopg://postgres:postgres@127.0.0.1:5432/postgres (CI
        service container). An omitted field would be supplied by PGUSER/PGHOST/PGPORT.
        The server must also be attested as disposable, once per cluster:
          cd \"\$(git rev-parse --show-toplevel)/..\"
          FIRMBATCH_ENV=test python3 -m firmbatch.control_plane.testing.attestation --mark
        See .env.example and .agents/skills/verify/SKILL.md."
else
  # From the PARENT directory, like the property tests: control_plane is imported as
  # firmbatch.control_plane. FIRMBATCH_ENV is passed explicitly -- the configuration
  # boundary has no default environment, deliberately.
  # --tb=short deliberately. The long traceback renders every fixture value at the head
  # of a failure -- `environment = {'FIRMBATCH_TEST_DATABASE_URL': '...'}` -- which is how
  # the privileged admin URL reaches a job log without anybody printing it. Short mode
  # keeps the failing line and the terminal exception, which is the part that is
  # actionable, and drops the argument rendering that is not.
  gate_pytest "${PARENT_DIR}" "PostgreSQL foundation suite (control_plane, real PostgreSQL 16)" \
    env FIRMBATCH_ENV=test python3 -m pytest -q --maxfail=1 --tb=short "${REPO_NAME}/control_plane/tests"
fi

# --- summary -----------------------------------------------------------------------
printf '\n'
if [ "${FAILED}" -eq 0 ]; then
  printf '  %d gates passed, 0 failed\n' "${PASSED}"
  exit 0
fi
printf '  %d gates passed, %d FAILED: %s\n' "${PASSED}" "${FAILED}" "${FAILED_NAMES[*]}"
exit 1
