"""Regression for the verification script's failure reporter (finding 8).

``scripts/verify-repository.sh`` runs under ``set -euo pipefail``. Its failure reporter
used to be ``awk ... | head -n 60``: ``head`` exits at line 60, ``awk`` takes SIGPIPE and
dies with 141, ``pipefail`` promotes that to the pipeline status, and ``set -e`` aborts the
whole script. The retained-log path, the traceback, this gate's result and the final
PASS/FAIL tally were all lost, and the script exited 141 instead of 1. Reproduced with a
5,000-line log.

These tests exercise the real function out of the real script, against output longer than
the display limit, and assert on what a human needs to see: the root exception, the log
path, a nonzero-but-not-141 result, and the summary line.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import textwrap

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
VERIFY_SCRIPT = REPO_ROOT / "scripts" / "verify-repository.sh"

#: Long enough that any line-limited display has to stop early -- which is precisely the
#: condition that used to raise SIGPIPE.
_TRACEBACK_LINES = 400

#: What the reader actually needs, and where pytest really puts it: at the END of the
#: traceback, after however many frames of SQLAlchemy and pytest wrapper the call took to
#: get there. A window at the top of the failure shows only the opening frames.
TERMINAL_EXCEPTION = (
    "E   sqlalchemy.exc.OperationalError: (psycopg.OperationalError) connection failed: "
    "FATAL:  password authentication failed for user \"firmbatch_test_app_0123456789ab\""
)

#: Near the top, so a test that only looked here would pass while showing nothing useful.
OPENING_CONTEXT = "____________________ test_tenant_a_cannot_read_tenant_b_workspaces _________________"


def _fake_pytest_output(tmp_path: pathlib.Path) -> pathlib.Path:
    """A failure log shaped like a real one: heading, wrapper frames, then the cause.

    Deliberately *not* the shape the previous fixture used. That one put the root
    exception on line 4, so a reporter that printed only the first 60 lines passed a test
    it should have failed.
    """
    body = [
        "===================================== FAILURES =====================================",
        OPENING_CONTEXT,
        "",
        "self = <firmbatch.control_plane.tests.test_tenant_isolation.Case object>",
        "",
    ]
    body += [f"    frame {i} of sqlalchemy and pytest wrapper machinery" for i in range(_TRACEBACK_LINES)]
    body += [
        "",
        TERMINAL_EXCEPTION,
        "",
        "firmbatch/control_plane/db/engine.py:210: OperationalError",
        "=========================== short test summary info ============================",
        "FAILED control_plane/tests/test_tenant_isolation.py::test_tenant_a_cannot_read",
        "1 failed, 135 passed in 12.00s",
    ]
    log = tmp_path / "pytest-output.txt"
    log.write_text("\n".join(body) + "\n")
    return log


def _run_gate_pytest(tmp_path: pathlib.Path) -> subprocess.CompletedProcess:
    """Source the real script's helpers and drive gate_pytest with a failing command.

    The script is sourced with a guard variable so it defines its functions and stops
    before running any gate; that keeps this test bound to the shipped implementation
    rather than to a copy of it.
    """
    payload = _fake_pytest_output(tmp_path)
    harness = tmp_path / "harness.sh"
    repo_root = REPO_ROOT
    harness.write_text(
        textwrap.dedent(
            f"""
            set -euo pipefail
            # gate_pytest sanitizes its capture before retaining it, so it needs the
            # repository root (for scripts/sanitize-secrets.py) and a private TMPDIR.
            REPO_ROOT="{repo_root}"
            TMPDIR="{tmp_path}"
            export TMPDIR
            PASSED=0
            FAILED=0
            FAILED_NAMES=()
            pass() {{ printf '  PASS  %s\\n' "$1"; PASSED=$((PASSED + 1)); }}
            fail() {{
              printf '  FAIL  %s\\n' "$1"
              [ $# -gt 1 ] && printf '        %s\\n' "$2"
              FAILED=$((FAILED + 1))
              FAILED_NAMES+=("$1")
              return 0
            }}

            # The shipped gate_pytest, extracted from the real script.
            eval "$(awk '/^gate_pytest\\(\\) \\{{$/,/^\\}}$/' {VERIFY_SCRIPT})"

            # A command that emits the long failure log and then FAILS, which is what puts
            # gate_pytest on its reporting path.
            gate_pytest "{tmp_path}" "fake suite" bash -c "cat '{payload}'; exit 1"
            # Everything below must still run.
            printf '  %d gates passed, %d FAILED: %s\\n' "$PASSED" "$FAILED" "${{FAILED_NAMES[*]}}"
            exit 1
            """
        ).strip()
    )
    return subprocess.run(
        ["bash", str(harness)], capture_output=True, text=True, cwd=str(tmp_path)
    )


def test_the_failure_reporter_survives_output_longer_than_it_displays(tmp_path):
    result = _run_gate_pytest(tmp_path)
    combined = result.stdout + result.stderr

    # 141 is SIGPIPE. It must never be the exit status.
    assert result.returncode != 141, f"reporter died of SIGPIPE:\n{combined}"
    assert result.returncode == 1, f"expected the harness exit of 1, got {result.returncode}"


def test_the_failure_reporter_shows_the_terminal_exception_and_the_log_path(tmp_path):
    """The actionable exception is at the END of a real traceback, not the beginning.

    This is the assertion the previous version of these tests could not make: its fixture
    put the exception near the top, so a reporter showing only opening wrapper frames
    passed. Here the exception sits behind 400 frames.
    """
    result = _run_gate_pytest(tmp_path)
    combined = result.stdout + result.stderr

    assert "FAIL  fake suite" in combined
    assert "OperationalError" in combined, "the terminal exception was not shown"
    assert "password authentication failed" in combined, "the actionable detail was not shown"
    assert "sanitized output retained at" in combined, "the retained-log path was not named"
    # And the context at the other end, so the reader knows which test it was.
    assert "test_tenant_a_cannot_read_tenant_b_workspaces" in combined
    assert "---- terminal exception ----" in combined


def test_the_failure_reporter_still_reaches_the_final_summary(tmp_path):
    """The line after the reporter must run: losing it was the worst part of the bug."""
    result = _run_gate_pytest(tmp_path)
    combined = result.stdout + result.stderr
    assert "1 FAILED: fake suite" in combined, f"the summary was never printed:\n{combined}"


def test_the_reporter_bounds_how_much_it_prints(tmp_path):
    """Bounded at both ends: enough to act on, not the whole log."""
    result = _run_gate_pytest(tmp_path)
    shown = [line for line in result.stdout.splitlines() if "frame " in line]
    assert 0 < len(shown) < 200, f"expected a bounded excerpt, got {len(shown)} traceback lines"
    assert len(result.stdout.splitlines()) < _TRACEBACK_LINES, "the reporter printed the whole log"


# --------------------------------------------------------------------------------------
# Finding 5: no credential may reach stdout, stderr, or the retained log.
#
# Two secrets arrive in a failing PostgreSQL test's traceback without anybody choosing to
# put them there:
#
#   * the privileged admin URL. pytest's long traceback renders every fixture value at the
#     head of a failure -- ``environment = {'FIRMBATCH_TEST_DATABASE_URL': '...'}`` -- and
#     in CI that URL carries a real password.
#   * per-run role passwords. psycopg echoes the failing statement, so a
#     ``CREATE ROLE ... PASSWORD '...'`` that fails carries a live credential.
#
# Redacting the printed excerpt while retaining an unsanitized file is not a fix: the
# failure message names the path. So the retained file is the sanitized one, the raw
# capture is deleted, and both are created 0600.
# --------------------------------------------------------------------------------------

ADMIN_PASSWORD = "s3ntinel-admin-passw0rd"
ADMIN_URL = f"postgresql+psycopg://postgres:{ADMIN_PASSWORD}@127.0.0.1:5432/postgres"
ROLE_PASSWORD = "0123456789abcdef0123456789abcdef"  # the shape secrets.token_hex(16) makes


def _secret_bearing_output(tmp_path: pathlib.Path) -> pathlib.Path:
    """A failure log shaped like a real one, carrying both secrets and a long traceback."""
    body = [
        "===================================== FAILURES =====================================",
        "_______________ test_the_provisioning_role_can_create_a_tenant _______________",
        "",
        # This is exactly what --tb=long prints for a fixture value.
        f"environment = {{'FIRMBATCH_ENV': 'test', 'FIRMBATCH_TEST_DATABASE_URL': '{ADMIN_URL}'}}",
        f"admin_engine = Engine({ADMIN_URL})",
        "",
    ]
    body += [
        f"    frame {i} of sqlalchemy and pytest wrapper machinery"
        for i in range(_TRACEBACK_LINES)
    ]
    body += [
        "",
        "    def _create_login_role(engine, role, password, marker, record):",
        f"        cursor.execute(\"CREATE ROLE x LOGIN PASSWORD '{ROLE_PASSWORD}'\")",
        "",
        "E   sqlalchemy.exc.ProgrammingError: (psycopg.errors.InsufficientPrivilege) "
        "permission denied to create role",
        f"E   [SQL: CREATE ROLE \"firmbatch_test_app_0123456789ab\" LOGIN PASSWORD '{ROLE_PASSWORD}']",
        "",
        "firmbatch/control_plane/testing/bootstrap.py:410: ProgrammingError",
        "=========================== short test summary info ============================",
        "FAILED control_plane/tests/test_role_privileges.py::test_the_provisioning_role",
        "1 failed, 285 passed in 24.00s",
    ]
    log = tmp_path / "secret-output.txt"
    log.write_text("\n".join(body) + "\n")
    return log


def _run_gate_with_secrets(tmp_path: pathlib.Path) -> tuple[subprocess.CompletedProcess, pathlib.Path]:
    """Drive the shipped ``gate_pytest`` over output that carries live-looking secrets."""
    payload = _secret_bearing_output(tmp_path)
    harness = tmp_path / "secret-harness.sh"
    harness.write_text(
        textwrap.dedent(
            f"""
            set -euo pipefail
            REPO_ROOT="{REPO_ROOT}"
            TMPDIR="{tmp_path}"
            export TMPDIR
            PASSED=0
            FAILED=0
            FAILED_NAMES=()
            pass() {{ printf '  PASS  %s\\n' "$1"; PASSED=$((PASSED + 1)); }}
            fail() {{
              printf '  FAIL  %s\\n' "$1"
              [ $# -gt 1 ] && printf '        %s\\n' "$2"
              FAILED=$((FAILED + 1))
              FAILED_NAMES+=("$1")
              return 0
            }}
            eval "$(awk '/^gate_pytest\\(\\) \\{{$/,/^\\}}$/' "$REPO_ROOT/scripts/verify-repository.sh")"
            gate_pytest "{tmp_path}" "fake suite" bash -c "cat '{payload}'; exit 1"
            printf '  %d gates passed, %d FAILED: %s\\n' "$PASSED" "$FAILED" "${{FAILED_NAMES[*]}}"
            exit 1
            """
        ).strip()
    )
    environment = dict(os.environ)
    environment["FIRMBATCH_TEST_DATABASE_URL"] = ADMIN_URL
    result = subprocess.run(
        ["bash", str(harness)],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=environment,
    )
    retained = [p for p in tmp_path.glob("firmbatch-foundation-suite.*.log")]
    assert len(retained) == 1, f"expected exactly one retained log, found {retained}"
    return result, retained[0]


def test_no_secret_reaches_stdout_stderr_or_the_retained_log(tmp_path):
    """Both secrets and the complete privileged URL, absent from all three places."""
    result, retained = _run_gate_with_secrets(tmp_path)
    printed = result.stdout + result.stderr
    kept = retained.read_text()

    for label, secret in (
        ("the admin password", ADMIN_PASSWORD),
        ("the generated role password", ROLE_PASSWORD),
        ("the complete privileged URL", ADMIN_URL),
    ):
        assert secret not in printed, f"{label} reached stdout/stderr"
        assert secret not in kept, f"{label} reached the retained log at {retained}"


def test_the_raw_capture_is_deleted(tmp_path):
    """Retaining a sanitized copy is worthless if the unsanitized one is still there."""
    _run_gate_with_secrets(tmp_path)
    leftovers = list(tmp_path.glob("firmbatch-foundation-suite.*.raw"))
    assert leftovers == [], f"the unsanitized capture survived: {leftovers}"


def test_the_retained_log_is_not_world_readable(tmp_path):
    """0600, and set at creation rather than after the write."""
    _, retained = _run_gate_with_secrets(tmp_path)
    mode = retained.stat().st_mode & 0o777
    assert mode == 0o600, f"retained log mode is {oct(mode)}, expected 0o600"


def test_the_actionable_exception_still_survives_sanitizing(tmp_path):
    """Sanitizing must not be achieved by throwing away what the reader needs."""
    result, retained = _run_gate_with_secrets(tmp_path)
    printed = result.stdout + result.stderr

    assert "InsufficientPrivilege" in printed, "the terminal exception was lost"
    assert "permission denied to create role" in printed, "the actionable detail was lost"
    assert "test_the_provisioning_role_can_create_a_tenant" in printed, "the failing test was lost"
    assert "sanitized output retained at" in printed
    assert "1 FAILED: fake suite" in printed, "the final summary was lost"
    assert result.returncode == 1, f"the real exit code was lost: {result.returncode}"
    # The redaction is visible rather than silent, so a reader knows something was removed.
    assert "***" in retained.read_text()


def test_a_url_password_is_removed_even_when_its_value_is_unknown(tmp_path):
    """The pattern pass covers a URL that arrived from somewhere this process cannot see."""
    from firmbatch.control_plane.tests import test_verification_reporting as self_module  # noqa: F401

    sanitize = _load_sanitizer().sanitize
    cleaned = sanitize("postgresql+psycopg://someone:unknown-secret@host:5432/db", secrets=())
    assert "unknown-secret" not in cleaned
    assert "postgresql+psycopg://someone:***@host:5432/db" == cleaned


def test_a_sql_password_literal_is_removed(tmp_path):
    sanitize = _load_sanitizer().sanitize
    cleaned = sanitize("[SQL: CREATE ROLE \"r\" LOGIN PASSWORD 'hunter2-not-hex']", secrets=())
    assert "hunter2-not-hex" not in cleaned
    assert "PASSWORD '***'" in cleaned


def _load_sanitizer():
    """Import the sanitizer by path: ``scripts/`` is not a package."""
    import importlib.util

    path = REPO_ROOT / "scripts" / "sanitize-secrets.py"
    spec = importlib.util.spec_from_file_location("firmbatch_sanitize_secrets", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------------------
# Finding 3: a known secret is redacted at any length.
#
# There was a four-character minimum on literal replacement. It was a rule about
# convenience applied to a question about secrecy: ``PGPASSWORD=abc`` is a real credential
# on a real cluster, and a developer database with a one-character password is a thing
# that exists. The only value that stays excluded is the empty string, because "" matches
# between every character and would redact the whole file.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret, line",
    [
        ("abc", "PGPASSWORD=abc was exported for this run"),
        ("x", "connection refused for password x"),
        ("ab", "postgresql+psycopg://u:ab@127.0.0.1:5432/postgres"),
        ("q7", "CREATE ROLE r LOGIN PASSWORD 'q7'"),
        ("s", "s"),
    ],
)
def test_a_short_known_secret_is_redacted(secret, line):
    sanitize = _load_sanitizer().sanitize
    cleaned = sanitize(line, [secret])
    assert secret not in cleaned, f"{secret!r} survived sanitizing"
    assert "***" in cleaned


def test_overlapping_short_and_long_secrets_are_both_redacted():
    """Longest first, so the long value is masked before the short one eats into it."""
    sanitize = _load_sanitizer().sanitize
    cleaned = sanitize("short=ab long=abcdef", ["ab", "abcdef"])
    assert "abcdef" not in cleaned
    assert "ab" not in cleaned.replace("***", "")


def test_an_empty_secret_is_ignored():
    """Replacing "" would redact every position in the file."""
    sanitize = _load_sanitizer().sanitize
    original = "nothing here is secret"
    assert sanitize(original, ["", None]) == original


def test_short_secrets_do_not_reach_stdout_or_the_retained_log(tmp_path):
    """End to end, through the real gate, with a three-character admin password."""
    short_admin_password = "abc"
    short_role_password = "q7"
    admin_url = f"postgresql+psycopg://postgres:{short_admin_password}@127.0.0.1:5432/postgres"

    body = [
        "===================================== FAILURES =====================================",
        "________________ test_short_password_case ________________",
        "",
        f"environment = {{'FIRMBATCH_TEST_DATABASE_URL': '{admin_url}'}}",
        "",
    ]
    body += [f"    frame {i} of wrapper machinery" for i in range(_TRACEBACK_LINES)]
    body += [
        "",
        f"E   [SQL: CREATE ROLE \"r\" LOGIN PASSWORD '{short_role_password}']",
        "E   sqlalchemy.exc.ProgrammingError: (psycopg.errors.InsufficientPrivilege) "
        "permission denied to create role",
        "=========================== short test summary info ============================",
        "1 failed, 1 passed in 1.00s",
    ]
    payload = tmp_path / "short-secret-output.txt"
    payload.write_text("\n".join(body) + "\n")

    harness = tmp_path / "short-harness.sh"
    harness.write_text(
        textwrap.dedent(
            f"""
            set -euo pipefail
            REPO_ROOT="{REPO_ROOT}"
            TMPDIR="{tmp_path}"
            export TMPDIR
            PASSED=0
            FAILED=0
            FAILED_NAMES=()
            pass() {{ printf '  PASS  %s\\n' "$1"; PASSED=$((PASSED + 1)); }}
            fail() {{
              printf '  FAIL  %s\\n' "$1"
              [ $# -gt 1 ] && printf '        %s\\n' "$2"
              FAILED=$((FAILED + 1))
              FAILED_NAMES+=("$1")
              return 0
            }}
            eval "$(awk '/^gate_pytest\\(\\) \\{{$/,/^\\}}$/' "$REPO_ROOT/scripts/verify-repository.sh")"
            gate_pytest "{tmp_path}" "fake suite" bash -c "cat '{payload}'; exit 1"
            printf '  %d gates passed, %d FAILED: %s\\n' "$PASSED" "$FAILED" "${{FAILED_NAMES[*]}}"
            exit 1
            """
        ).strip()
    )
    environment = dict(os.environ)
    environment["FIRMBATCH_TEST_DATABASE_URL"] = admin_url
    environment["PGPASSWORD"] = short_admin_password
    result = subprocess.run(
        ["bash", str(harness)], capture_output=True, text=True, cwd=str(tmp_path), env=environment
    )

    retained = list(tmp_path.glob("firmbatch-foundation-suite.*.log"))
    assert len(retained) == 1, retained
    kept = retained[0].read_text()
    printed = result.stdout + result.stderr

    for label, secret in (
        ("the short admin password", short_admin_password),
        ("the short role password", short_role_password),
        ("the complete privileged URL", admin_url),
    ):
        assert secret not in printed, f"{label} reached stdout/stderr"
        assert secret not in kept, f"{label} reached the retained log"

    # No raw capture left, permissions still restrictive, and the failure still readable.
    assert list(tmp_path.glob("firmbatch-foundation-suite.*.raw")) == []
    assert retained[0].stat().st_mode & 0o777 == 0o600
    assert "InsufficientPrivilege" in printed
    assert "test_short_password_case" in printed
    assert result.returncode == 1
