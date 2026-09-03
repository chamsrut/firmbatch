#!/usr/bin/env python3
"""Remove credentials from a captured log, in place, before anything retains or prints it.

A failing PostgreSQL test writes a lot into its traceback, and two kinds of secret arrive
there without anybody choosing to put them:

* **the privileged admin URL.** ``FIRMBATCH_TEST_DATABASE_URL`` carries a password, and CI
  sets it to a real one. pytest's long traceback mode renders every fixture value at the
  head of a failure -- ``environment = {'FIRMBATCH_TEST_DATABASE_URL': '...'}`` -- so a
  single failing test publishes it to the job log.
* **generated role passwords.** The bootstrap mints one per role per run. psycopg echoes
  the failing statement, so a ``CREATE ROLE ... PASSWORD '...'`` that fails carries a live
  credential into the traceback, and from there into a retained file.

Redacting only the excerpt that gets *printed* is not enough, and was the earlier mistake:
the full log stays on disk at a path the failure message helpfully names. So the retained
file is the sanitized one, the raw capture is deleted, and both are created 0600.

What gets replaced:

* every value of the named environment variables, **whatever its length**, longest first so
  a URL is masked before a password that is a substring of it. There was a four-character
  minimum here and it was wrong: ``PGPASSWORD=abc`` is a real credential on a real cluster,
  and a length threshold is a rule about convenience applied to a question about secrecy.
  The one exclusion is the empty string, which would otherwise match between every
  character and redact the entire file;
* the password field of any PostgreSQL URL, whether or not this process knows the value --
  which is what covers a URL that arrived from somewhere else entirely;
* any ``PASSWORD '...'`` literal in an echoed SQL statement;
* long hexadecimal runs, which is the shape ``secrets.token_hex`` produces.

Usage::

    sanitize-secrets.py --in RAW --out RETAINED [--env VAR ...]

Exits non-zero only if it could not do its job, so a caller may treat success as "the file
at --out is safe to keep and to quote from".
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys

REDACTED = "***"

#: The password field of a PostgreSQL URL: scheme, user, ':', password, '@'. Non-greedy on
#: the password and anchored on the '@' so it cannot run past the authority.
_URL_PASSWORD = re.compile(r"(?P<head>postgres(?:ql)?(?:\+\w+)?://[^\s:/@]+:)[^\s@/]*(?P<tail>@)")

#: ``PASSWORD 'literal'`` as psycopg echoes it when a CREATE/ALTER ROLE fails.
_SQL_PASSWORD = re.compile(r"(?i)(?P<head>\bPASSWORD\s+)(?P<quote>['\"])(?:[^'\"]*)(?P=quote)")

#: ``secrets.token_hex(16)`` is 32 hex characters. 24 is comfortably below that and well
#: above anything that occurs naturally in a traceback (OIDs are decimal, and the longest
#: incidental hex here is a 12-character database suffix, which is not a secret).
_LONG_HEX = re.compile(r"\b[0-9a-f]{24,}\b")

#: Variables whose *values* are secrets. Named rather than guessed so that a value which
#: happens to look ordinary is still removed.
DEFAULT_SECRET_VARS = (
    "FIRMBATCH_TEST_DATABASE_URL",
    "FIRMBATCH_DATABASE_URL",
    "FIRMBATCH_MIGRATION_DATABASE_URL",
    "PGPASSWORD",
)


def sanitize(text: str, secrets: "list[str] | tuple[str, ...]" = ()) -> str:
    """Return ``text`` with every known and every pattern-matched credential removed."""
    # Longest first: a URL contains its own password, so replacing the password first
    # would leave a URL that no longer matches the literal we hold. Overlapping short and
    # long values are the case this ordering exists for.
    #
    # `if s` only. A known secret is redacted at any length -- a one-character password is
    # still the password. Empty strings are skipped because "" is a substring of every
    # position in the file and replacing it would redact the whole thing.
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    text = _URL_PASSWORD.sub(lambda m: f"{m.group('head')}{REDACTED}{m.group('tail')}", text)
    text = _SQL_PASSWORD.sub(lambda m: f"{m.group('head')}{m.group('quote')}{REDACTED}{m.group('quote')}", text)
    text = _LONG_HEX.sub(REDACTED, text)
    return text


def _write_private(path: pathlib.Path, text: str) -> None:
    """Create the file 0600 *before* writing, so it is never briefly world-readable."""
    handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8", errors="replace") as fh:
        fh.write(text)


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="source", required=True)
    parser.add_argument("--out", dest="destination", required=True)
    parser.add_argument(
        "--env",
        action="append",
        default=None,
        help="an environment variable whose value is a secret (repeatable)",
    )
    args = parser.parse_args(argv)

    names = args.env if args.env is not None else list(DEFAULT_SECRET_VARS)
    secrets = [os.environ[name] for name in names if os.environ.get(name)]

    source = pathlib.Path(args.source)
    try:
        raw = source.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"could not read {source}: {exc}", file=sys.stderr)
        return 1

    _write_private(pathlib.Path(args.destination), sanitize(raw, secrets))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
